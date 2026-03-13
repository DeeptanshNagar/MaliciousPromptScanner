"""
MAPS FastAPI Backend
====================
REST API for the Malicious AI Prompt Scanner.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import logging
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.core.scanner import MAPSScanner
from backend.logging.logger import MAPSLogger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scanner: Optional[MAPSScanner] = None
maps_logger: Optional[MAPSLogger] = None


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000)
    detailed: bool = Field(False)


class BatchScanRequest(BaseModel):
    prompts: List[str] = Field(..., min_items=1, max_items=100)
    detailed: bool = Field(False)


class ScanResponse(BaseModel):
    scan_id: str
    decision: str
    risk_score: int
    classification: str
    confidence: float
    should_block: bool
    should_log: bool
    reason: str
    detectors_triggered: List[str]
    categories: List[str]
    scan_time_ms: float
    prompt: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scanner, maps_logger
    
    logger.info("Starting up MAPS API...")
    scanner = MAPSScanner()
    
    log_dir = Path(__file__).parent.parent / "logging"
    log_dir.mkdir(exist_ok=True)
    maps_logger = MAPSLogger(db_path=log_dir / "maps_logs.db")
    
    logger.info("MAPS API ready")
    
    yield
    
    logger.info("Shutting down MAPS API...")
    if maps_logger:
        maps_logger.close()


app = FastAPI(
    title="MAPS - Malicious AI Prompt Scanner",
    description="Multi-layer security engine for detecting malicious prompts",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "name": "MAPS - Malicious AI Prompt Scanner",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "scanner_ready": scanner is not None,
        "logger_ready": maps_logger is not None
    }


@app.get("/status")
async def get_status():
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    status = scanner.get_status()
    return {"status": "ready", **status}


@app.post("/scan_prompt", response_model=ScanResponse)
async def scan_prompt(request: ScanRequest, background_tasks: BackgroundTasks):
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    try:
        result = scanner.scan(request.prompt, detailed=request.detailed)
        
        if maps_logger and result.get('should_log'):
            background_tasks.add_task(maps_logger.log_scan, result)
        
        return ScanResponse(**result)
        
    except Exception as e:
        logger.error(f"Error scanning prompt: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.post("/scan_batch")
async def scan_batch(request: BatchScanRequest, background_tasks: BackgroundTasks):
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    try:
        results = scanner.scan_batch(request.prompts, detailed=request.detailed)
        
        if maps_logger:
            for result in results:
                if result.get('should_log'):
                    background_tasks.add_task(maps_logger.log_scan, result)
        
        total_blocked = sum(1 for r in results if r['should_block'])
        total_warnings = sum(1 for r in results if r['decision'] == 'WARN')
        
        return {
            "results": results,
            "total_scanned": len(results),
            "total_blocked": total_blocked,
            "total_warnings": total_warnings
        }
        
    except Exception as e:
        logger.error(f"Error in batch scan: {e}")
        raise HTTPException(status_code=500, detail=f"Batch scan failed: {str(e)}")


@app.get("/statistics")
async def get_statistics(hours: int = 24):
    if not maps_logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")
    
    try:
        stats = maps_logger.get_statistics(hours=hours)
        return stats
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@app.get("/recent_scans")
async def get_recent_scans(limit: int = 100, classification: Optional[str] = None, decision: Optional[str] = None):
    if not maps_logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")
    
    try:
        logs = maps_logger.get_recent_logs(limit=limit, classification=classification, decision=decision)
        return {"logs": logs, "count": len(logs)}
        
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get recent scans: {str(e)}")


@app.get("/trends")
async def get_trends(hours: int = 24):
    if not maps_logger:
        raise HTTPException(status_code=503, detail="Logger not initialized")
    
    try:
        trends = maps_logger.get_trend_data(hours=hours)
        return {"trends": trends, "hours": hours}
        
    except Exception as e:
        logger.error(f"Error getting trends: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
