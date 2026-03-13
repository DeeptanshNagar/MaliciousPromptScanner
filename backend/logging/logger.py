"""
MAPS Logging System
===================
Logs all scan events to SQLite database for auditing and analysis.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class MAPSLogger:
    """Logger for MAPS scan events."""
    
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path(__file__).parent / "maps_logs.db"
        
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    prompt TEXT NOT NULL,
                    prompt_hash TEXT,
                    decision TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    classification TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    should_block BOOLEAN NOT NULL,
                    should_log BOOLEAN NOT NULL,
                    reason TEXT,
                    detectors_triggered TEXT,
                    categories TEXT,
                    scan_time_ms REAL,
                    layer_results TEXT,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_classification ON scan_logs(classification)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_decision ON scan_logs(decision)')
            
            conn.commit()
            logger.info(f"Initialized database at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def log_scan(self, scan_result: Dict, metadata: Optional[Dict] = None):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                prompt = scan_result.get('prompt', '')
                prompt_hash = self._hash_prompt(prompt)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_logs (
                        scan_id, timestamp, prompt, prompt_hash,
                        decision, risk_score, classification, confidence,
                        should_block, should_log, reason,
                        detectors_triggered, categories, scan_time_ms,
                        layer_results, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result.get('scan_id', ''),
                    datetime.fromtimestamp(scan_result.get('timestamp', 0)),
                    prompt,
                    prompt_hash,
                    scan_result.get('decision', ''),
                    scan_result.get('risk_score', 0),
                    scan_result.get('classification', ''),
                    scan_result.get('confidence', 0.0),
                    scan_result.get('should_block', False),
                    scan_result.get('should_log', False),
                    scan_result.get('reason', ''),
                    json.dumps(scan_result.get('detectors_triggered', [])),
                    json.dumps(scan_result.get('categories', [])),
                    scan_result.get('scan_time_ms', 0),
                    json.dumps(scan_result.get('layer_results', {})),
                    json.dumps(metadata) if metadata else None
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error logging scan: {e}")
    
    def _hash_prompt(self, prompt: str) -> str:
        import hashlib
        return hashlib.md5(prompt.encode()).hexdigest()[:16]
    
    def get_recent_logs(self, limit: int = 100, classification: Optional[str] = None, decision: Optional[str] = None) -> List[Dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM scan_logs WHERE 1=1'
            params = []
            
            if classification:
                query += ' AND classification = ?'
                params.append(classification)
            
            if decision:
                query += ' AND decision = ?'
                params.append(decision)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [dict(row) for row in rows]
    
    def get_statistics(self, hours: int = 24) -> Dict:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT COUNT(*) FROM scan_logs WHERE timestamp >= datetime('now', '-{hours} hours')")
            total_scans = cursor.fetchone()[0]
            
            cursor.execute(f"SELECT classification, COUNT(*) as count FROM scan_logs WHERE timestamp >= datetime('now', '-{hours} hours') GROUP BY classification")
            by_classification = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute(f"SELECT decision, COUNT(*) as count FROM scan_logs WHERE timestamp >= datetime('now', '-{hours} hours') GROUP BY decision")
            by_decision = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute(f"SELECT AVG(risk_score) FROM scan_logs WHERE timestamp >= datetime('now', '-{hours} hours')")
            avg_risk = cursor.fetchone()[0] or 0
            
            from collections import Counter
            cursor.execute(f"SELECT detectors_triggered FROM scan_logs WHERE timestamp >= datetime('now', '-{hours} hours')")
            detector_counts = Counter()
            for row in cursor.fetchall():
                detectors = json.loads(row[0] or '[]')
                detector_counts.update(detectors)
            
            return {
                'total_scans': total_scans,
                'by_classification': by_classification,
                'by_decision': by_decision,
                'average_risk_score': round(avg_risk, 2),
                'top_detectors': dict(detector_counts.most_common(10)),
                'time_window_hours': hours
            }
    
    def get_trend_data(self, hours: int = 24) -> List[Dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(f'''
                SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                       classification, COUNT(*) as count
                FROM scan_logs
                WHERE timestamp >= datetime('now', '-{hours} hours')
                GROUP BY hour, classification
                ORDER BY hour
            ''')
            
            rows = cursor.fetchall()
            
            hourly_data = {}
            for row in rows:
                hour, classification, count = row
                if hour not in hourly_data:
                    hourly_data[hour] = {'hour': hour}
                hourly_data[hour][classification] = count
            
            return list(hourly_data.values())
    
    def close(self):
        logger.info("Logger closed")
