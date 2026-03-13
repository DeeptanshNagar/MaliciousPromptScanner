#!/usr/bin/env python3
"""
MAPS Startup Script
===================
Convenient script to start MAPS components.

Usage:
    python start.py --api          # Start API server
    python start.py --dashboard    # Start dashboard
    python start.py --all          # Start both
"""

import argparse
import subprocess
import sys
from pathlib import Path


def start_api():
    """Start the API server."""
    print("🚀 Starting MAPS API Server...")
    print("   URL: http://localhost:8000")
    print("   Docs: http://localhost:8000/docs")
    print("   Press Ctrl+C to stop\n")
    
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "backend.api.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload"
        ])
    except KeyboardInterrupt:
        print("\n✅ API server stopped")


def start_dashboard():
    """Start the web dashboard."""
    print("📊 Starting MAPS Dashboard...")
    print("   URL: http://localhost:8501")
    print("   Press Ctrl+C to stop\n")
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            "web_dashboard/app.py"
        ])
    except KeyboardInterrupt:
        print("\n✅ Dashboard stopped")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Start MAPS components')
    parser.add_argument(
        '--api',
        action='store_true',
        help='Start API server'
    )
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Start web dashboard'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Start both API and dashboard'
    )
    
    args = parser.parse_args()
    
    if args.all:
        print("Starting both API and dashboard...")
        print("Note: Use separate terminals for better control\n")
        start_api()
    elif args.api:
        start_api()
    elif args.dashboard:
        start_dashboard()
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python start.py --api        # Start API only")
        print("  python start.py --dashboard  # Start dashboard only")


if __name__ == "__main__":
    main()