#!/usr/bin/env python3
"""
EVVP Backend — Early Vulnerability Verification Platform
=========================================================
Usage:
    python main.py                          # all ingestion workers + API server
    python main.py --ingest-only            # ingestion only (no API)
    python main.py --api-only               # API only (no ingestion)
    python main.py --collector reddit       # single collector, runs continuously
    python main.py --collector github
    python main.py --collector blog
    python main.py --collector nvd
    python main.py --once                   # single pass all collectors then exit
    python main.py --once --collector reddit
"""
import argparse
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import get_logger

logger = get_logger("main")


def _bootstrap() -> None:
    """Load persisted CVE mentions and register notification callbacks."""
    from pipeline.tracker  import load_from_disk, register_trending_callback
    from pipeline.notifier import dispatch_trending
    load_from_disk()
    register_trending_callback(dispatch_trending)
    logger.info("Bootstrap complete — tracker loaded, notifier registered")


def main():
    parser = argparse.ArgumentParser(description="EVVP Backend")
    parser.add_argument("--collector", choices=["reddit", "github", "blog", "nvd"])
    parser.add_argument("--once",        action="store_true")
    parser.add_argument("--ingest-only", action="store_true")
    parser.add_argument("--api-only",    action="store_true")
    parser.add_argument("--api-port",    type=int, default=8000)
    parser.add_argument("--api-host",    default="0.0.0.0")
    args = parser.parse_args()

    _bootstrap()

    from ingestion import reddit, github, blog, nvd

    collector_map = {
        "reddit": (reddit.run_once, reddit.run_continuous),
        "github": (github.run_once, github.run_continuous),
        "blog":   (blog.run_once,   blog.run_continuous),
        "nvd":    (nvd.run_once,    nvd.run_continuous),
    }

    # Single collector
    if args.collector:
        run_once, run_continuous = collector_map[args.collector]
        run_once() if args.once else run_continuous()
        return

    # Single pass all collectors
    if args.once:
        logger.info("Single pass — all collectors")
        for name, (run_once, _) in collector_map.items():
            try:
                logger.info("Running %s", name)
                run_once()
            except Exception as e:
                logger.error("%s failed: %s", name, e)
        return

    # API only
    if args.api_only:
        from api.server import run as run_api
        run_api(host=args.api_host, port=args.api_port)
        return

    # Full mode: ingestion workers + API server
    from scheduler.runner import start as start_scheduler
    from api.server import run as run_api

    if not args.ingest_only:
        threading.Thread(
            target=run_api,
            kwargs={"host": args.api_host, "port": args.api_port},
            daemon=True,
            name="api",
        ).start()
        logger.info("API server started on %s:%d", args.api_host, args.api_port)

    logger.info("Starting all ingestion workers")
    start_scheduler()


if __name__ == "__main__":
    main()
