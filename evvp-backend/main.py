#!/usr/bin/env python3
"""
EVVP Backend — Early Vulnerability & Vulnerability Intelligence Platform
========================================================================
Usage:
    python main.py                          # collectors + API + dashboard (http://localhost:8000)
    python main.py --api-only               # API + dashboard only (no collection)
    python main.py --ingest-only            # collectors only (no API)
    python main.py --once                   # one pass over every enabled source, then exit
    python main.py --once --collector blog  # one pass of a single collector
    python main.py --collector nvd          # one collector, runs continuously
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
    from pipeline.tracker import load_from_disk, register_trending_callback
    from pipeline.notifier import dispatch_trending
    load_from_disk()
    register_trending_callback(dispatch_trending)
    logger.info("Bootstrap complete — tracker loaded, notifier registered")


def main():
    parser = argparse.ArgumentParser(description="EVVP Backend")
    parser.add_argument("--collector", choices=["reddit", "github", "blog", "nvd", "cisa"])
    parser.add_argument("--once", action="store_true", help="single pass, ignoring per-source intervals")
    parser.add_argument("--ingest-only", action="store_true")
    parser.add_argument("--api-only", action="store_true")
    parser.add_argument("--api-port", type=int, default=int(os.getenv("EVVP_PORT", 8000)))
    parser.add_argument("--api-host", default=os.getenv("EVVP_HOST", "127.0.0.1"))
    args = parser.parse_args()

    from storage import db
    try:
        backend = db.check_storage()
    except db.StorageError as exc:
        logger.critical("Storage check failed — refusing to start: %s", exc)
        print(f"\nEVVP cannot start: {exc}\n(PostgreSQL is configured via DB_URL; EVVP never silently falls back to JSON files.)", file=sys.stderr)
        sys.exit(2)
    logger.info("Storage backend: %s", backend)
    _bootstrap()

    if args.api_only:
        from api.server import run as run_api
        run_api(host=args.api_host, port=args.api_port)
        return

    from ingestion import reddit, github, blog, nvd, cisa
    collectors = {
        "reddit": (reddit.run_once, reddit.run_continuous),
        "github": (github.run_once, github.run_continuous),
        "blog": (blog.run_once, blog.run_continuous),
        "nvd": (nvd.run_once, nvd.run_continuous),
        "cisa": (cisa.run_once, cisa.run_continuous),
    }

    if args.collector:
        run_once, run_continuous = collectors[args.collector]
        run_once(force=True) if args.once else run_continuous()
        return

    if args.once:
        logger.info("Single pass — all collectors")
        for name, (run_once, _) in collectors.items():
            try:
                logger.info("Running %s", name)
                run_once(force=True)
            except Exception as e:
                logger.error("%s failed: %s", name, e)
        return

    from scheduler.runner import start as start_scheduler
    if not args.ingest_only:
        from api.server import run as run_api
        threading.Thread(target=run_api, kwargs={"host": args.api_host, "port": args.api_port},
                         daemon=True, name="api").start()
        logger.info("Dashboard + API on http://%s:%d", args.api_host, args.api_port)
    logger.info("Starting all collectors")
    start_scheduler()


if __name__ == "__main__":
    main()
