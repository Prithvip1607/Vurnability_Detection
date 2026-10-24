"""Scheduler — runs every collector (plus periodic re-enrichment) as a daemon thread.

Each collector decides for itself when it is due, from the Source Manager's per-source interval,
so changes made in the dashboard apply on the next tick with no restart.
"""
import signal
import sys
import threading
import time

from ingestion import reddit, github, blog, nvd, cisa
from utils.audit import audit, EV_SYSTEM_START, EV_SYSTEM_STOP, EV_WORKER_START, EV_WORKER_ERROR
from utils.logger import get_logger

logger = get_logger("scheduler")
REENRICH_EVERY = 1800            # seconds


def _reenrich_loop() -> None:
    """Retry NVD/EPSS for findings whose CVE was not yet published (or NVD was down)."""
    from pipeline import reenrich
    while True:
        time.sleep(REENRICH_EVERY)
        try:
            reenrich.run()
        except Exception as exc:
            logger.error("Re-enrichment cycle failed: %s", exc)


_WORKERS = [
    ("reddit", reddit.run_continuous),
    ("github", github.run_continuous),
    ("blog", blog.run_continuous),
    ("nvd", nvd.run_continuous),
    ("cisa", cisa.run_continuous),
    ("reenrich", _reenrich_loop),
]


def _wrap(name: str, target):
    """A crashing worker is audited and restarted after a pause; it never takes the others down."""
    def _run():
        audit(EV_WORKER_START, worker=name)
        while True:
            try:
                target()
                return
            except Exception as e:
                audit(EV_WORKER_ERROR, worker=name, message=str(e))
                logger.error("Worker %s crashed: %s — restarting in 60s", name, e)
                time.sleep(60)
    return _run


def start() -> None:
    audit(EV_SYSTEM_START, workers=[w[0] for w in _WORKERS])
    for name, target in _WORKERS:
        threading.Thread(target=_wrap(name, target), name=name, daemon=True).start()
        logger.info("Started worker: %s", name)

    def _shutdown(sig, frame):
        audit(EV_SYSTEM_STOP, reason="signal_received")
        logger.info("Shutdown signal — exiting")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    while True:                      # keep the main thread alive; workers are daemons
        time.sleep(3600)
