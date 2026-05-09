"""
Scheduler — runs all ingestion workers as daemon threads with graceful shutdown.
"""
import signal
import sys
import threading

from ingestion import reddit, github, blog, nvd
from utils.audit  import audit, EV_SYSTEM_START, EV_SYSTEM_STOP, EV_WORKER_START, EV_WORKER_ERROR
from utils.logger import get_logger

logger = get_logger("scheduler")

_WORKERS = [
    ("reddit", reddit.run_continuous),
    ("github", github.run_continuous),
    ("blog",   blog.run_continuous),
    ("nvd",    nvd.run_continuous),
]


def _wrap(name: str, target):
    """Wrap a worker so crashes are audited and logged."""
    def _run():
        audit(EV_WORKER_START, worker=name)
        try:
            target()
        except Exception as e:
            audit(EV_WORKER_ERROR, worker=name, message=str(e))
            logger.error("Worker %s crashed: %s", name, e)
    return _run


def start() -> None:
    audit(EV_SYSTEM_START, workers=[w[0] for w in _WORKERS])
    threads = []
    for name, target in _WORKERS:
        t = threading.Thread(target=_wrap(name, target), name=name, daemon=True)
        t.start()
        threads.append(t)
        logger.info("Started worker: %s", name)

    def _shutdown(sig, frame):
        audit(EV_SYSTEM_STOP, reason="signal_received")
        logger.info("Shutdown signal — exiting")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for t in threads:
        t.join()
