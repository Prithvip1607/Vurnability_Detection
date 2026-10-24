import threading
import signal
import sys

from collectors import reddit_collector, github_collector, blog_collector
from utils.logger import get_logger

logger = get_logger("scheduler")

_COLLECTORS = [
    ("reddit", reddit_collector.run_continuous),
    ("github", github_collector.run_continuous),
    ("blog",   blog_collector.run_continuous),
]


def start() -> None:
    threads = []
    for name, target in _COLLECTORS:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        threads.append(t)
        logger.info("Started collector thread: %s", name)

    def _shutdown(sig, frame):
        logger.info("Shutdown signal received — exiting")
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    for t in threads:
        t.join()
