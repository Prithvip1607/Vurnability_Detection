import time
import threading


class RateLimiter:
    """Token bucket — enforces a minimum interval between calls."""

    def __init__(self, calls_per_hour: int):
        self._interval = 3600 / max(calls_per_hour, 1)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        with self._lock:
            elapsed = time.monotonic() - self._last
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last = time.monotonic()
