import time
import functools
from utils.logger import get_logger

logger = get_logger("retry")


def retry(max_attempts: int = 3, base_delay: float = 5.0, exceptions=(Exception,)):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        logger.error("%s failed after %d attempts: %s", fn.__name__, max_attempts, e)
                        raise
                    delay = base_delay * (2 ** (attempt - 1))
                    logger.warning("%s attempt %d failed: %s — retrying in %.1fs", fn.__name__, attempt, e, delay)
                    time.sleep(delay)
        return wrapper
    return decorator
