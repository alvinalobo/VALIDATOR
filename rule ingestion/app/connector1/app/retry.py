import time
import functools
import logging
from app.exceptions import ConnectorTransientError

logger = logging.getLogger(__name__)

def with_retry(max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
    """
    Decorator for retrying functions when a ConnectorTransientError is encountered.
    Uses exponential backoff with a cap.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except ConnectorTransientError as exc:
                    if attempt == max_attempts:
                        logger.warning(f"Attempt {attempt} failed permanently: {exc}")
                        raise
                    logger.warning(f"Attempt {attempt} failed, retrying in {delay}s: {exc}")
                    time.sleep(delay)
                    delay = min(delay * 2.0, max_delay)
        return wrapper
    return decorator
