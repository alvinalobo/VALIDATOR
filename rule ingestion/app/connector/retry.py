
import functools
import logging
import random
import time
from typing import Callable, TypeVar

from app.connector.exceptions import ConnectorTransientError

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable)


def with_retry(
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.25,
) -> Callable[[F], F]:
    """
    Decorator: retry the wrapped call on ConnectorTransientError using
    exponential backoff — delay doubles each attempt (base_delay,
    2*base_delay, 4*base_delay, ...), capped at max_delay, with random
    jitter added so multiple connectors backing off at once don't all
    retry in lockstep and hammer the source simultaneously.

    max_attempts counts the FIRST try, so max_attempts=4 means up to
    3 retries after the initial attempt. On final failure, re-raises
    the last ConnectorTransientError seen.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc: ConnectorTransientError = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except ConnectorTransientError as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        logger.error(
                            "%s failed after %d attempts: %s",
                            func.__qualname__, attempt, exc,
                        )
                        raise
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    delay += random.uniform(0, delay * jitter)
                    logger.warning(
                        "%s attempt %d/%d failed (%s); retrying in %.2fs",
                        func.__qualname__, attempt, max_attempts, exc, delay,
                    )
                    time.sleep(delay)
            raise last_exc

        return wrapper

    return decorator