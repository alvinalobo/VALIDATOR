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
    Retry a connector operation when a transient error occurs.

    Retry strategy:
        - Exponential backoff
        - Maximum delay limit
        - Random jitter to avoid synchronized retries

    Args:
        max_attempts:
            Total number of attempts including the first attempt.

        base_delay:
            Initial retry delay in seconds.

        max_delay:
            Maximum retry delay in seconds.

        jitter:
            Random jitter percentage applied to the calculated delay.

    Retries are performed only for ConnectorTransientError.

    Permanent connector errors are propagated immediately.
    """

    if max_attempts <= 0:
        raise ValueError("max_attempts must be greater than 0")

    if base_delay < 0:
        raise ValueError("base_delay cannot be negative")

    if max_delay < 0:
        raise ValueError("max_delay cannot be negative")

    if max_delay < base_delay:
        raise ValueError("max_delay must be greater than or equal to base_delay")

    if jitter < 0:
        raise ValueError("jitter cannot be negative")

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)

                except ConnectorTransientError as exc:
                    if attempt == max_attempts:
                        logger.error(
                            "%s failed after %d attempts: %s",
                            func.__qualname__,
                            attempt,
                            exc,
                        )
                        raise

                    delay = min(
                        base_delay * (2 ** (attempt - 1)),
                        max_delay,
                    )

                    if jitter > 0 and delay > 0:
                        delay += random.uniform(
                            0,
                            delay * jitter,
                        )

                    logger.warning(
                        "%s attempt %d/%d failed with transient error: %s. "
                        "Retrying in %.2f seconds.",
                        func.__qualname__,
                        attempt,
                        max_attempts,
                        exc,
                        delay,
                    )

                    if delay > 0:
                        time.sleep(delay)

        return wrapper

    return decorator