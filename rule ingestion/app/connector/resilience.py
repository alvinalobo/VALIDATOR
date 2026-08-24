import logging
from typing import Any, Callable, Optional, TypeVar

from app.connector.circuit_breaker import CircuitBreaker
from app.connector.retry import with_retry


logger = logging.getLogger(__name__)

T = TypeVar("T")


class ConnectorResilience:
    """
    Centralized resilience layer for connector operations.

    Provides:
        - Retry with exponential backoff
        - Circuit breaker protection
        - Graceful fallback execution
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        max_attempts: int = 4,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        jitter: float = 0.25,
    ) -> None:
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

    def execute(
        self,
        operation: Callable[..., T],
        *args: Any,
        fallback: Optional[Callable[..., T]] = None,
        max_attempts: Optional[int] = None,
        **kwargs: Any,
    ) -> T:
        """
        Execute a connector operation with retry, circuit breaker,
        and optional fallback.

        Args:
            operation:
                Connector operation to execute.

            *args:
                Positional arguments passed to the operation.

            fallback:
                Optional fallback function used when the operation
                cannot be completed.

            max_attempts:
                Optional per-operation retry limit.
                If not provided, the connector-wide default is used.

            **kwargs:
                Keyword arguments passed to the operation.
        """

        retry_attempts = (
            max_attempts
            if max_attempts is not None
            else self.max_attempts
        )

        retrying_operation = with_retry(
            max_attempts=retry_attempts,
            base_delay=self.base_delay,
            max_delay=self.max_delay,
            jitter=self.jitter,
        )(operation)

        try:
            return self.circuit_breaker.call(
                retrying_operation,
                *args,
                **kwargs,
            )

        except Exception as exc:
            logger.warning(
                "Connector operation failed: %s",
                exc,
            )

            if fallback is None:
                raise

            return self._execute_fallback(
                fallback,
                exc,
            )

    def _execute_fallback(
        self,
        fallback: Callable[..., T],
        original_error: Exception,
    ) -> T:
        """
        Execute the fallback independently from the original
        operation arguments.

        The fallback receives the original error as a keyword
        argument when supported.
        """

        logger.warning(
            "Executing connector fallback because primary operation "
            "failed: %s",
            original_error,
        )

        try:
            return fallback(error=original_error)

        except TypeError:
            # Support simple zero-argument fallback functions.
            return fallback()

    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self.circuit_breaker.reset()

    @property
    def state(self):
        """Return the current circuit breaker state."""
        return self.circuit_breaker.state

    @property
    def failure_count(self) -> int:
        """Return the current consecutive failure count."""
        return self.circuit_breaker.failure_count