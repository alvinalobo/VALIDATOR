"""
circuit_breaker.py

Circuit breaker pattern for the Connector Framework.

States:
  CLOSED   -> normal operation, requests pass through
  OPEN     -> too many failures, requests are blocked immediately
  HALF_OPEN -> after cooldown, allow ONE test request through

Transitions:
  CLOSED  -> OPEN     : when failure_count >= failure_threshold
  OPEN    -> HALF_OPEN: after cooldown_seconds elapse
  HALF_OPEN -> CLOSED : if the test request succeeds
  HALF_OPEN -> OPEN   : if the test request fails
"""

import time
import logging
from enum import Enum
from typing import Callable, Any

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when the circuit is OPEN and requests are blocked."""
    pass


class CircuitOpenError(CircuitBreakerError):
    """Raised when the circuit is OPEN and requests are blocked."""
    pass


class CircuitBreaker:
    """
    Protects connectors from cascading failures.

    Usage:
        breaker = CircuitBreaker(failure_threshold=5, cooldown_seconds=60)

        try:
            result = breaker.call(some_function, arg1, arg2)
        except CircuitBreakerError:
            # Circuit is OPEN — fail fast
            ...
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 60.0,
        recovery_timeout: float = None,
        half_open_max_calls: int = 1,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = recovery_timeout if recovery_timeout is not None else cooldown_seconds
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0

    @property
    def failure_count(self) -> int:
        """Return the current consecutive failure count."""
        return self._failure_count

    @property
    def state(self) -> CircuitState:
        """Current circuit state (auto-transitions OPEN -> HALF_OPEN)."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_failure_time
            if elapsed >= self.cooldown_seconds:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(
                    "Circuit breaker: OPEN -> HALF_OPEN after %.1fs cooldown",
                    elapsed,
                )
        return self._state

    def _on_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            logger.info("Circuit breaker: HALF_OPEN -> CLOSED (success)")
        else:
            # Reset failure count on success in CLOSED state
            self._failure_count = 0

    def _on_failure(self) -> None:
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker: HALF_OPEN -> OPEN (failure during test)"
            )
        elif self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker: CLOSED -> OPEN (%d consecutive failures)",
                self._failure_count,
            )

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute func through the circuit breaker.

        Raises CircuitBreakerError if the circuit is OPEN.
        """
        current_state = self.state

        if current_state == CircuitState.OPEN:
            raise CircuitOpenError(
                f"Circuit breaker is OPEN. "
                f"Retry after {self.cooldown_seconds}s cooldown."
            )

        if current_state == CircuitState.HALF_OPEN:
            if self._half_open_calls >= self.half_open_max_calls:
                raise CircuitOpenError(
                    "Circuit breaker HALF_OPEN: test call already in progress."
                )
            self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        logger.info("Circuit breaker: manually reset to CLOSED")

    def get_status(self) -> dict:
        """Return current circuit breaker status for monitoring."""
        return {
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "cooldown_seconds": self.cooldown_seconds,
            "last_failure_time": self._last_failure_time,
        }
