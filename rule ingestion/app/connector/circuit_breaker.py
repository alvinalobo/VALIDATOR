from enum import Enum
from time import monotonic
from typing import Callable, TypeVar


T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Circuit Breaker implementation for connector resilience.

    States:
        CLOSED:
            Requests are allowed normally.

        OPEN:
            Requests are blocked because the failure threshold
            has been reached.

        HALF_OPEN:
            After the recovery timeout, one request is allowed
            to check whether the endpoint has recovered.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be greater than 0")

        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be greater than 0")

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> CircuitState:
        """
        Return the current circuit state.

        If the circuit is OPEN and the recovery timeout has elapsed,
        transition to HALF_OPEN.
        """
        if (
            self._state == CircuitState.OPEN
            and self._opened_at is not None
            and monotonic() - self._opened_at >= self.recovery_timeout
        ):
            self._state = CircuitState.HALF_OPEN

        return self._state

    @property
    def failure_count(self) -> int:
        """Return the current consecutive failure count."""
        return self._failure_count

    def allow_request(self) -> bool:
        """
        Determine whether a request should be allowed.

        CLOSED    -> allowed
        OPEN      -> blocked
        HALF_OPEN -> allowed for recovery test
        """
        return self.state in {
            CircuitState.CLOSED,
            CircuitState.HALF_OPEN,
        }

    def record_success(self) -> None:
        """
        Record a successful request.

        Any successful request closes the circuit and resets
        the consecutive failure count.
        """
        self._failure_count = 0
        self._opened_at = None
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """
        Record a failed request.

        Once the failure threshold is reached, the circuit
        transitions to OPEN.
        """
        self._failure_count += 1

        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_at = monotonic()

    def reset(self) -> None:
        """
        Manually reset the circuit to CLOSED.
        """
        self._failure_count = 0
        self._opened_at = None
        self._state = CircuitState.CLOSED

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute a function through the circuit breaker.

        Raises:
            CircuitOpenError:
                When the circuit is OPEN and requests are blocked.

        Returns:
            The return value of the wrapped function.
        """
        if not self.allow_request():
            raise CircuitOpenError(
                "Circuit breaker is OPEN. Request blocked."
            )

        try:
            result = func(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise
        else:
            self.record_success()
            return result


class CircuitOpenError(Exception):
    """
    Raised when a request is blocked because the circuit is OPEN.
    """

    pass