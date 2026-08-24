import pytest

from app.connector.circuit_breaker import CircuitOpenError, CircuitState
from app.connector.exceptions import ConnectorTransientError
from app.connector.resilience import ConnectorResilience


def test_successful_operation_returns_result():
    resilience = ConnectorResilience(
        max_attempts=2,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    def operation():
        return "success"

    result = resilience.execute(operation)

    assert result == "success"
    assert resilience.state == CircuitState.CLOSED
    assert resilience.failure_count == 0


def test_transient_failure_is_retried():
    resilience = ConnectorResilience(
        max_attempts=3,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    attempts = {"count": 0}

    def operation():
        attempts["count"] += 1

        if attempts["count"] < 3:
            raise ConnectorTransientError("Temporary failure")

        return "recovered"

    result = resilience.execute(operation)

    assert result == "recovered"
    assert attempts["count"] == 3
    assert resilience.state == CircuitState.CLOSED


def test_fallback_runs_when_operation_fails():
    resilience = ConnectorResilience(
        max_attempts=2,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    def operation():
        raise ConnectorTransientError("Endpoint unavailable")

    def fallback(error=None):
        assert isinstance(error, ConnectorTransientError)
        return "fallback-result"

    result = resilience.execute(
        operation,
        fallback=fallback,
    )

    assert result == "fallback-result"


def test_fallback_runs_when_circuit_is_open():
    resilience = ConnectorResilience(
        failure_threshold=1,
        recovery_timeout=30,
        max_attempts=1,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    def failing_operation():
        raise ConnectorTransientError("Endpoint unavailable")

    with pytest.raises(ConnectorTransientError):
        resilience.execute(failing_operation)

    assert resilience.state == CircuitState.OPEN

    def fallback(error=None):
        assert isinstance(error, CircuitOpenError)
        return "degraded-result"

    result = resilience.execute(
        failing_operation,
        fallback=fallback,
    )

    assert result == "degraded-result"
    assert resilience.state == CircuitState.OPEN


def test_original_error_is_raised_without_fallback():
    resilience = ConnectorResilience(
        max_attempts=1,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    def operation():
        raise ConnectorTransientError("Connection failed")

    with pytest.raises(ConnectorTransientError, match="Connection failed"):
        resilience.execute(operation)


def test_manual_reset_closes_circuit():
    resilience = ConnectorResilience(
        failure_threshold=1,
        recovery_timeout=30,
        max_attempts=1,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )

    def operation():
        raise ConnectorTransientError("Failure")

    with pytest.raises(ConnectorTransientError):
        resilience.execute(operation)

    assert resilience.state == CircuitState.OPEN

    resilience.reset()

    assert resilience.state == CircuitState.CLOSED
    assert resilience.failure_count == 0