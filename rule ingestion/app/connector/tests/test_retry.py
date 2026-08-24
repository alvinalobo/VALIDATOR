import pytest

from app.connector.exceptions import ConnectorTransientError
from app.connector.retry import with_retry


def test_retry_succeeds_after_transient_failures():
    attempts = {"count": 0}

    @with_retry(
        max_attempts=3,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )
    def unstable_function():
        attempts["count"] += 1

        if attempts["count"] < 3:
            raise ConnectorTransientError("Temporary failure")

        return "success"

    result = unstable_function()

    assert result == "success"
    assert attempts["count"] == 3


def test_retry_raises_after_max_attempts():
    attempts = {"count": 0}

    @with_retry(
        max_attempts=3,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )
    def failing_function():
        attempts["count"] += 1
        raise ConnectorTransientError("Permanent failure")

    with pytest.raises(ConnectorTransientError):
        failing_function()

    assert attempts["count"] == 3


def test_non_transient_error_is_not_retried():
    attempts = {"count": 0}

    @with_retry(
        max_attempts=3,
        base_delay=0,
        max_delay=0,
        jitter=0,
    )
    def invalid_function():
        attempts["count"] += 1
        raise ValueError("Invalid input")

    with pytest.raises(ValueError):
        invalid_function()

    assert attempts["count"] == 1


def test_retry_configuration_validation():
    with pytest.raises(ValueError):
        with_retry(max_attempts=0)

    with pytest.raises(ValueError):
        with_retry(base_delay=-1)

    with pytest.raises(ValueError):
        with_retry(max_delay=-1)

    with pytest.raises(ValueError):
        with_retry(jitter=-1)

    with pytest.raises(ValueError):
        with_retry(base_delay=5, max_delay=2)