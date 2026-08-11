import httpx
import pytest

from app.connector.base_connector import ConnectorConfig
from app.connector.crowdstrike_logscale_connector import (
    CrowdStrikeLogScaleConnector,
)


def create_connector():
    config = ConnectorConfig(
        connector_id="test-crowdstrike",
        vendor="crowdstrike",
        product="logscale",
        credentials={
            "host": "https://example.logscale.test",
            "token": "test-token",
        },
        scope={
            "repository": "test-repository",
        },
    )

    return CrowdStrikeLogScaleConnector(config)


def test_query_success(monkeypatch):
    connector = create_connector()

    expected_response = {
        "id": "test-job-id",
    }

    def mock_post(*args, **kwargs):
        assert args[0] == (
            "https://example.logscale.test/"
            "api/v1/repositories/test-repository/queryjobs"
        )

        assert kwargs["headers"]["Authorization"] == "Bearer test-token"

        assert kwargs["json"] == {
            "queryString": "hello",
            "start": "1h",
            "end": "now",
            "isLive": False,
        }

        return httpx.Response(
            200,
            json=expected_response,
            request=httpx.Request("POST", args[0]),
        )

    monkeypatch.setattr(httpx, "post", mock_post)

    result = connector.query(
        "hello",
        ("1h", "now"),
    )

    assert result == [expected_response]


def test_query_rejects_empty_query():
    connector = create_connector()

    with pytest.raises(ValueError, match="Query cannot be empty"):
        connector.query("", ("1h", "now"))


def test_query_requires_two_time_values():
    connector = create_connector()

    with pytest.raises(
        ValueError,
        match="time_range must contain start and end values",
    ):
        connector.query("hello", ("1h",))

def test_poll_success(monkeypatch):
    connector = create_connector()
    connector._last_job_id = "test-job-id"

    expected_response = {
        "status": "completed",
        "events": [
            {"message": "test event"}
        ],
    }

    def mock_get(*args, **kwargs):
        assert args[0] == (
            "https://example.logscale.test/"
            "api/v1/repositories/test-repository/"
            "queryjobs/test-job-id"
        )

        assert kwargs["headers"]["Authorization"] == "Bearer test-token"

        return httpx.Response(
            200,
            json=expected_response,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    result = connector.poll()

    assert result == [expected_response]


def test_poll_without_job_id():
    connector = create_connector()

    with pytest.raises(
        ValueError,
        match="No query job is available to poll",
    ):
        connector.poll()

def test_validate_connection_success(monkeypatch):
    connector = create_connector()

    def mock_get(*args, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    assert connector.validate_connection() is True


def test_validate_connection_failure(monkeypatch):
    connector = create_connector()

    def mock_get(*args, **kwargs):
        return httpx.Response(
            401,
            request=httpx.Request("GET", args[0]),
        )

    monkeypatch.setattr(httpx, "get", mock_get)

    assert connector.validate_connection() is False