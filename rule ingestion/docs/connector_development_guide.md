# Connector Development Guide

## Overview

This guide explains how to build a new connector for the Rule Ingestion Service's Connector Framework. Connectors allow the Validation Engine to query external SIEM/security platforms and retrieve detection results.

---

## Architecture

```
┌──────────────────────────────────────┐
│         Connector Framework          │
│  ┌──────────────┐  ┌──────────────┐ │
│  │ BaseConnector │  │  Registry    │ │
│  │   (ABC)      │──│  (Runtime)   │ │
│  └──────┬───────┘  └──────────────┘ │
│         │                            │
│  ┌──────┴───────────────────────┐   │
│  │  Your Custom Connector       │   │
│  └──────────────────────────────┘   │
└──────────────────────────────────────┘
```

Every connector inherits from `BaseConnector` and implements three core methods:

| Method | Purpose |
|--------|---------|
| `validate_connection()` | Check that credentials and endpoint are reachable |
| `query(syntax, params)` | Execute a detection query and return results |
| `poll(query_id)` | Retrieve results from an async/paginated query |

---

## Step 1: Create Your Connector File

Create a new file in `app/connector/`:

```
app/connector/my_siem_connector.py
```

---

## Step 2: Implement BaseConnector

```python
from app.connector.base_connector import BaseConnector, ConnectorConfig
from app.connector.exceptions import (
    ConnectorTransientError,
    ConnectorPermanentError,
)


class MySiemConnector(BaseConnector):
    """Connector for MySIEM detection platform."""

    CONNECTOR_TYPE = "my_siem"

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._base_url = config.host.rstrip("/")
        self._token = config.credentials.get("token", "")
        self._session = None

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def validate_connection(self) -> bool:
        """Verify the API is reachable and credentials are valid."""
        try:
            import httpx

            response = httpx.get(
                f"{self._base_url}/api/health",
                headers=self._headers,
                timeout=10.0,
            )
            return response.status_code == 200

        except Exception:
            return False

    def query(self, syntax: str, params: dict | None = None) -> dict:
        """Execute a detection query against MySIEM."""
        import httpx

        payload = {"query": syntax, **(params or {})}

        try:
            response = httpx.post(
                f"{self._base_url}/api/search",
                headers=self._headers,
                json=payload,
                timeout=60.0,
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code >= 500:
                raise ConnectorTransientError(
                    f"MySIEM server error: {exc.response.status_code}"
                ) from exc
            raise ConnectorPermanentError(
                f"MySIEM client error: {exc.response.status_code}"
            ) from exc

        except httpx.RequestError as exc:
            raise ConnectorTransientError(
                "Failed to connect to MySIEM API"
            ) from exc

    def poll(self, query_id: str) -> dict:
        """Poll for async query results."""
        import httpx

        try:
            response = httpx.get(
                f"{self._base_url}/api/search/{query_id}/status",
                headers=self._headers,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "COMPLETE":
                return self._fetch_results(query_id)
            elif data.get("status") == "ERROR":
                raise ConnectorPermanentError(
                    f"Query {query_id} failed: {data.get('error')}"
                )
            else:
                return {"status": "PENDING", "query_id": query_id}

        except httpx.RequestError as exc:
            raise ConnectorTransientError(
                "Failed to poll MySIEM for query results"
            ) from exc

    def _fetch_results(self, query_id: str) -> dict:
        """Retrieve final results for a completed query."""
        import httpx

        response = httpx.get(
            f"{self._base_url}/api/search/{query_id}/results",
            headers=self._headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()
```

---

## Step 3: Register Your Connector

### Option A: Auto-registration via Plugin Loader

Add your connector to `config_validation.py` so the plugin loader discovers it:

```python
# In config_validation.py, add to REQUIRED_FIELDS:
CONNECTOR_REQUIRED_FIELDS = {
    ...
    "my_siem": ["host", "token"],
}
```

The plugin loader will auto-discover any Python file in `app/connector/` whose class inherits from `BaseConnector`.

### Option B: Manual Registration

```python
from app.connector.base_connector import ConnectorRegistry
from app.connector.my_siem_connector import MySiemConnector

ConnectorRegistry.register("my_siem", MySiemConnector)
```

---

## Step 4: Configuration

Your connector's `ConnectorConfig` will contain:

| Field | Description |
|-------|-------------|
| `connector_type` | Must match your `CONNECTOR_TYPE` constant |
| `host` | Base URL of the API |
| `credentials` | Dict with auth tokens, keys, etc. |
| `rate_limit` | Optional requests-per-second limit |
| `timeout` | Optional request timeout in seconds |

---

## Step 5: Error Handling

Always use the framework's exception hierarchy:

| Exception | When to Use |
|-----------|-------------|
| `ConnectorTransientError` | Temporary failures (network timeout, 5xx, rate limit) — will be retried |
| `ConnectorPermanentError` | Permanent failures (401, 403, invalid query) — will NOT be retried |

The `retry.py` decorator handles exponential backoff for transient errors automatically.

---

## Step 6: Write Tests

Create a test file at `tests/test_my_siem_connector.py`:

```python
import pytest
from unittest.mock import MagicMock, patch
from app.connector.base_connector import ConnectorConfig
from app.connector.my_siem_connector import MySiemConnector


@pytest.fixture
def connector():
    config = ConnectorConfig(
        connector_type="my_siem",
        host="https://my-siem.example.com",
        credentials={"token": "test-token-123"},
    )
    return MySiemConnector(config)


class TestMySiemConnector:
    def test_validate_connection_success(self, connector):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.get", return_value=mock_response):
            assert connector.validate_connection() is True

    def test_validate_connection_failure(self, connector):
        with patch("httpx.get", side_effect=Exception("Connection refused")):
            assert connector.validate_connection() is False

    def test_query_success(self, connector):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"host": "server-01", "alert": "malware"}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_response):
            result = connector.query("SELECT * FROM alerts")
            assert "results" in result

    def test_query_server_error(self, connector):
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 500
        http_error = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=mock_response,
        )
        mock_response.raise_for_status.side_effect = http_error

        with patch("httpx.post", return_value=mock_response):
            from app.connector.exceptions import ConnectorTransientError

            with pytest.raises(ConnectorTransientError):
                connector.query("SELECT * FROM alerts")
```

Run with:
```bash
pytest tests/test_my_siem_connector.py -v
```

---

## Best Practices

1. **Always use `ConnectorTransientError` for retryable errors** — the retry framework handles backoff.
2. **Never log credentials** — use `config.credentials` but don't print/log token values.
3. **Set reasonable timeouts** — every HTTP call should have a timeout (default 30s).
4. **Handle pagination** — if the API returns paginated results, loop through pages in `poll()`.
5. **Validate connection before queries** — call `validate_connection()` first to fail fast.
6. **Write tests with mocks** — don't hit real APIs in unit tests; use `unittest.mock`.

---

## Existing Connectors (Reference)

| Connector | File | Query Language |
|-----------|------|----------------|
| Splunk | `splunk_connector.py` | SPL |
| Elastic Security | `elastic_connector.py` | EQL / KQL |
| IBM QRadar | `qradar_connector.py` | AQL |
| CrowdStrike LogScale | `crowdstrike_logscale_connector.py` | LQL |
| Microsoft Sentinel | `sentinel_connector.py` | KQL |

Study any of these as a reference implementation.

---

## Registration API

Connectors can also be registered at runtime via the API:

```
POST /api/v2/connectors/register
Content-Type: application/json

{
    "connector_type": "my_siem",
    "host": "https://my-siem.example.com",
    "credentials": {
        "token": "your-api-token"
    }
}
```

---

## Health Monitoring

Once registered, your connector's health is automatically tracked:

```
GET /api/v2/connectors/{connector_type}/health
```

Returns:
```json
{
    "connector_type": "my_siem",
    "status": "healthy",
    "health_score": 0.95,
    "avg_latency_ms": 230.5,
    "error_rate": 0.02,
    "availability": 0.99,
    "last_check": "2026-08-24T12:00:00Z"
}
```

Health scoring combines:
- **Query latency** (lower is better)
- **Error rate** (fewer errors = higher score)
- **Availability** (uptime percentage)
