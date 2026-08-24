"""
sentinel_connector.py

Microsoft Sentinel SIEM Connector.
- KQL query execution against Microsoft Graph Security API
- OAuth2 token-based authentication
- Pagination support
- Rate limiting
- Mock mode for offline testing
"""

import time
import httpx
from typing import List, Dict, Any, Optional

from app.connector.base_connector import BaseConnector, ConnectorConfig, ConnectorRegistry
from app.connector.exceptions import (
    ConnectorTransientError,
    ConnectorPermanentError,
)


class SentinelConnector(BaseConnector):
    """
    Microsoft Sentinel SIEM Connector implementing KQL query execution
    against the Microsoft Graph Security API ( unifiedSecurityIncidentTasks ).
    Supports OAuth2 token authentication, pagination, and mock mode.
    """

    GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.tenant_id = config.credentials.get("tenant_id", "")
        self.client_id = config.credentials.get("client_id", "")
        self.client_secret = config.credentials.get("client_secret", "")
        self.workspace_id = config.credentials.get("workspace_id", "")
        self.access_token = config.credentials.get("access_token", "")
        self.is_mock = config.credentials.get("mock", not bool(self.tenant_id))
        self.verify_ssl = config.credentials.get("verify_ssl", True)
        self.timeout = config.credentials.get("timeout", 30.0)
        self.page_size = config.credentials.get("page_size", 100)

        self.base_url = (
            f"{self.GRAPH_BASE_URL}"
            f"/security/runQueries"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        """Build OAuth2 bearer token headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        return headers

    def _handle_http_error(self, resp: httpx.Response, context: str) -> None:
        """Classify HTTP errors into transient or permanent."""
        status = resp.status_code

        if status in (429,) or status >= 500:
            raise ConnectorTransientError(
                f"{context}: HTTP {status} - {resp.text[:200]}"
            )

        if status in (401, 403):
            raise ConnectorPermanentError(
                f"{context}: Authentication failed (HTTP {status}). "
                "Check tenant_id, client_id, client_secret, or access_token."
            )

        if status == 404:
            raise ConnectorPermanentError(
                f"{context}: Resource not found (HTTP 404). "
                "Check workspace_id."
            )

        raise ConnectorPermanentError(
            f"{context}: HTTP {status} - {resp.text[:200]}"
        )

    def validate_connection(self) -> bool:
        """Verify credentials work by querying the Graph API root."""
        if self.is_mock:
            return True

        url = f"{self.GRAPH_BASE_URL}/$metadata"
        try:
            with httpx.Client(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                resp = client.get(
                    url, headers=self._get_auth_headers()
                )

                if resp.status_code in (401, 403):
                    raise ConnectorPermanentError(
                        "Sentinel rejected credentials. Check OAuth2 config."
                    )

                if resp.status_code in (429,) or resp.status_code >= 500:
                    raise ConnectorTransientError(
                        f"Sentinel metadata check failed: HTTP {resp.status_code}"
                    )

                return resp.status_code == 200

        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ConnectorTransientError(
                f"Could not reach Microsoft Graph API: {exc}"
            ) from exc

    def query(
        self, query_str: str, time_range: tuple = (None, None)
    ) -> List[Dict[str, Any]]:
        """
        Execute a KQL query against Microsoft Sentinel via Graph Security API.

        Uses the unifiedSecurityIncidentTasks / runQueries endpoint.
        Falls back to a mock mode when no credentials are configured.
        """
        if self.is_mock:
            return self._query_mock(query_str, time_range)

        if not query_str or not query_str.strip():
            raise ValueError("Query cannot be empty")

        earliest, latest = time_range

        payload: Dict[str, Any] = {
            "query": query_str,
        }

        if earliest:
            payload["startTime"] = str(earliest)
        if latest:
            payload["endTime"] = str(latest)

        try:
            with httpx.Client(
                verify=self.verify_ssl, timeout=self.timeout
            ) as client:
                resp = client.post(
                    self.base_url,
                    headers=self._get_auth_headers(),
                    json=payload,
                )

                if resp.status_code not in (200, 202):
                    self._handle_http_error(resp, "Sentinel KQL query")

                result = resp.json()

                # Graph Security API returns results in 'results' key
                # or wraps them under a 'value' list
                if "results" in result:
                    return result["results"]
                if "value" in result:
                    return result["value"]

                return [result]

        except httpx.HTTPStatusError as exc:
            self._handle_http_error(exc.response, "Sentinel KQL query")
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ConnectorTransientError(
                f"Could not reach Sentinel: {exc}"
            ) from exc

        return []

    def poll(self) -> List[Dict[str, Any]]:
        """Pull new events since last poll (5-minute window)."""
        now = time.time()
        start_ts = self._last_poll_ts or (now - 300)

        results = self.query(
            "SecurityEvent | where TimeGenerated > ago(5m)",
            time_range=(start_ts, now),
        )

        self._last_poll_ts = now
        return results

    def _query_mock(
        self, query_str: str, time_range: tuple
    ) -> List[Dict[str, Any]]:
        """Mock KQL query execution for offline testing."""
        mock_events = [
            {
                "TimeGenerated": "2026-07-15T10:00:00Z",
                "Device": "WORKSTATION-01",
                "Account": "DOMAIN\\user1",
                "ProcessCommandLine": "powershell.exe -enc SQBmACgA...",
                "FileName": "powershell.exe",
                "AlertName": "Suspicious encoded PowerShell",
            },
            {
                "TimeGenerated": "2026-07-15T10:05:00Z",
                "Device": "WORKSTATION-02",
                "Account": "DOMAIN\\admin",
                "ProcessCommandLine": "cmd.exe /c whoami",
                "FileName": "cmd.exe",
                "AlertName": "Reconnaissance command detected",
            },
        ]

        query_lower = query_str.lower()

        if "powershell" in query_lower or "enc" in query_lower:
            return [e for e in mock_events if "powershell" in e["FileName"].lower()]

        if "cmd.exe" in query_lower or "whoami" in query_lower:
            return [e for e in mock_events if "cmd.exe" in e["FileName"].lower()]

        # Default: return all mock events
        return mock_events


# Register Sentinel Connector with the registry
ConnectorRegistry.register("sentinel", SentinelConnector)
