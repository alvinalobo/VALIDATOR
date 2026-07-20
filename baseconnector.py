"""
sentinel_connector.py

Implements BaseConnector against Microsoft Sentinel's underlying Log
Analytics workspace query API (KQL), which — unlike Splunk — is
synchronous: POST the KQL, get results back in one call.

config.credentials needs: 'workspace_id', 'token' (Azure AD bearer token).
"""

import time
from typing import Any, Dict, List

import requests

from app.base_connector import BaseConnector, ConnectorConfig

_LOG_ANALYTICS_BASE = "https://api.loganalytics.io/v1/workspaces"


class SentinelConnectionError(Exception):
    """Raised when the Log Analytics workspace can't be reached or auth fails."""


class SentinelConnector(BaseConnector):
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._workspace_id = config.credentials["workspace_id"]
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {config.credentials['token']}",
                "Content-Type": "application/json",
            }
        )

    def query(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        earliest, latest = time_range
        timespan = f"{earliest}/{latest}"

        resp = self._session.post(
            f"{_LOG_ANALYTICS_BASE}/{self._workspace_id}/query",
            json={"query": query_str, "timespan": timespan},
            timeout=30,
        )
        if resp.status_code != 200:
            raise SentinelConnectionError(f"Query failed: {resp.status_code} {resp.text}")

        return self._rows_to_dicts(resp.json())

    @staticmethod
    def _rows_to_dicts(response_body: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Log Analytics returns column-oriented tables; zip columns+rows
        into a list of dicts so callers get the same shape regardless
        of which connector produced the results."""
        tables = response_body.get("tables", [])
        if not tables:
            return []
        table = tables[0]
        column_names = [c["name"] for c in table["columns"]]
        return [dict(zip(column_names, row)) for row in table["rows"]]

    def poll(self) -> List[Dict[str, Any]]:
        earliest = "-1h" if self._last_poll_ts is None else "-5m"
        results = self.query("union * | take 1000", (earliest, "now"))
        self._last_poll_ts = time.time()
        return results

    def validate_connection(self) -> bool:
        try:
            resp = self._session.post(
                f"{_LOG_ANALYTICS_BASE}/{self._workspace_id}/query",
                json={"query": "print 1", "timespan": "PT1H"},
                timeout=5,
            )
        except requests.RequestException:
            return False
        if resp.status_code == 401:
            raise ConnectionError("Sentinel rejected the auth token — check credentials")
        return resp.status_code == 200
        