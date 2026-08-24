

import re
import time
from typing import Any, Dict, List

import requests

from app.connector.base_connector import BaseConnector, ConnectorConfig, ConnectorRegistry
try:
    from app.connector.exceptions import ConnectorPermanentError, ConnectorTransientError
    from app.connector.retry import with_retry
except ImportError:
    # Fallback so this file works even before exceptions.py/retry.py exist.
    class ConnectorTransientError(Exception):
        pass

    class ConnectorPermanentError(Exception):
        pass

    def with_retry(**_kwargs):
        def decorator(func):
            return func
        return decorator


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

_EQL_START_RE = re.compile(
    r"^\s*(process|file|network|registry|dns|library|driver|any)\s+where\b",
    re.IGNORECASE,
)
_EQL_SEQUENCE_RE = re.compile(r"^\s*sequence\b", re.IGNORECASE)


def _detect_query_language(query_str: str) -> str:
    """Heuristic EQL/KQL detection. Returns 'eql' or 'kql'."""
    if _EQL_START_RE.match(query_str) or _EQL_SEQUENCE_RE.match(query_str):
        return "eql"
    return "kql"


def _raise_for_status(resp: requests.Response, context: str) -> None:
    if resp.status_code < 400:
        return
    if resp.status_code in _RETRYABLE_STATUS_CODES:
        raise ConnectorTransientError(f"{context}: {resp.status_code} {resp.text[:200]}")
    raise ConnectorPermanentError(f"{context}: {resp.status_code} {resp.text[:200]}")


class ElasticConnector(BaseConnector):
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self._base_url = config.credentials["base_url"].rstrip("/")
        self._index = config.scope.get("index", "*") if config.scope else "*"
        self._forced_language = config.scope.get("language") if config.scope else None

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"ApiKey {config.credentials['api_key']}",
                "Content-Type": "application/json",
            }
        )

    @with_retry(max_attempts=4, base_delay=1.0, max_delay=20.0)
    def query(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        language = self._forced_language or _detect_query_language(query_str)
        if language == "eql":
            return self._query_eql(query_str, time_range)
        return self._query_kql(query_str, time_range)

    def _query_eql(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        earliest, latest = time_range
        body = {
            "query": query_str,
            "filter": {"range": {"@timestamp": {"gte": earliest, "lte": latest}}},
        }
        try:
            resp = self._session.post(
                f"{self._base_url}/{self._index}/_eql/search",
                json=body,
                timeout=30,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(f"Could not reach Elastic (EQL): {exc}") from exc

        _raise_for_status(resp, "EQL search failed")
        return self._extract_eql_hits(resp.json())

    def _query_kql(self, query_str: str, time_range: tuple) -> List[Dict[str, Any]]:
        earliest, latest = time_range
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query_str}}],
                    "filter": [{"range": {"@timestamp": {"gte": earliest, "lte": latest}}}],
                }
            }
        }
        try:
            resp = self._session.post(
                f"{self._base_url}/{self._index}/_search",
                json=body,
                timeout=30,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(f"Could not reach Elastic (KQL): {exc}") from exc

        _raise_for_status(resp, "KQL search failed")
        return self._extract_search_hits(resp.json())

    @staticmethod
    def _extract_eql_hits(response_body: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = response_body.get("hits", {}).get("events", [])
        return [e.get("_source", {}) for e in events]

    @staticmethod
    def _extract_search_hits(response_body: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = response_body.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def poll(self) -> List[Dict[str, Any]]:
        """Pull events since the last poll (or the last hour, on first call)."""
        earliest = "now-1h" if self._last_poll_ts is None else "now-5m"
        results = self._query_kql("*", (earliest, "now"))
        self._last_poll_ts = time.time()
        return results

    @with_retry(max_attempts=3, base_delay=1.0, max_delay=10.0)
    def validate_connection(self) -> bool:
        try:
            resp = self._session.get(f"{self._base_url}/_cluster/health", timeout=5)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ConnectorTransientError(f"Could not reach Elastic: {exc}") from exc

        if resp.status_code in (401, 403):
            raise ConnectorPermanentError("Elastic rejected the API key — check credentials")
        if resp.status_code in _RETRYABLE_STATUS_CODES:
            raise ConnectorTransientError(f"Elastic health check returned {resp.status_code}")
        return resp.status_code == 200
