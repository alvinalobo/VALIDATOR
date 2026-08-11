from typing import List, Dict, Any

import httpx

from app.connector.base_connector import BaseConnector, ConnectorConfig


class CrowdStrikeLogScaleConnector(BaseConnector):

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        self.host = config.credentials.get("host", "").rstrip("/")
        self.token = config.credentials.get("token")
        self.repository = config.scope.get("repository", "")
        self._last_job_id = None

    def _get_auth_headers(self) -> Dict[str, str]:
        if not self.token:
            raise ValueError("CrowdStrike LogScale API token is required")

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _get_query_url(self) -> str:
        if not self.host:
            raise ValueError("CrowdStrike LogScale host is required")

        if not self.repository:
            raise ValueError("CrowdStrike LogScale repository is required")

        return (
            f"{self.host}/api/v1/repositories/"
            f"{self.repository}/queryjobs"
        )

    def _get_query_result_url(self, job_id: str) -> str:
        if not job_id:
            raise ValueError("Query job ID is required")

        return (
            f"{self.host}/api/v1/repositories/"
            f"{self.repository}/queryjobs/{job_id}"
        )

    def query(
        self,
        query_str: str,
        time_range: tuple
    ) -> List[Dict[str, Any]]:
        if not query_str or not query_str.strip():
            raise ValueError("Query cannot be empty")

        if len(time_range) != 2:
            raise ValueError("time_range must contain start and end values")

        start, end = time_range

        payload = {
            "queryString": query_str,
            "start": start,
            "end": end,
            "isLive": False,
        }

        response = httpx.post(
            self._get_query_url(),
            headers=self._get_auth_headers(),
            json=payload,
            timeout=30.0,
        )

        response.raise_for_status()

        result = response.json()

        self._last_job_id = result.get("id")

        return [result]

    def poll(self) -> List[Dict[str, Any]]:
        if not self._last_job_id:
            raise ValueError("No query job is available to poll")

        response = httpx.get(
            self._get_query_result_url(self._last_job_id),
            headers=self._get_auth_headers(),
            timeout=30.0,
        )

        response.raise_for_status()

        result = response.json()

        if isinstance(result, list):
            return result

        return [result]

    def validate_connection(self) -> bool:
        try:
            response = httpx.get(
                self._get_query_url(),
                headers=self._get_auth_headers(),
                timeout=30.0,
            )

            return response.status_code == 200

        except (httpx.HTTPError, ValueError):
            return False