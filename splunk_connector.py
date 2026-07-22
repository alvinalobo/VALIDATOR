
"""
splunk_connector.py

Single-file Splunk Connector Framework
Features:
- SPL Query Execution
- Splunk REST API Integration
- Token / Basic Authentication
- Pagination
- Rate Limiting
- Retry Logic
- Connection Validation
- Polling
- Mock Mode
"""

import time
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConnectorConfig:
    def __init__(self, credentials: Dict[str, Any]):
        self.credentials = credentials


class ConnectorRegistry:
    _registry = {}

    @classmethod
    def register(cls, name, connector):
        cls._registry[name] = connector


class BaseConnector:
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self._last_poll_ts = None

    def query(self, *args, **kwargs):
        raise NotImplementedError

    def poll(self):
        raise NotImplementedError

    def validate_connection(self):
        raise NotImplementedError


class RateLimiter:
    def __init__(self, requests_per_second=5):
        self.delay = 1 / max(requests_per_second, 1)
        self.last = 0

    def wait(self):
        now = time.time()
        elapsed = now - self.last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last = time.time()


class SplunkConnector(BaseConnector):

    READ_ONLY_BLOCKLIST = (
        "outputlookup",
        "collect",
        "delete",
        "script",
        "map",
    )

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)

        c = config.credentials

        self.host = c.get("host", "").rstrip("/")
        self.port = c.get("port", 8089)
        self.scheme = c.get("scheme", "https")
        self.token = c.get("token")
        self.username = c.get("username")
        self.password = c.get("password")
        self.verify_ssl = c.get("verify_ssl", False)
        self.timeout = c.get("timeout", 30)
        self.page_size = c.get("page_size", 1000)
        self.max_retry = c.get("retry", 3)
        self.mock = c.get("mock", not bool(self.host))

        self.base_url = f"{self.scheme}://{self.host}:{self.port}" if self.host else ""
        self.client = httpx.Client(
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        self.rate = RateLimiter(c.get("requests_per_second", 5))

    def _headers(self):
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _auth(self):
        if self.token:
            return None
        if self.username and self.password:
            return (self.username, self.password)
        return None

    def _request(self, method, url, **kwargs):
        last = None
        for i in range(self.max_retry):
            try:
                self.rate.wait()
                r = self.client.request(
                    method,
                    url,
                    headers=self._headers(),
                    auth=self._auth(),
                    **kwargs
                )
                r.raise_for_status()
                return r
            except Exception as e:
                last = e
                logger.warning("Retry %s/%s : %s", i + 1, self.max_retry, e)
                time.sleep(2 ** i)
        raise last

    def validate_connection(self):
        if self.mock:
            return True

        try:
            url = self.base_url + "/services/authentication/current-context?output_mode=json"
            self._request("GET", url)
            return True
        except Exception:
            return False

    def _validate_query(self, q):
        lower = q.lower()
        for item in self.READ_ONLY_BLOCKLIST:
            if item in lower:
                raise ValueError(f"Blocked SPL command: {item}")

    def _create_job(self, q, earliest=None, latest=None):
        payload = {
            "search": q if q.startswith("search") else "search " + q,
            "output_mode": "json"
        }
        if earliest:
            payload["earliest_time"] = earliest
        if latest:
            payload["latest_time"] = latest

        url = self.base_url + "/services/search/jobs"
        r = self._request("POST", url, data=payload)
        return r.json()["sid"]

    def _wait_job(self, sid):
        url = self.base_url + f"/services/search/jobs/{sid}?output_mode=json"
        for _ in range(60):
            r = self._request("GET", url)
            state = (
                r.json()
                .get("entry", [{}])[0]
                .get("content", {})
                .get("dispatchState")
            )
            if state == "DONE":
                return
            time.sleep(1)
        raise TimeoutError("Search timeout")

    def _results(self, sid):
        all_rows = []
        offset = 0
        while True:
            url = (
                self.base_url
                + f"/services/search/jobs/{sid}/results"
                + f"?output_mode=json&count={self.page_size}&offset={offset}"
            )
            r = self._request("GET", url)
            rows = r.json().get("results", [])
            if not rows:
                break
            all_rows.extend(rows)
            if len(rows) < self.page_size:
                break
            offset += self.page_size
        return all_rows

    def _cleanup(self, sid):
        try:
            url = self.base_url + f"/services/search/jobs/{sid}"
            self._request("DELETE", url)
        except Exception:
            pass

    def _mock(self, q):
        data = [
            {
                "host": "PC-01",
                "Image": "vssadmin.exe",
                "CommandLine": "vssadmin delete shadows /all /quiet",
                "_time": "2026-07-20T10:00:00"
            },
            {
                "host": "PC-02",
                "Image": "msiexec.exe",
                "CommandLine": "msiexec /i malware.msi",
                "_time": "2026-07-20T10:01:00"
            }
        ]
        q = q.lower()
        return [
            d for d in data
            if q == "*" or q in str(d).lower()
        ]

    def query(
        self,
        query_str: str,
        time_range: Tuple[Optional[str], Optional[str]] = (None, None)
    ) -> List[Dict]:

        if self.mock:
            return self._mock(query_str)

        self._validate_query(query_str)

        sid = self._create_job(
            query_str,
            earliest=time_range[0],
            latest=time_range[1]
        )

        try:
            self._wait_job(sid)
            return self._results(sid)
        finally:
            self._cleanup(sid)

    def poll(self):
        now = int(time.time())
        start = self._last_poll_ts or now - 300
        self._last_poll_ts = now
        return self.query(
            "index=*",
            (str(start), str(now))
        )


ConnectorRegistry.register("splunk", SplunkConnector)


if __name__ == "__main__":

    config = ConnectorConfig({
        "host": "YOUR-SPLUNK-HOST",
        "port": 8089,
        "scheme": "https",
        "token": "YOUR_SPLUNK_TOKEN",
        "verify_ssl": True,
        "mock": False,
        "requests_per_second": 5,
        "page_size": 1000,
    })

    connector = SplunkConnector(config)

    if connector.validate_connection():
        print("connection successful")
        events = connector.query("*")
        print(events)
    else:
        print("unable to connect to splunk")
        print("management api is not reachable")