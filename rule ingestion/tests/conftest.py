import sys
from pathlib import Path
import time
import socket
import threading
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


# ============================================================
# PROJECT ROOT / PYTHON PATH FIX
# ============================================================
# conftest.py location:
# rule ingestion/
# └── app/
#     └── connector/
#         └── tests/
#             └── conftest.py
#
# parents[3] => rule ingestion/
PROJECT_ROOT = Path(__file__).resolve().parents[3]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# GLOBAL MOCK SERVER STATE
# ============================================================

MOCK_SERVER_STATE = {
    # ---------------- SPLUNK ----------------
    "splunk_dispatch_status_calls": 0,
    "splunk_dispatch_state": "DONE",

    "splunk_results_response": {
        "results": [
            {
                "_raw": "splunk_test"
            }
        ]
    },

    # ---------------- ELASTIC ----------------
    "elastic_health_status": 200,
    "elastic_health_calls": 0,

    "elastic_search_status": 200,
    "elastic_search_response": {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "event": "kql_test"
                    }
                }
            ]
        }
    },

    "elastic_eql_status": 200,
    "elastic_eql_response": {
        "hits": {
            "events": [
                {
                    "_source": {
                        "event": "eql_test"
                    }
                }
            ]
        }
    },

    # ---------------- QRADAR ----------------
    "qradar_health_status": 200,
    "qradar_search_create_status": 201,
    "qradar_search_status": "COMPLETED",
    "qradar_search_status_calls": 0,

    "qradar_search_id": "qradar-test-search-123",

    "qradar_results_response": {
        "events": [
            {
                "sourceip": "192.168.1.10",
                "destinationip": "10.0.0.10",
                "username": "admin",
                "eventname": "Successful Login",
                "qid": 5001
            },
            {
                "sourceip": "192.168.1.20",
                "destinationip": "10.0.0.20",
                "username": "user1",
                "eventname": "Failed Login",
                "qid": 5002
            }
        ]
    },
}


# ============================================================
# MOCK SIEM HTTP SERVER
# ============================================================

class MockSIEMRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """
        Suppress HTTP server logs during pytest execution.
        """
        pass

    # ========================================================
    # GET REQUESTS
    # ========================================================

    def do_GET(self):

        # ----------------------------------------------------
        # SPLUNK AUTH VALIDATION
        # ----------------------------------------------------
        if "services/authentication/current-context" in self.path:

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            self.wfile.write(
                json.dumps(
                    {
                        "username": "admin"
                    }
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # SPLUNK JOB POLL RESULTS
        # ----------------------------------------------------
        if (
            "services/search/jobs/" in self.path
            and "/results" in self.path
        ):

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            self.wfile.write(
                json.dumps(
                    MOCK_SERVER_STATE[
                        "splunk_results_response"
                    ]
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # SPLUNK JOB POLL STATUS
        # ----------------------------------------------------
        if (
            "services/search/jobs/" in self.path
            and "/results" not in self.path
        ):

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            MOCK_SERVER_STATE[
                "splunk_dispatch_status_calls"
            ] += 1

            self.wfile.write(
                json.dumps(
                    {
                        "entry": [
                            {
                                "content": {
                                    "dispatchState":
                                    MOCK_SERVER_STATE[
                                        "splunk_dispatch_state"
                                    ]
                                }
                            }
                        ]
                    }
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # ELASTIC HEALTH CHECK
        # ----------------------------------------------------
        if "_cluster/health" in self.path:

            status = MOCK_SERVER_STATE[
                "elastic_health_status"
            ]

            MOCK_SERVER_STATE[
                "elastic_health_calls"
            ] += 1

            # Support transient retry testing
            if isinstance(status, list):

                index = min(
                    MOCK_SERVER_STATE[
                        "elastic_health_calls"
                    ] - 1,
                    len(status) - 1
                )

                current_status = status[index]

            else:
                current_status = status

            self.send_response(current_status)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            if current_status == 200:

                self.wfile.write(
                    json.dumps(
                        {
                            "status": "green"
                        }
                    ).encode("utf-8")
                )

            else:

                self.wfile.write(
                    json.dumps(
                        {
                            "error":
                            f"HTTP {current_status} error"
                        }
                    ).encode("utf-8")
                )

            return

        # ----------------------------------------------------
        # QRADAR CONNECTION VALIDATION
        # ----------------------------------------------------
        if "/api/ariel/searches" in self.path:

            status = MOCK_SERVER_STATE[
                "qradar_health_status"
            ]

            self.send_response(status)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            if status == 200:

                self.wfile.write(
                    json.dumps(
                        {
                            "searches": []
                        }
                    ).encode("utf-8")
                )

            else:

                self.wfile.write(
                    json.dumps(
                        {
                            "error": "QRadar unavailable"
                        }
                    ).encode("utf-8")
                )

            return

        # ----------------------------------------------------
        # QRADAR SEARCH STATUS
        # ----------------------------------------------------
        if "/api/ariel/searches/" in self.path:

            # Results endpoint should be checked separately
            if self.path.endswith("/results"):

                self.send_response(200)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    json.dumps(
                        MOCK_SERVER_STATE[
                            "qradar_results_response"
                        ]
                    ).encode("utf-8")
                )

                return

            MOCK_SERVER_STATE[
                "qradar_search_status_calls"
            ] += 1

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps(
                    {
                        "search_id":
                        MOCK_SERVER_STATE[
                            "qradar_search_id"
                        ],
                        "status":
                        MOCK_SERVER_STATE[
                            "qradar_search_status"
                        ]
                    }
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # NOT FOUND
        # ----------------------------------------------------
        self.send_response(404)
        self.end_headers()

    # ========================================================
    # POST REQUESTS
    # ========================================================

    def do_POST(self):

        # ----------------------------------------------------
        # SPLUNK DISPATCH JOB
        # ----------------------------------------------------
        if "services/search/jobs" in self.path:

            self.send_response(201)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps(
                    {
                        "sid": "job_12345"
                    }
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # QRADAR ARIEL SEARCH CREATION
        # ----------------------------------------------------
        if "/api/ariel/searches" in self.path:

            status = MOCK_SERVER_STATE[
                "qradar_search_create_status"
            ]

            self.send_response(status)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            if status in (200, 201):

                self.wfile.write(
                    json.dumps(
                        {
                            "search_id":
                            MOCK_SERVER_STATE[
                                "qradar_search_id"
                            ]
                        }
                    ).encode("utf-8")
                )

            else:

                self.wfile.write(
                    json.dumps(
                        {
                            "error":
                            "QRadar search creation failed"
                        }
                    ).encode("utf-8")
                )

            return

        # ----------------------------------------------------
        # ELASTIC EQL SEARCH
        # ----------------------------------------------------
        if "/_eql/search" in self.path:

            status = MOCK_SERVER_STATE[
                "elastic_eql_status"
            ]

            self.send_response(status)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps(
                    MOCK_SERVER_STATE[
                        "elastic_eql_response"
                    ]
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # ELASTIC STANDARD SEARCH / KQL
        # ----------------------------------------------------
        if "/_search" in self.path:

            status = MOCK_SERVER_STATE[
                "elastic_search_status"
            ]

            self.send_response(status)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                json.dumps(
                    MOCK_SERVER_STATE[
                        "elastic_search_response"
                    ]
                ).encode("utf-8")
            )

            return

        # ----------------------------------------------------
        # NOT FOUND
        # ----------------------------------------------------
        self.send_response(404)
        self.end_headers()


# ============================================================
# FREE PORT FINDER
# ============================================================

def get_free_port():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.bind(
        ("127.0.0.1", 0)
    )

    port = sock.getsockname()[1]

    sock.close()

    return port


# ============================================================
# MOCK SERVER FIXTURE
# ============================================================

@pytest.fixture(scope="session")
def mock_server_url():

    port = get_free_port()

    server = HTTPServer(
        ("127.0.0.1", port),
        MockSIEMRequestHandler
    )

    server_thread = threading.Thread(
        target=server.serve_forever
    )

    server_thread.daemon = True
    server_thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


# ============================================================
# RESET MOCK STATE BEFORE EVERY TEST
# ============================================================

@pytest.fixture(autouse=True)
def reset_mock_state():

    MOCK_SERVER_STATE.clear()

    MOCK_SERVER_STATE.update({

        # ---------------- SPLUNK ----------------

        "splunk_dispatch_status_calls": 0,

        "splunk_dispatch_state": "DONE",

        "splunk_results_response": {
            "results": [
                {
                    "_raw": "splunk_test"
                }
            ]
        },

        # ---------------- ELASTIC ----------------

        "elastic_health_status": 200,

        "elastic_health_calls": 0,

        "elastic_search_status": 200,

        "elastic_search_response": {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "event": "kql_test"
                        }
                    }
                ]
            }
        },

        "elastic_eql_status": 200,

        "elastic_eql_response": {
            "hits": {
                "events": [
                    {
                        "_source": {
                            "event": "eql_test"
                        }
                    }
                ]
            }
        },

        # ---------------- QRADAR ----------------

        "qradar_health_status": 200,

        "qradar_search_create_status": 201,

        "qradar_search_status": "COMPLETED",

        "qradar_search_status_calls": 0,

        "qradar_search_id": "qradar-test-search-123",

        "qradar_results_response": {
            "events": [
                {
                    "sourceip": "192.168.1.10",
                    "destinationip": "10.0.0.10",
                    "username": "admin",
                    "eventname": "Successful Login",
                    "qid": 5001
                },
                {
                    "sourceip": "192.168.1.20",
                    "destinationip": "10.0.0.20",
                    "username": "user1",
                    "eventname": "Failed Login",
                    "qid": 5002
                }
            ]
        }
    })