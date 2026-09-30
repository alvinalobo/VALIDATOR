"""m1: /health must use the cross-pod envelope and probe a dependency.

m1 recorded that Alpha returned a hardcoded "healthy" string while
Beta/Gamma/Delta already return the {status, service} envelope. The endpoint
now returns {status, service} and proves liveness by reading through the
database engine (the one dependency a live pod must reach).
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_the_cross_pod_envelope():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "rule-ingestion"


def test_health_probes_the_database_engine():
    """The endpoint must hit the engine; a DB failure surfaces as degraded
    rather than a crash or a misleading healthy string."""
    import app.main as main_module

    original = main_module.engine

    class _BrokenEngine:
        def connect(self):
            raise RuntimeError("db unreachable")

    try:
        main_module.engine = _BrokenEngine()
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json() == {"status": "degraded", "service": "rule-ingestion"}
    finally:
        main_module.engine = original