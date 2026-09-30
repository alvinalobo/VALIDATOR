"""m8: `clone_repo` must not fetch SSRF-serving targets.

m8 recorded that clone URLs were accepted with no guard against loopback,
link-local, private, reserved or multicast hosts — a caller could name
`169.254.169.254` or `127.0.0.1` and the pod would fetch it on their behalf.
`_validate_clone_url` now rejects those destinations for network URLs while
leaving local directory paths untouched (the integration suite ingests a local
fixture repo, so that branch must keep working offline).
"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.api.rules import _validate_clone_url, clone_repo

os.environ["SECRET_KEY"] = "test-secret-key"
_TOKEN = jwt.encode(
    {"tenant_id": "test-tenant"},
    os.environ["SECRET_KEY"],
    algorithm="HS256",
)

client = TestClient(
    __import__("app.main", fromlist=["app"]).app,
    headers={"Authorization": f"Bearer {_TOKEN}"},
)

FIXTURE_REPO = Path(__file__).resolve().parent / "fixtures" / "rule_repo"


def test_local_directory_path_is_still_allowed():
    """The offline fixture branch is a legit use of clone_repo; it must not be
    treated as a network fetch."""
    assert clone_repo(str(FIXTURE_REPO)) == os.path.abspath(str(FIXTURE_REPO))


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://127.0.0.1/repo.git",
        "http://localhost/repo.git",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.7/repo.git",
        "http://192.168.1.10/repo.git",
        "http://[::1]/repo.git",
    ],
)
def test_ssrf_targets_are_rejected(bad_url):
    with pytest.raises(ValueError):
        _validate_clone_url(bad_url)


@pytest.mark.parametrize(
    "good_url",
    [
        "https://github.com/SigmaHQ/sigma.git",
        "https://gitlab.com/sigma/sigma.git",
    ],
)
def test_public_and_git_urls_are_allowed(good_url):
    _validate_clone_url(good_url)


def test_ingest_rejects_ssrf_target_with_400():
    resp = client.post(
        "/api/v2/rules/ingest",
        json={
            "repo_url": "http://127.0.0.1/repo.git",
            "branch": "main",
            "rule_types": ["sigma"],
        },
    )
    assert resp.status_code == 400
    assert "Failed to clone repository" in resp.json()["detail"]