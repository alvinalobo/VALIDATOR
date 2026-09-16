"""
Week 13 deliverable: performance testing of the Rule Ingestion Service.

Measures ingestion throughput (rules per second) for a repository of 1000+
rules, and verifies the large-repository optimisations actually pay off:

  * shallow clone (`depth=1`, `single_branch=True`) — already in `clone_repo`;
  * content-addressed parse memoisation — identical rule content is parsed
    once and reused, which is what makes repeat ingests of a big repository
    dramatically cheaper.

The thresholds below are deliberately loose floors, not benchmarks: they are
meant to catch a catastrophic regression (e.g. the parse cache silently
disabling, or per-rule work becoming quadratic), not to police CI machine
speed. Set SKIP_PERFORMANCE_TESTS=1 to skip this module.
"""

import os
import sys
import time
import uuid
from pathlib import Path

import pytest

# Configure python path to project root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from fastapi.testclient import TestClient

from app.main import app
from app.api import rules as rules_api
from app.api.rules import INGESTED_RULES

client = TestClient(app)

pytestmark = pytest.mark.skipif(
    os.getenv("SKIP_PERFORMANCE_TESTS") == "1",
    reason="performance tests disabled via SKIP_PERFORMANCE_TESTS=1",
)

# Conservative floors. Measured locally: ~100 rules/sec parse throughput
# (pySigma) and ~200 rules/sec through the lenient YAML path.
MIN_RULES_PER_SECOND = 20
LARGE_REPO_SIZE = 1000
KQL_REPO_SIZE = 20


@pytest.fixture(autouse=True)
def clean_state():
    INGESTED_RULES.clear()
    yield
    INGESTED_RULES.clear()


def _sigma_rule(index: int) -> str:
    """Generate a distinct, pySigma-valid Sigma rule."""
    return f"""title: Generated Detection Rule {index}
id: {uuid.UUID(int=index + 1)}
status: stable
description: Synthetic rule number {index} used by the throughput harness.
author: Perf Harness
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'synthetic-marker-{index}'
    condition: selection
level: medium
"""


def _kql_rule(index: int) -> str:
    return f"""// id: {uuid.UUID(int=500000 + index)}
// title: Generated KQL Rule {index}
// description: Synthetic KQL rule {index} used by the throughput harness.
// author: Perf Harness
// mitre: T1059.001
// level: medium

DeviceProcessEvents
| where ProcessCommandLine has "synthetic-kql-marker-{index}"
| project Timestamp, DeviceName, ProcessCommandLine
"""


def _build_repository(tmp_path: Path, sigma_count: int, kql_count: int) -> Path:
    """Write a synthetic rule repository to disk, mirroring a real checkout."""
    repo = tmp_path / "large_rule_repo"
    sigma_dir = repo / "rules" / "sigma"
    kql_dir = repo / "rules" / "kql"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    kql_dir.mkdir(parents=True, exist_ok=True)

    for i in range(sigma_count):
        (sigma_dir / f"rule_{i:05d}.yml").write_text(_sigma_rule(i), encoding="utf-8")

    for i in range(kql_count):
        (kql_dir / f"rule_{i:05d}.kql").write_text(_kql_rule(i), encoding="utf-8")

    return repo


def _ingest(repo: Path):
    started = time.perf_counter()
    response = client.post("/api/v2/rules/ingest", json={"repo_url": str(repo)})
    elapsed = time.perf_counter() - started
    assert response.status_code == 200, response.text
    return response.json(), elapsed


# ----------------------------------------------------------------------
# Throughput
# ----------------------------------------------------------------------

def test_ingests_a_thousand_rule_repository_within_the_throughput_floor(tmp_path):
    """A 1000+ rule repository must ingest at or above the throughput floor."""
    repo = _build_repository(tmp_path, LARGE_REPO_SIZE, KQL_REPO_SIZE)
    rules_api._PARSE_CACHE.clear()  # force a cold run

    parsed, elapsed = _ingest(repo)

    assert len(parsed) == LARGE_REPO_SIZE + KQL_REPO_SIZE
    assert all(rule["syntax_valid"] for rule in parsed)

    throughput = len(parsed) / elapsed
    assert throughput >= MIN_RULES_PER_SECOND, (
        f"ingestion throughput {throughput:.1f} rules/sec is below the floor of "
        f"{MIN_RULES_PER_SECOND} rules/sec ({len(parsed)} rules in {elapsed:.1f}s)"
    )


def test_discovery_finds_every_generated_rule_file(tmp_path):
    """File discovery must scale linearly and not walk into stray directories."""
    from app.api.rules import discover_rule_files

    repo = _build_repository(tmp_path, 200, 10)
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")

    discovered = discover_rule_files(str(repo), ["sigma", "kql"])

    assert len(discovered) == 210
    # .git contents must never be treated as rules.
    assert not any(f".git{os.sep}" in path for path in discovered)


# ----------------------------------------------------------------------
# Large-repository optimisation: parse memoisation
# ----------------------------------------------------------------------

def test_repeat_ingest_of_identical_content_is_much_faster(tmp_path):
    """
    Re-ingesting the same repository must be materially cheaper because
    identical content is parsed once. This is the measurable payoff of the
    content-addressed parse cache.
    """
    repo = _build_repository(tmp_path, 300, 10)

    rules_api._PARSE_CACHE.clear()
    _, cold_elapsed = _ingest(repo)

    # Warm run: every content hash is already cached.
    _, warm_elapsed = _ingest(repo)

    assert warm_elapsed < cold_elapsed, (
        f"warm ingest ({warm_elapsed:.2f}s) was not faster than cold "
        f"({cold_elapsed:.2f}s) — the parse cache is not being used"
    )


def test_parse_cache_holds_at_most_one_entry_per_distinct_content(tmp_path):
    repo = _build_repository(tmp_path, 50, 5)

    rules_api._PARSE_CACHE.clear()
    _ingest(repo)

    # 55 distinct rule files -> exactly 55 cache entries (one per content hash).
    assert len(rules_api._PARSE_CACHE) == 55


def test_duplicate_rule_content_is_parsed_once_but_still_returned_per_file(tmp_path):
    """
    Caching must not swallow rules: two files with identical content are two
    rules in the output, sharing one cache entry.
    """
    repo = tmp_path / "duplicate_repo"
    (repo / "sigma").mkdir(parents=True)
    (repo / "sigma" / "copy_a.yml").write_text(_sigma_rule(1), encoding="utf-8")
    (repo / "sigma" / "copy_b.yml").write_text(_sigma_rule(1), encoding="utf-8")

    rules_api._PARSE_CACHE.clear()
    parsed, _ = _ingest(repo)

    assert len(parsed) == 2
    assert parsed[0]["content_hash"] == parsed[1]["content_hash"]
    assert len(rules_api._PARSE_CACHE) == 1


def test_cached_and_uncached_parses_produce_identical_results(tmp_path):
    """Cache hits must be indistinguishable from a cold parse."""
    repo = _build_repository(tmp_path, 25, 0)

    rules_api._PARSE_CACHE.clear()
    cold, _ = _ingest(repo)

    warm, _ = _ingest(repo)

    cold_by_id = {r["rule_id"]: r for r in cold}
    warm_by_id = {r["rule_id"]: r for r in warm}

    assert cold_by_id.keys() == warm_by_id.keys()

    # `created_at` / `updated_at` are wall-clock defaults, so they legitimately
    # differ between two ingests; every content-derived field must not.
    volatile = {"created_at", "updated_at"}
    for rule_id, cold_rule in cold_by_id.items():
        stable_cold = {k: v for k, v in cold_rule.items() if k not in volatile}
        stable_warm = {k: v for k, v in warm_by_id[rule_id].items() if k not in volatile}
        assert stable_cold == stable_warm
