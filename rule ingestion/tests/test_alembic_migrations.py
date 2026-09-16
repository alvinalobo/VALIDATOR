"""
Week 2 deliverable: Alembic migrations for the `detection_rules` table.

These tests exercise the migration through Alembic's offline mode, which
renders the DDL without connecting to a database. That keeps the check runnable
in CI on any machine (no PostgreSQL needed) while still proving that:

  * the revision is discovered from `alembic/versions/`;
  * `upgrade` emits the full table, its uniqueness constraints and indexes; and
  * `downgrade` cleanly reverses it.

A missing Alembic scaffold is exactly the kind of gap this suite is meant to
catch — before it, `alembic upgrade head` could not run at all because there
was no alembic.ini, no env.py and no versions directory.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

POSTGRES_URL = "postgresql://postgres:postgres@localhost:5432/rule_ingestion"


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    """Invoke the Alembic CLI with the project root as CWD."""
    env = dict(os.environ)
    env["DATABASE_URL"] = POSTGRES_URL
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_alembic_configuration_is_present():
    assert (PROJECT_ROOT / "alembic.ini").is_file()
    assert (PROJECT_ROOT / "alembic" / "env.py").is_file()
    assert (PROJECT_ROOT / "alembic" / "versions").is_dir()


def test_revision_is_discovered_as_the_only_head():
    result = _run_alembic("heads")
    assert result.returncode == 0, result.stderr

    heads = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(heads) == 1, f"expected exactly one head, got {heads}"
    assert "001_create_detection_rules" in heads[0]


def test_upgrade_emits_the_detection_rules_table():
    result = _run_alembic("upgrade", "head", "--sql")
    assert result.returncode == 0, result.stderr

    sql = result.stdout
    assert "CREATE TABLE detection_rules" in sql


@pytest.mark.parametrize(
    "expected",
    [
        # Every column the service relies on for version tracking.
        "rule_id VARCHAR(255) NOT NULL",
        "version VARCHAR(20)",
        "parent_rule_id UUID",
        "is_latest BOOLEAN",
        "content_hash VARCHAR(64) NOT NULL",
        "detection_logic JSONB NOT NULL",
        "mitre_techniques JSONB",
        "syntax_valid BOOLEAN",
        # Uniqueness: one row per rule revision, one row per distinct content.
        "CONSTRAINT uq_rule_version UNIQUE (rule_id, version)",
        "CONSTRAINT uq_content_hash UNIQUE (content_hash)",
        # Lookup indexes used by search/ingest.
        "CREATE INDEX ix_detection_rules_rule_id",
        "CREATE INDEX ix_detection_rules_content_hash",
        "CREATE INDEX ix_detection_rules_is_latest",
        "CREATE INDEX ix_detection_rules_status",
    ],
)
def test_upgrade_emits_expected_schema_elements(expected):
    result = _run_alembic("upgrade", "head", "--sql")
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout, f"missing from generated DDL: {expected}"


def test_downgrade_reverses_the_migration():
    result = _run_alembic("downgrade", "001_create_detection_rules:base", "--sql")
    assert result.returncode == 0, result.stderr

    sql = result.stdout
    assert "DROP INDEX ix_detection_rules_content_hash" in sql
    assert "DROP TABLE detection_rules" in sql
