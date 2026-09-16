"""create detection_rules table

Revision ID: 001_create_detection_rules
Revises:
Create Date: 2026-09-16

Week 2 deliverable: the `detection_rules` table, which stores every ingested
rule version addressed by SHA-256 content hash.

The DDL itself is authored in `app.models.database` — that module is a plain
Alembic revision script (it defines `revision`/`upgrade`/`downgrade`, not an
ORM model) that predates this scaffold. Rather than duplicate ~170 lines of
column definitions and let the two copies drift, this module re-exports it so
Alembic discovers the revision from the conventional `alembic/versions/`
directory. New migrations should be written directly in this directory using
the `alembic revision` command.

Schema notes:
  * `UniqueConstraint("rule_id", "version")`  - one row per rule revision.
  * `UniqueConstraint("content_hash")`        - identical content is stored once,
    which is what makes version tracking idempotent.
  * `is_latest` / `parent_rule_id`            - support supersession chains without
    ever deleting a superseded revision, so past verdicts stay reproducible.
"""

from app.models.database import (  # noqa: F401
    branch_labels,
    depends_on,
    down_revision,
    downgrade,
    revision,
    upgrade,
)

__all__ = [
    "revision",
    "down_revision",
    "branch_labels",
    "depends_on",
    "upgrade",
    "downgrade",
]
