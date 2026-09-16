"""
Alembic runtime environment for the Rule Ingestion Service.

Resolves the database URL from the `DATABASE_URL` environment variable and
falls back to a local SQLite file so migrations can be run (and smoke-tested)
without a running PostgreSQL instance.

Supports both offline mode (`alembic upgrade head --sql`, which emits SQL
without connecting — used to verify migrations in CI without a database) and
online mode (`alembic upgrade head`).
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the application package importable so migration scripts can reference it.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Alembic Config object, providing access to values in alembic.ini.
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# No declarative ORM metadata is used for autogenerate; the schema is authored
# explicitly in the revision scripts under alembic/versions/.
target_metadata = None

DEFAULT_DATABASE_URL = "sqlite:///./rule_ingestion.db"


def get_database_url() -> str:
    """Environment-driven URL, falling back to a local SQLite database."""
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to a database."""
    context.configure(
        url=get_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect to the database and run migrations in a transaction."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
