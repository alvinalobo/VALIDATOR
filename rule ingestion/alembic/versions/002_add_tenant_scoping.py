"""Add tenant scoping to detection rules.

Revision ID: 002_add_tenant_scoping
Revises: 001_create_detection_rules
"""

from alembic import op
import sqlalchemy as sa


revision = "002_add_tenant_scoping"
down_revision = "001_create_detection_rules"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = {
        column["name"]
        for column in inspector.get_columns("detection_rules")
    }

    if "tenant_id" not in columns:
        op.add_column(
            "detection_rules",
            sa.Column("tenant_id", sa.String(length=255), nullable=True),
        )

    indexes = {
        index["name"]
        for index in inspector.get_indexes("detection_rules")
    }

    if "ix_detection_rules_tenant_id" not in indexes:
        op.create_index(
            "ix_detection_rules_tenant_id",
            "detection_rules",
            ["tenant_id"],
        )

    with op.batch_alter_table("detection_rules") as batch_op:
        try:
            batch_op.drop_constraint("uq_rule_version", type_="unique")
        except Exception:
            pass

        try:
            batch_op.drop_constraint("uq_content_hash", type_="unique")
        except Exception:
            pass

        batch_op.create_unique_constraint(
            "uq_tenant_rule_version",
            ["tenant_id", "rule_id", "version"],
        )
        batch_op.create_unique_constraint(
            "uq_tenant_content_hash",
            ["tenant_id", "content_hash"],
        )


def downgrade():
    with op.batch_alter_table("detection_rules") as batch_op:
        batch_op.drop_constraint(
            "uq_tenant_content_hash",
            type_="unique",
        )
        batch_op.drop_constraint(
            "uq_tenant_rule_version",
            type_="unique",
        )

        batch_op.create_unique_constraint(
            "uq_content_hash",
            ["content_hash"],
        )
        batch_op.create_unique_constraint(
            "uq_rule_version",
            ["rule_id", "version"],
        )

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    indexes = {
        index["name"]
        for index in inspector.get_indexes("detection_rules")
    }

    if "ix_detection_rules_tenant_id" in indexes:
        op.drop_index(
            "ix_detection_rules_tenant_id",
            table_name="detection_rules",
        )
