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
    # Tenant scoping moves the uniqueness guarantees from (rule_id, version)
    # and (content_hash) to tenant-prefixed variants, so two tenants can hold
    # identical rule content without colliding. Written with plain op.* calls
    # so it renders correctly in offline `--sql` mode (the CI check path).
    op.add_column(
        "detection_rules",
        sa.Column("tenant_id", sa.String(length=255), nullable=True),
    )
    op.create_index(
        "ix_detection_rules_tenant_id",
        "detection_rules",
        ["tenant_id"],
    )

    op.drop_constraint(
        "uq_rule_version",
        "detection_rules",
        type_="unique",
    )
    op.drop_constraint(
        "uq_content_hash",
        "detection_rules",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_tenant_rule_version",
        "detection_rules",
        ["tenant_id", "rule_id", "version"],
    )
    op.create_unique_constraint(
        "uq_tenant_content_hash",
        "detection_rules",
        ["tenant_id", "content_hash"],
    )


def downgrade():
    op.drop_constraint(
        "uq_tenant_content_hash",
        "detection_rules",
        type_="unique",
    )
    op.drop_constraint(
        "uq_tenant_rule_version",
        "detection_rules",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_content_hash",
        "detection_rules",
        ["content_hash"],
    )
    op.create_unique_constraint(
        "uq_rule_version",
        "detection_rules",
        ["rule_id", "version"],
    )
    op.drop_index(
        "ix_detection_rules_tenant_id",
        table_name="detection_rules",
    )
    op.drop_column("detection_rules", "tenant_id")