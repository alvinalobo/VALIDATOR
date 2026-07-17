
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid

revision = "001_create_detection_rules"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "detection_rules",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            default=uuid.uuid4
        ),

        sa.Column(
            "rule_id",
            sa.String(255),
            nullable=False
        ),

        sa.Column(
            "version",
            sa.String(20),
            nullable=False,
            server_default="1.0"
        ),

        sa.Column(
            "parent_rule_id",
            UUID(as_uuid=True),
            nullable=True
        ),

        sa.Column(
            "is_latest",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true")
        ),

        sa.Column(
            "title",
            sa.String(500),
            nullable=False
        ),

        sa.Column(
            "description",
            sa.Text(),
            nullable=True
        ),

        sa.Column(
            "author",
            sa.String(255),
            nullable=True
        ),

        sa.Column(
            "created_by",
            sa.String(255),
            nullable=True
        ),

        sa.Column(
            "change_log",
            sa.Text(),
            nullable=True
        ),

        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="active"
        ),

        sa.Column(
            "rule_format",
            sa.String(20),
            nullable=False
        ),

        sa.Column(
            "severity",
            sa.String(20),
            nullable=True
        ),

        sa.Column(
            "content_hash",
            sa.String(64),
            nullable=False
        ),

        sa.Column(
            "syntax_valid",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true")
        ),

        sa.Column(
            "validation_errors",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb")
        ),

        sa.Column(
            "mitre_techniques",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb")
        ),

        sa.Column(
            "detection_logic",
            JSONB,
            nullable=False
        ),

        sa.Column(
            "tags",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb")
        ),

        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now()
        ),

        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now()
        ),

        sa.UniqueConstraint(
            "rule_id",
            "version",
            name="uq_rule_version"
        ),

        sa.UniqueConstraint(
            "content_hash",
            name="uq_content_hash"
        )
    )

    op.create_index("ix_detection_rules_rule_id","detection_rules",["rule_id"])
    op.create_index("ix_detection_rules_version","detection_rules",["version"])
    op.create_index("ix_detection_rules_is_latest","detection_rules",["is_latest"])
    op.create_index("ix_detection_rules_rule_format","detection_rules",["rule_format"])
    op.create_index("ix_detection_rules_content_hash","detection_rules",["content_hash"])
    op.create_index("ix_detection_rules_status","detection_rules",["status"])

def downgrade():
    op.drop_index("ix_detection_rules_status", table_name="detection_rules")
    op.drop_index("ix_detection_rules_content_hash", table_name="detection_rules")
    op.drop_index("ix_detection_rules_rule_format", table_name="detection_rules")
    op.drop_index("ix_detection_rules_is_latest", table_name="detection_rules")
    op.drop_index("ix_detection_rules_version", table_name="detection_rules")
    op.drop_index("ix_detection_rules_rule_id", table_name="detection_rules")
    op.drop_table("detection_rules")