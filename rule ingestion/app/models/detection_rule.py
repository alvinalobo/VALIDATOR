from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, JSON, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    parent_rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    is_latest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    change_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    rule_format: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    syntax_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    validation_errors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    detection_logic: Mapped[dict | str] = mapped_column(JSON, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_id", "version", name="uq_tenant_rule_version"),
        UniqueConstraint("tenant_id", "content_hash", name="uq_tenant_content_hash"),
    )
