"""SQLAlchemy ORM models for VulnHunter."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    flows: Mapped[list[FlowRow]] = relationship(back_populates="user", cascade="all, delete-orphan")
    api_tokens: Mapped[list[APITokenRow]] = relationship(back_populates="user", cascade="all, delete-orphan")


class APITokenRow(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[UserRow] = relationship(back_populates="api_tokens")


class FlowRow(Base):
    __tablename__ = "flows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target_host: Mapped[str] = mapped_column(String(512), nullable=False)
    target_ports: Mapped[str] = mapped_column(Text, default="")
    custom_task: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    threat_level: Mapped[str] = mapped_column(String(32), default="Unknown")
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    remediation_steps: Mapped[Any] = mapped_column(JSON, default=list)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    user: Mapped[UserRow | None] = relationship(back_populates="flows")
    tasks: Mapped[list[TaskRow]] = relationship(back_populates="flow", cascade="all, delete-orphan")
    tool_results: Mapped[list[ToolResultRow]] = relationship(back_populates="flow", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list[VulnerabilityRow]] = relationship(back_populates="flow", cascade="all, delete-orphan")


class TaskRow(Base):
    __tablename__ = "tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    agent_role: Mapped[str] = mapped_column(String(32), default="orchestrator")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    flow: Mapped[FlowRow] = relationship(back_populates="tasks")
    subtasks: Mapped[list[SubTaskRow]] = relationship(back_populates="task", cascade="all, delete-orphan")


class SubTaskRow(Base):
    __tablename__ = "subtasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    agent_role: Mapped[str] = mapped_column(String(32), default="orchestrator")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    task: Mapped[TaskRow] = relationship(back_populates="subtasks")
    actions: Mapped[list[ActionRow]] = relationship(back_populates="subtask", cascade="all, delete-orphan")


class ActionRow(Base):
    __tablename__ = "actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    subtask_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("subtasks.id", ondelete="CASCADE"))
    agent_role: Mapped[str] = mapped_column(String(32), default="orchestrator")
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), default="")
    tool_input: Mapped[Any] = mapped_column(JSON, default=dict)
    tool_output: Mapped[str] = mapped_column(Text, default="")
    thought: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    subtask: Mapped[SubTaskRow] = relationship(back_populates="actions")


class ToolResultRow(Base):
    __tablename__ = "tool_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"))
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    raw_output: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[Any] = mapped_column(JSON, default=dict)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    flow: Mapped[FlowRow] = relationship(back_populates="tool_results")


class VulnerabilityRow(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_new_uuid)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    tool: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    cwe_id: Mapped[str] = mapped_column(String(32), default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    flow: Mapped[FlowRow] = relationship(back_populates="vulnerabilities")
