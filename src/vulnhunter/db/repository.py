"""CRUD repository for VulnHunter database operations."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vulnhunter.db.models import (
    ActionRow, APITokenRow, FlowRow, SubTaskRow, TaskRow,
    ToolResultRow, UserRow, VulnerabilityRow,
)


class Repository:
    """Encapsulates all database queries."""

    def __init__(self, session: AsyncSession):
        self.s = session

    # ── Users ───────────────────────────────────────────────────────────
    async def create_user(self, email: str, password_hash: str, display_name: str = "", is_admin: bool = False) -> UserRow:
        user = UserRow(email=email, password_hash=password_hash, display_name=display_name, is_admin=is_admin)
        self.s.add(user)
        await self.s.flush()
        return user

    async def get_user_by_email(self, email: str) -> UserRow | None:
        result = await self.s.execute(select(UserRow).where(UserRow.email == email))
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: uuid.UUID) -> UserRow | None:
        result = await self.s.execute(select(UserRow).where(UserRow.id == user_id))
        return result.scalar_one_or_none()

    # ── API Tokens ──────────────────────────────────────────────────────
    async def create_api_token(self, user_id: uuid.UUID, token_hash: str, name: str, expires_at: datetime) -> APITokenRow:
        token = APITokenRow(user_id=user_id, token_hash=token_hash, name=name, expires_at=expires_at)
        self.s.add(token)
        await self.s.flush()
        return token

    async def get_api_token_by_hash(self, token_hash: str) -> APITokenRow | None:
        result = await self.s.execute(
            select(APITokenRow).where(APITokenRow.token_hash == token_hash, APITokenRow.revoked == False)
        )
        return result.scalar_one_or_none()

    async def list_api_tokens(self, user_id: uuid.UUID) -> Sequence[APITokenRow]:
        result = await self.s.execute(
            select(APITokenRow).where(APITokenRow.user_id == user_id).order_by(APITokenRow.created_at.desc())
        )
        return result.scalars().all()

    async def revoke_api_token(self, token_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        result = await self.s.execute(
            update(APITokenRow).where(APITokenRow.id == token_id, APITokenRow.user_id == user_id).values(revoked=True)
        )
        return result.rowcount > 0

    # ── Flows ───────────────────────────────────────────────────────────
    async def create_flow(
        self, target_host: str, target_ports: str = "", custom_task: str = "", user_id: uuid.UUID | None = None,
    ) -> FlowRow:
        flow = FlowRow(target_host=target_host, target_ports=target_ports, custom_task=custom_task, user_id=user_id)
        self.s.add(flow)
        await self.s.flush()
        return flow

    async def get_flow(self, flow_id: uuid.UUID) -> FlowRow | None:
        result = await self.s.execute(
            select(FlowRow)
            .options(
                selectinload(FlowRow.tasks).selectinload(TaskRow.subtasks),
                selectinload(FlowRow.tool_results),
                selectinload(FlowRow.vulnerabilities),
            )
            .where(FlowRow.id == flow_id)
        )
        return result.scalar_one_or_none()

    async def list_flows(self, user_id: uuid.UUID | None = None, limit: int = 50, offset: int = 0) -> Sequence[FlowRow]:
        q = select(FlowRow).order_by(FlowRow.created_at.desc()).limit(limit).offset(offset)
        if user_id:
            q = q.where(FlowRow.user_id == user_id)
        result = await self.s.execute(q)
        return result.scalars().all()

    async def update_flow(self, flow_id: uuid.UUID, **kwargs: Any) -> None:
        kwargs["updated_at"] = datetime.now(timezone.utc)
        await self.s.execute(update(FlowRow).where(FlowRow.id == flow_id).values(**kwargs))

    # ── Tasks ───────────────────────────────────────────────────────────
    async def create_task(self, flow_id: uuid.UUID, name: str, description: str = "", agent_role: str = "orchestrator") -> TaskRow:
        task = TaskRow(flow_id=flow_id, name=name, description=description, agent_role=agent_role)
        self.s.add(task)
        await self.s.flush()
        return task

    async def update_task(self, task_id: uuid.UUID, **kwargs: Any) -> None:
        kwargs["updated_at"] = datetime.now(timezone.utc)
        await self.s.execute(update(TaskRow).where(TaskRow.id == task_id).values(**kwargs))

    # ── SubTasks ────────────────────────────────────────────────────────
    async def create_subtask(self, task_id: uuid.UUID, name: str, description: str = "", agent_role: str = "orchestrator") -> SubTaskRow:
        subtask = SubTaskRow(task_id=task_id, name=name, description=description, agent_role=agent_role)
        self.s.add(subtask)
        await self.s.flush()
        return subtask

    async def update_subtask(self, subtask_id: uuid.UUID, **kwargs: Any) -> None:
        kwargs["updated_at"] = datetime.now(timezone.utc)
        await self.s.execute(update(SubTaskRow).where(SubTaskRow.id == subtask_id).values(**kwargs))

    # ── Actions ─────────────────────────────────────────────────────────
    async def create_action(
        self, subtask_id: uuid.UUID, action_type: str, agent_role: str = "orchestrator",
        tool_name: str = "", tool_input: dict | None = None, tool_output: str = "", thought: str = "",
    ) -> ActionRow:
        action = ActionRow(
            subtask_id=subtask_id, action_type=action_type, agent_role=agent_role,
            tool_name=tool_name, tool_input=tool_input or {}, tool_output=tool_output, thought=thought,
        )
        self.s.add(action)
        await self.s.flush()
        return action

    # ── Tool Results ────────────────────────────────────────────────────
    async def create_tool_result(
        self, flow_id: uuid.UUID, tool_name: str, success: bool,
        raw_output: str = "", data: dict | None = None, duration_seconds: float = 0.0, error: str = "",
    ) -> ToolResultRow:
        tr = ToolResultRow(
            flow_id=flow_id, tool_name=tool_name, success=success,
            raw_output=raw_output, data=data or {}, duration_seconds=duration_seconds, error=error,
        )
        self.s.add(tr)
        await self.s.flush()
        return tr

    # ── Vulnerabilities ─────────────────────────────────────────────────
    async def create_vulnerability(
        self, flow_id: uuid.UUID, title: str, severity: str, tool: str = "",
        description: str = "", evidence: str = "", cwe_id: str = "",
        cvss_score: float = 0.0, cvss_vector: str = "", remediation: str = "",
    ) -> VulnerabilityRow:
        vuln = VulnerabilityRow(
            flow_id=flow_id, title=title, severity=severity, tool=tool,
            description=description, evidence=evidence, cwe_id=cwe_id,
            cvss_score=cvss_score, cvss_vector=cvss_vector, remediation=remediation,
        )
        self.s.add(vuln)
        await self.s.flush()
        return vuln

    async def list_vulnerabilities(self, flow_id: uuid.UUID) -> Sequence[VulnerabilityRow]:
        result = await self.s.execute(
            select(VulnerabilityRow).where(VulnerabilityRow.flow_id == flow_id).order_by(VulnerabilityRow.created_at)
        )
        return result.scalars().all()
