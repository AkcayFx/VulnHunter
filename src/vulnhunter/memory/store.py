"""Vector memory store backed by pgvector."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, DateTime, String, Text, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from vulnhunter.db.models import Base

logger = logging.getLogger("vulnhunter.memory")

try:
    from pgvector.sqlalchemy import Vector

    _HAS_PGVECTOR = True
except ImportError:
    _HAS_PGVECTOR = False
    Vector = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> uuid.UUID:
    return uuid.uuid4()


if _HAS_PGVECTOR:

    class MemoryRow(Base):
        __tablename__ = "memories"

        id = Column(PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid)
        content = Column(Text, nullable=False)
        category = Column(String(64), nullable=False, default="general")
        source_scan_id = Column(PG_UUID(as_uuid=True), nullable=True)
        embedding = Column(Vector(1536), nullable=True)
        created_at = Column(DateTime(timezone=True), default=_utcnow)

else:

    class MemoryRow(Base):  # type: ignore[no-redef]
        __tablename__ = "memories"

        id = Column(PG_UUID(as_uuid=True), primary_key=True, default=_new_uuid)
        content = Column(Text, nullable=False)
        category = Column(String(64), nullable=False, default="general")
        source_scan_id = Column(PG_UUID(as_uuid=True), nullable=True)
        created_at = Column(DateTime(timezone=True), default=_utcnow)


class MemoryStore:
    """CRUD and vector-similarity queries on the memories table."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def add(
        self,
        content: str,
        embedding: list[float] | None = None,
        category: str = "general",
        source_scan_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        row = MemoryRow(
            content=content,
            category=category,
            source_scan_id=source_scan_id,
        )
        if _HAS_PGVECTOR and embedding is not None:
            row.embedding = embedding  # type: ignore[assignment]
        self.session.add(row)
        await self.session.flush()
        return row.id  # type: ignore[return-value]

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the top-k most similar memories using cosine distance."""
        if not _HAS_PGVECTOR:
            logger.warning("pgvector not available — returning empty results")
            return []

        vec_literal = "[" + ",".join(str(v) for v in query_embedding) + "]"
        cat_filter = f"AND category = '{category}'" if category else ""

        sql = text(f"""
            SELECT id, content, category,
                   1 - (embedding <=> :vec ::vector) AS similarity
            FROM memories
            WHERE embedding IS NOT NULL {cat_filter}
            ORDER BY embedding <=> :vec ::vector
            LIMIT :k
        """)
        result = await self.session.execute(sql, {"vec": vec_literal, "k": top_k})
        rows = result.fetchall()
        return [
            {
                "id": str(r.id),
                "content": r.content,
                "category": r.category,
                "similarity": float(r.similarity),
            }
            for r in rows
        ]

    async def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        sql = text("SELECT id, content, category, created_at FROM memories ORDER BY created_at DESC LIMIT :lim")
        result = await self.session.execute(sql, {"lim": limit})
        return [
            {"id": str(r.id), "content": r.content, "category": r.category}
            for r in result.fetchall()
        ]
