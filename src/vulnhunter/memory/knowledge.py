"""Knowledge manager — high-level API for storing and recalling scan knowledge."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from vulnhunter.config import AIConfig, MemoryConfig
from vulnhunter.memory.embeddings import EmbeddingProvider
from vulnhunter.memory.store import MemoryStore
from vulnhunter.models import ScanReport, Vulnerability

logger = logging.getLogger("vulnhunter.memory")


class KnowledgeManager:
    """Bridges scan results → embeddings → pgvector storage, and provides
    a recall API so agents can query past findings."""

    def __init__(
        self,
        store: MemoryStore,
        ai_config: AIConfig,
        memory_config: MemoryConfig,
    ):
        self.store = store
        self.embedder = EmbeddingProvider(ai_config, memory_config)
        self.top_k = memory_config.top_k

    async def ingest_report(self, report: ScanReport, scan_id: uuid.UUID | None = None) -> int:
        """Break a finished report into chunks and store each with an embedding."""
        chunks = self._report_to_chunks(report)
        count = 0
        for chunk_text, category in chunks:
            try:
                vec = await self.embedder.embed(chunk_text)
                await self.store.add(
                    content=chunk_text,
                    embedding=vec,
                    category=category,
                    source_scan_id=scan_id,
                )
                count += 1
            except Exception as e:
                logger.warning(f"Failed to store chunk: {e}")
        logger.info(f"Ingested {count} memory chunks from scan")
        return count

    async def recall(self, query: str, category: str | None = None) -> str:
        """Semantic search over past knowledge. Returns a formatted context block."""
        vec = await self.embedder.embed(query)
        results = await self.store.search(vec, top_k=self.top_k, category=category)
        if not results:
            return ""

        lines = ["## Relevant past knowledge\n"]
        for r in results:
            sim = r["similarity"]
            lines.append(f"[similarity={sim:.2f}] {r['content'][:500]}\n")
        return "\n".join(lines)

    @staticmethod
    def _report_to_chunks(report: ScanReport) -> list[tuple[str, str]]:
        """Split a ScanReport into (text, category) tuples for embedding."""
        chunks: list[tuple[str, str]] = []

        if report.ai_summary:
            chunks.append((
                f"Scan of {report.target.host}: {report.ai_summary[:1500]}",
                "summary",
            ))

        for v in report.vulnerabilities:
            text = (
                f"Vulnerability on {report.target.host}: [{v.severity.value.upper()}] "
                f"{v.title} — {v.description[:500]}"
            )
            if v.remediation:
                text += f" | Remediation: {v.remediation[:300]}"
            chunks.append((text, "vulnerability"))

        for tr in report.tool_results:
            if tr.success and tr.raw_output:
                chunks.append((
                    f"Tool '{tr.tool_name}' on {report.target.host}: {tr.raw_output[:800]}",
                    "tool_result",
                ))

        return chunks
