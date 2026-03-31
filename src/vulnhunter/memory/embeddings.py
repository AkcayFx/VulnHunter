"""Embedding provider — generates vector embeddings via the OpenRouter / OpenAI API."""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import aiohttp

from vulnhunter.config import AIConfig, MemoryConfig

logger = logging.getLogger("vulnhunter.memory")

_CACHE: dict[str, list[float]] = {}


class EmbeddingProvider:
    """Generates text embeddings via an OpenAI-compatible embeddings endpoint."""

    def __init__(self, ai_config: AIConfig, memory_config: MemoryConfig):
        self.api_key = ai_config.api_key
        self.base_url = ai_config.base_url.rstrip("/")
        self.model = memory_config.embedding_model

    async def embed(self, text: str) -> list[float]:
        """Return an embedding vector for *text*. Results are cached in-memory."""
        cache_key = hashlib.md5(f"{self.model}:{text}".encode()).hexdigest()
        if cache_key in _CACHE:
            return _CACHE[cache_key]

        url = f"{self.base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "input": text}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(f"Embedding API error {resp.status}: {body[:200]}")
                    return self._fallback_embed(text)
                data: dict[str, Any] = await resp.json()

        vector: list[float] = data["data"][0]["embedding"]
        _CACHE[cache_key] = vector
        return vector

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts. Falls back to individual calls on failure."""
        url = f"{self.base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "input": texts}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [item["embedding"] for item in data["data"]]
        except Exception as e:
            logger.warning(f"Batch embedding failed: {e}")

        results = []
        for t in texts:
            results.append(await self.embed(t))
        return results

    @staticmethod
    def _fallback_embed(text: str, dim: int = 256) -> list[float]:
        """Deterministic hash-based fallback when the API is unavailable."""
        digest = hashlib.sha256(text.encode()).digest()
        import struct
        vec: list[float] = []
        for i in range(dim):
            byte_pair = digest[(i * 2) % len(digest)] ^ digest[(i * 2 + 1) % len(digest)]
            vec.append((byte_pair / 255.0) * 2 - 1)
        return vec
