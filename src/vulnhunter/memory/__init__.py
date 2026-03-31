"""Memory and knowledge system for VulnHunter — pgvector-backed semantic recall."""

__all__ = ["EmbeddingProvider", "MemoryStore", "KnowledgeManager"]


def __getattr__(name: str):
    if name == "EmbeddingProvider":
        from vulnhunter.memory.embeddings import EmbeddingProvider
        return EmbeddingProvider
    if name == "MemoryStore":
        from vulnhunter.memory.store import MemoryStore
        return MemoryStore
    if name == "KnowledgeManager":
        from vulnhunter.memory.knowledge import KnowledgeManager
        return KnowledgeManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
