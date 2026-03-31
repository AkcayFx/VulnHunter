"""Base tool interface for VulnHunter."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from vulnhunter.models import ToolResult, Vulnerability

if TYPE_CHECKING:
    from vulnhunter.sandbox.executor import SandboxedExecutor
    from vulnhunter.scope.manager import ScopeManager
    from vulnhunter.stealth.rate_limiter import AdaptiveRateLimiter


class BaseTool(ABC):
    """Abstract base class for all scanning tools.

    Each tool exposes itself as an OpenAI-compatible function for AI agents to call.
    If a ``sandbox`` executor is injected, subclasses may delegate network calls
    to the Docker container instead of running on the host.
    If a ``scope_manager`` is injected, targets are validated before execution.
    If a ``rate_limiter`` is injected, requests are throttled per-domain.
    """

    sandbox: SandboxedExecutor | None = None
    scope_manager: ScopeManager | None = None
    rate_limiter: AdaptiveRateLimiter | None = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description for the AI agent."""

    @property
    @abstractmethod
    def parameters(self) -> dict[str, Any]:
        """JSON Schema for the tool's parameters (OpenAI function calling format)."""

    @abstractmethod
    async def _execute(self, **kwargs: Any) -> ToolResult:
        """Internal execution logic. Subclasses implement this."""

    def _extract_target(self, kwargs: dict[str, Any]) -> str:
        """Extract target string from tool arguments for scope checking."""
        for key in ("target", "url", "domain", "host", "hostname", "ip"):
            val = kwargs.get(key)
            if val and isinstance(val, str):
                return val
        return ""

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with scope enforcement, timing, and error handling."""
        start = time.monotonic()
        try:
            # Scope enforcement — block out-of-scope targets before execution
            if self.scope_manager is not None:
                target = self._extract_target(kwargs)
                if target:
                    allowed, reason = self.scope_manager.check_target(target)
                    if not allowed:
                        return ToolResult(
                            tool_name=self.name,
                            success=False,
                            error=f"OUT OF SCOPE: {reason}",
                            duration_seconds=time.monotonic() - start,
                        )

            # Rate limiting — throttle requests per-domain
            if self.rate_limiter is not None:
                target = self._extract_target(kwargs)
                if target:
                    from urllib.parse import urlparse
                    domain = urlparse(target).hostname or target
                    await self.rate_limiter.acquire(domain)

            result = await self._execute(**kwargs)
            result.duration_seconds = time.monotonic() - start
            return result
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=str(e),
                duration_seconds=time.monotonic() - start,
            )

    def to_openai_function(self) -> dict[str, Any]:
        """Convert to OpenAI function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }
