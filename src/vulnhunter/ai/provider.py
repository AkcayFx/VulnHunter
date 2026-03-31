"""Multi-LLM provider with function calling support for VulnHunter.

Supports: DeepSeek, OpenAI, Anthropic (via OpenAI compat), Gemini, Ollama, OpenRouter, Groq.
All providers use OpenAI-compatible chat completions API.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from vulnhunter.config import AIConfig

logger = logging.getLogger("vulnhunter.ai")


class LLMProvider:
    """Handles communication with any OpenAI-compatible LLM API."""

    def __init__(self, config: AIConfig):
        self.config = config
        self.client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
            timeout=120.0,
            max_retries=2,
        )
        logger.info(f"LLM provider: {config.provider} | model: {config.model} | url: {config.base_url}")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict = "auto",
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        try:
            response = await self.client.chat.completions.create(**kwargs)
        except Exception as e:
            logger.error(f"LLM API error ({self.config.provider}): {e}")
            raise

        choice = response.choices[0]
        result: dict[str, Any] = {
            "content": choice.message.content or "",
            "tool_calls": [],
            "finish_reason": choice.finish_reason,
        }

        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                result["tool_calls"].append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args,
                })

        return result

    async def simple_chat(self, system_prompt: str, user_message: str) -> str:
        result = await self.chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ]
        )
        return result["content"]
