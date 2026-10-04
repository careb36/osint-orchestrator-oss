"""
Ollama LLM provider.

Uses httpx against {llm_base_url}/api/chat with stream: false.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx

from orchestrator.config import settings


class OllamaClient:
    """Calls the Ollama /api/chat endpoint asynchronously (stream: false)."""

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        """One non-streaming /api/chat completion in JSON mode; returns the raw text."""
        _ = model_route
        _ = response_schema
        url = f"{settings.llm_base_url}/api/chat"
        payload = {
            "model": settings.ollama_model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "num_predict": settings.llm_max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
        return str(data["message"]["content"])
