"""
Anthropic LLM provider (optional extra).

Install: pip install anthropic
"""

from __future__ import annotations

import logging

from orchestrator.config import settings

logger = logging.getLogger(__name__)

try:
    import anthropic as _anthropic_sdk

    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False


class AnthropicClient:
    """Calls the Anthropic Messages API using the official SDK."""

    async def complete(self, system: str, user: str, *, timeout: float) -> str:
        """One Messages-API completion (temperature 0); returns the raw text."""
        if not _HAS_ANTHROPIC:
            raise RuntimeError("anthropic package is not installed; run: pip install anthropic")
        client = _anthropic_sdk.AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            # The SDK default is 2 retries × timeout; see config.llm_max_tokens.
            max_retries=1,
        )
        response = await client.messages.create(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": user}],
            timeout=timeout,
        )
        return str(response.content[0].text)  # type: ignore[union-attr]
