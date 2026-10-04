"""
OpenAI-compatible LLM provider (optional extra).

Works with the official OpenAI API, Azure OpenAI, or any local server that
speaks the OpenAI chat-completions protocol (e.g. LM Studio, vLLM).

Install: pip install openai
Config:  OPENAI_API_KEY, optionally OPENAI_BASE_URL for compatible endpoints.
"""

from __future__ import annotations

import logging

from orchestrator.config import settings

logger = logging.getLogger(__name__)

try:
    import openai as _openai_sdk

    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False


class OpenAICompatClient:
    """Calls any OpenAI-compatible /v1/chat/completions endpoint."""

    async def complete(self, system: str, user: str, *, timeout: float) -> str:
        """One /v1/chat/completions call (temperature 0); returns the raw text."""
        if not _HAS_OPENAI:
            raise RuntimeError("openai package is not installed; run: pip install openai")
        client = _openai_sdk.AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url or None,
            timeout=timeout,
            max_retries=1,  # SDK default is 2; see config.llm_max_tokens
        )
        response = await client.chat.completions.create(
            model=settings.llm_model,
            temperature=0,
            max_tokens=settings.llm_max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return str(response.choices[0].message.content or "")
