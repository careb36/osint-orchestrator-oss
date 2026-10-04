"""
LLM provider abstraction for the synthesizer.

Protocol
--------
    LLMClient.complete(system, user, *, timeout) -> str

Factory
-------
    get_client(target) -> LLMClient | None

Rules
-----
- settings.llm_provider == "none"      → no client at all: synthesis is off for every
                                          target, and a per-target `llm` cannot re-enable it.
- target.llm == "local"                → always OllamaClient, regardless of global setting.
- target.llm in {"anthropic", "openai"} → that provider (targets.yaml documents `llm`
                                          as an override of LLM_PROVIDER, so it must be one).
- otherwise settings.llm_provider decides: "anthropic" / "openai" (require an API key)
                                          or Ollama as the default.
- Returns None and logs a warning if the chosen remote provider has no API key.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from orchestrator.config import settings
from orchestrator.models import Target

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal contract satisfied by all provider implementations."""

    async def complete(self, system: str, user: str, *, timeout: float) -> str:
        """Send a chat completion request and return the assistant's response."""
        ...


def get_client(target: Target) -> LLMClient | None:
    """
    Return the LLM client to use for *target*.

    Returns None (with a warning) when the configured provider cannot be used
    because no API key is present.  Never raises.
    """
    if settings.llm_provider == "none":
        return None

    if target.llm == "local":
        # Hard rule: local targets always use Ollama.
        from orchestrator.synthesizer.providers.ollama import OllamaClient

        return OllamaClient()

    # Per-target override first (Target.llm is validated to this enum), then the
    # global setting. Previously only "local" was honoured and `llm: anthropic`
    # on a target silently used whatever the global provider was.
    provider = target.llm if target.llm in ("anthropic", "openai") else settings.llm_provider
    if provider == "anthropic":
        if not settings.anthropic_api_key:
            logger.warning(
                "LLM provider 'anthropic' requires ANTHROPIC_API_KEY — synthesis skipped"
            )
            return None
        from orchestrator.synthesizer.providers.anthropic import AnthropicClient

        return AnthropicClient()

    if provider == "openai":
        if not settings.openai_api_key:
            logger.warning("LLM provider 'openai' requires OPENAI_API_KEY — synthesis skipped")
            return None
        from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

        return OpenAICompatClient()

    # Default: Ollama
    from orchestrator.synthesizer.providers.ollama import OllamaClient

    return OllamaClient()
