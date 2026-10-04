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
- target.llm == "anthropic"             → Anthropic provider.
- target.llm == "openai"                → OpenAI-compatible family; if LLM_PROVIDER=nebius,
                                          routes to Nebius, else to OpenAI.
- otherwise settings.llm_provider decides: "anthropic" / "openai" / "nebius"
                                          (require an API key) or Ollama as the default.
- Returns None and logs a warning if the chosen remote provider has no API key.
"""

from __future__ import annotations

import logging
from typing import Any, Literal, Protocol, runtime_checkable

from orchestrator.config import settings
from orchestrator.models import Target

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal contract satisfied by all provider implementations."""

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
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

    # Per-target override first (Target.llm is validated), then the global
    # setting. `llm: openai` means "OpenAI-compatible API family", so when the
    # global provider is set to nebius we route that target to the Nebius preset.
    if target.llm == "anthropic":
        provider = "anthropic"
    elif target.llm == "openai":
        provider = "nebius" if settings.llm_provider == "nebius" else "openai"
    else:
        provider = settings.llm_provider
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

    if provider == "nebius":
        if not settings.nebius_api_key:
            logger.warning("LLM provider 'nebius' requires NEBIUS_API_KEY — synthesis skipped")
            return None
        from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

        return OpenAICompatClient(
            provider_name="nebius",
            api_key=settings.nebius_api_key,
            base_url=settings.nebius_base_url,
        )

    # Default: Ollama
    from orchestrator.synthesizer.providers.ollama import OllamaClient

    return OllamaClient()
