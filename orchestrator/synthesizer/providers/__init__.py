"""
LLM provider abstraction for the synthesizer.

Protocol
--------
    LLMClient.complete(system, user, *, timeout, model_route, response_schema) -> str
    LLMClient.model_for_route(route) -> str   (the model a route is actually sent to)
    LLMClient.provider -> str                 (name recorded on findings and metrics)

Factory
-------
    get_client(target) -> LLMClient | None

Rules
-----
The provider is the target's choice. ``Target.llm`` is a closed literal that
defaults to "local", so ``settings.llm_provider`` never picks a provider for a
target that did not name one: a target's prompts reach a cloud LLM provider
only when it opts in. "local" means the Ollama server at LLM_BASE_URL, which
the operator may host anywhere.

- settings.llm_provider == "none"      → no client at all: synthesis is off for every
                                          target, and a per-target `llm` cannot re-enable it.
- target.llm == "local" (the default)  → always OllamaClient, regardless of global setting.
- target.llm == "anthropic"             → Anthropic provider.
- target.llm == "openai"                → OpenAI-compatible family; if LLM_PROVIDER=nebius,
                                          routes to Nebius, else to OpenAI.
- target.llm == "nebius"                → Nebius OpenAI-compatible provider.
- Returns None and logs a warning if the chosen remote provider has no API key.
- The branches are exhaustive over ``Target.llm``; ``assert_never`` makes mypy
  reject a new value that ``get_client`` does not handle.
"""

from __future__ import annotations

import logging
from typing import Any, Literal, Protocol, assert_never, runtime_checkable

from orchestrator.config import NEBIUS_DEFAULT_BASE_URL, settings
from orchestrator.models import Target

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal contract satisfied by all provider implementations."""

    @property
    def provider(self) -> str:
        """Provider name as recorded on findings and in the ``provider`` metric label."""
        ...

    def model_for_route(self, route: Literal["reasoning", "fast"]) -> str:
        """Return the model a request on *route* is sent to, so callers persist the truth."""
        ...

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

    The provider is ``target.llm``. ``settings.llm_provider`` only switches
    synthesis off (``none``) or sends ``llm: openai`` targets to the Nebius
    preset (``nebius``); it is never a fallback provider. Returns None (with a
    warning) when the chosen cloud provider has no API key. Never raises for a
    validated Target: the closing ``assert_never`` is only reachable with a
    value that bypassed validation, and then it fails closed instead of
    sending the prompts anywhere.
    """
    if settings.llm_provider == "none":
        return None

    llm = target.llm
    if llm == "local":
        # Hard rule: local targets always use Ollama.
        from orchestrator.synthesizer.providers.ollama import OllamaClient

        return OllamaClient()

    if llm == "anthropic":
        if not settings.anthropic_api_key:
            logger.warning(
                "LLM provider 'anthropic' requires ANTHROPIC_API_KEY — synthesis skipped"
            )
            return None
        from orchestrator.synthesizer.providers.anthropic import AnthropicClient

        return AnthropicClient()

    # `llm: openai` means "OpenAI-compatible API family", so under
    # LLM_PROVIDER=nebius that target goes to the Nebius preset below.
    if llm == "openai" and settings.llm_provider != "nebius":
        if not settings.openai_api_key:
            logger.warning("LLM provider 'openai' requires OPENAI_API_KEY — synthesis skipped")
            return None
        from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

        return OpenAICompatClient()

    if llm == "nebius" or llm == "openai":
        if not settings.nebius_api_key:
            logger.warning("LLM provider 'nebius' requires NEBIUS_API_KEY — synthesis skipped")
            return None
        from orchestrator.synthesizer.providers.openai_compat import OpenAICompatClient

        return OpenAICompatClient(
            provider_name="nebius",
            api_key=settings.nebius_api_key,
            # A blanked NEBIUS_BASE_URL must not fall through to api.openai.com.
            base_url=settings.nebius_base_url.strip() or NEBIUS_DEFAULT_BASE_URL,
        )

    assert_never(llm)
