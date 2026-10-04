"""
Anthropic LLM provider (optional extra).

Install: pip install anthropic
"""

from __future__ import annotations

import logging
import time
from typing import Any, Literal

from orchestrator.config import settings
from orchestrator.synthesizer.model_routing import resolve_model_for_route
from orchestrator.synthesizer.providers._telemetry import record_request, status_label

logger = logging.getLogger(__name__)

try:
    import anthropic as _anthropic_sdk

    _HAS_ANTHROPIC = True
except ImportError:
    _anthropic_sdk = None
    _HAS_ANTHROPIC = False

_PROVIDER = "anthropic"


def _timeout_types() -> tuple[type[BaseException], ...]:
    cls = getattr(_anthropic_sdk, "APITimeoutError", None)
    return (cls,) if cls is not None else ()


class AnthropicClient:
    """Calls the Anthropic Messages API using the official SDK."""

    @staticmethod
    def model_for_route(route: Literal["reasoning", "fast"]) -> str:
        """The model a request on *route* is sent to (persisted with the finding)."""
        return resolve_model_for_route(route)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        """One Messages-API completion (temperature 0); returns the raw text."""
        _ = response_schema  # the Messages API has no response_format; the parser is tolerant
        if not _HAS_ANTHROPIC:
            raise RuntimeError("anthropic package is not installed; run: pip install anthropic")
        model = self.model_for_route(model_route)
        client = _anthropic_sdk.AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            # The SDK default is 2 retries × timeout; see config.llm_max_tokens.
            max_retries=1,
        )
        started = time.monotonic()
        try:
            response = await client.messages.create(
                model=model,
                max_tokens=settings.llm_max_tokens,
                temperature=0,
                system=system,
                messages=[{"role": "user", "content": user}],
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            status = status_label(exc, timeout_types=_timeout_types())
            logger.warning(
                "LLM request failed: provider=%s model=%s status=%s",
                _PROVIDER,
                model,
                status,
                extra={
                    "provider": _PROVIDER,
                    "model": model,
                    "status": status,
                    "latency_ms": int((time.monotonic() - started) * 1000),
                },
            )
            record_request(_PROVIDER, model, status)
            raise
        usage = getattr(response, "usage", None)
        in_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        out_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        logger.info(
            "LLM request completed: provider=%s model=%s status=ok",
            _PROVIDER,
            model,
            extra={
                "provider": _PROVIDER,
                "model": model,
                "status": "ok",
                "latency_ms": int((time.monotonic() - started) * 1000),
                "input_tokens": in_tokens,
                "output_tokens": out_tokens,
            },
        )
        record_request(_PROVIDER, model, "ok", in_tokens=in_tokens, out_tokens=out_tokens)
        return str(response.content[0].text)  # type: ignore[union-attr]
