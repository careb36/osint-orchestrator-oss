"""
Ollama LLM provider.

Uses httpx against {llm_base_url}/api/chat with stream: false.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Literal

import httpx

from orchestrator.config import settings
from orchestrator.synthesizer.providers._policy import status_label
from orchestrator.synthesizer.providers._telemetry import record_request

logger = logging.getLogger(__name__)

_PROVIDER = "ollama"


def _count(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


class OllamaClient:
    """Calls the Ollama /api/chat endpoint asynchronously (stream: false)."""

    provider = _PROVIDER

    @staticmethod
    def model_for_route(route: Literal["reasoning", "fast"]) -> str:
        """Ollama always serves OLLAMA_MODEL: cloud model names 404 on a local server."""
        _ = route
        return settings.ollama_model

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
        _ = response_schema  # Ollama's JSON mode is requested through "format" below
        model = self.model_for_route(model_route)
        url = f"{settings.llm_base_url}/api/chat"
        payload = {
            "model": model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "num_predict": settings.llm_max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
            content = str(data["message"]["content"])
            # Counts are informational: a non-numeric value from another
            # Ollama-compatible server must not fail a completed request.
            in_tokens = _count(data.get("prompt_eval_count"))
            out_tokens = _count(data.get("eval_count"))
        except Exception as exc:  # noqa: BLE001
            status = status_label(
                exc,
                timeout_types=(httpx.TimeoutException,),
                status_code=(
                    exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                ),
            )
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
        return content
