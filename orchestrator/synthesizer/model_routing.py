"""Model routing helpers for reasoning vs fast LLM workloads."""

from __future__ import annotations

from typing import Literal

from orchestrator.config import settings


def resolve_model_for_route(route: Literal["reasoning", "fast"]) -> str:
    """Return the configured model for the requested workload route."""
    if route == "fast" and settings.llm_model_fast:
        return settings.llm_model_fast
    if route == "reasoning" and settings.llm_model_reasoning:
        return settings.llm_model_reasoning
    return settings.llm_model
