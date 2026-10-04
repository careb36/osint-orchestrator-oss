"""Model routing helpers for reasoning vs fast LLM workloads."""

from __future__ import annotations

from typing import Literal, get_args

from orchestrator.config import settings

ModelRoute = Literal["reasoning", "fast"]
MODEL_ROUTES: frozenset[str] = frozenset(get_args(ModelRoute))


def resolve_model_for_route(route: ModelRoute) -> str:
    """Return the configured model for the requested workload route.

    ``Literal`` is erased at runtime, so an unknown route is rejected here
    instead of silently falling back to ``LLM_MODEL`` while the caller records
    the route it asked for.
    """
    if route not in MODEL_ROUTES:
        raise ValueError(f"unknown model route {route!r}; expected one of {sorted(MODEL_ROUTES)}")
    if route == "fast" and settings.llm_model_fast:
        return settings.llm_model_fast
    if route == "reasoning" and settings.llm_model_reasoning:
        return settings.llm_model_reasoning
    return settings.llm_model
