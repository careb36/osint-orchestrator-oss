"""
Shared request telemetry for the LLM providers.

Every provider records each completion in ``llm_requests_total`` and
``llm_tokens_total`` with the same ``provider`` / ``model`` labels, so an
operator sees the counters move whichever provider is configured and the
``model`` label never collides across providers. One sample is one SDK
completion call: the Anthropic SDK's internal retry is not visible here.
"""

from __future__ import annotations

from orchestrator import metrics


def record_request(
    provider: str, model: str, status: str, *, in_tokens: int = 0, out_tokens: int = 0
) -> None:
    """Count one request outcome and, on success, its token usage."""
    metrics.llm_requests_total.labels(provider, model, status).inc()
    if in_tokens:
        metrics.llm_tokens_total.labels(provider, model, "input").inc(in_tokens)
    if out_tokens:
        metrics.llm_tokens_total.labels(provider, model, "output").inc(out_tokens)
