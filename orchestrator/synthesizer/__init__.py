"""
Synthesizer — Phase 3.

Produces a structured Finding by:
  1. Fetching the current run's observables from RunReportData.
  2. Querying the last N run_observables for historical deltas.
  3. Selecting the appropriate LLM client (Ollama / Anthropic / OpenAI).
  4. Building system + user prompts (stored in prompts/*.txt for readability).
  5. Calling the LLM; retrying once with a repair prompt on JSON parse errors.
  6. Persisting a FindingRecord for audit and the GET /runs/{id}/finding API.

Privacy: prompt content and raw responses are never logged at INFO level;
only byte-lengths are logged at DEBUG.

Error handling: no exception from the LLM ever crashes the calling pipeline.
  - If the provider is unavailable (no key, Ollama unreachable):
      returns None and logs a warning (run continues, report is generated).
  - If the LLM call times out / errors:
      annotates Run.error, returns None (report generated without synthesis).
  - If JSON parsing fails twice:
      returns Finding(risk_level="unknown") with a descriptive summary.

LLM selection:
  target.llm == "local"  → always OllamaClient (regardless of global setting).
  settings.llm_provider   → OllamaClient | AnthropicClient | OpenAICompatClient (OpenAI/Nebius).
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError, field_validator
from sqlmodel import col, select

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.demo import consume_budget
from orchestrator.i18n import resolve_language, t
from orchestrator.models import Finding, FindingRecord, Run, RunObservable, RunStatus, Target
from orchestrator.reports import CollectorReportResult, ReportObservable, RunReportData
from orchestrator.synthesizer.providers import LLMClient
from orchestrator.textsafe import flatten_untrusted, neutralise_markdown

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_SYSTEM_PROMPT = (_PROMPTS_DIR / "system.txt").read_text(encoding="utf-8")
_USER_PROMPT_TEMPLATE = (_PROMPTS_DIR / "user.txt").read_text(encoding="utf-8")

# Valid English identifiers for risk_level.
_RISK_LEVELS = frozenset({"low", "medium", "high", "critical", "unknown"})


# ─── Internal pydantic model for LLM output validation ───────────────────────


# Bounds on what a model reply may put into a report: a model that answers
# with a novel, or with a thousand "pivots", is a broken model, not a finding.
_MAX_SUMMARY_CHARS = 4000
_MAX_JUSTIFICATION_CHARS = 2000
_MAX_LIST_ITEMS = 50
_MAX_ITEM_CHARS = 500


def _clean_text(value: object, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError("expected a string")
    # Neutralised once, here, so every consumer — report, PDF, alert body,
    # API, console — gets text that cannot link, embed or restructure.
    return neutralise_markdown(value.strip())[:limit]


def _clean_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("expected a list of strings")
    items = [_clean_text(v, _MAX_ITEM_CHARS) for v in value if isinstance(v, str) and v.strip()]
    return items[:_MAX_LIST_ITEMS]


class _FindingOutput(BaseModel):
    """Validation schema for the JSON object the LLM must return.

    Unknown ``risk_level`` values coerce to ``unknown`` rather than raising:
    a hallucinated label degrades the finding, it never fails the run.
    """

    summary: str
    new_since_last_run: list[str] = []
    risk_level: str = "unknown"
    risk_justification: str = ""
    suggested_pivots: list[str] = []

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, v: object) -> str:
        text = _clean_text(v, _MAX_SUMMARY_CHARS)
        if not text:
            raise ValueError("summary is empty")
        return text

    @field_validator("risk_justification", mode="before")
    @classmethod
    def _justification(cls, v: object) -> str:
        return _clean_text(v if v is not None else "", _MAX_JUSTIFICATION_CHARS)

    @field_validator("new_since_last_run", "suggested_pivots", mode="before")
    @classmethod
    def _lists(cls, v: object) -> list[str]:
        return _clean_list(v)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _coerce_risk_level(cls, v: object) -> str:
        s = str(v).strip().lower()
        return s if s in _RISK_LEVELS else "unknown"


_FINDING_JSON_SCHEMA = _FindingOutput.model_json_schema()


async def _complete_with_optional_schema(
    client: LLMClient,
    system: str,
    user: str,
    *,
    timeout: float,
    model_route: Literal["reasoning", "fast"],
    response_schema: dict[str, Any] | None,
) -> str:
    return await client.complete(
        system,
        user,
        timeout=timeout,
        model_route=model_route,
        response_schema=response_schema,
    )


# ─── Prompt building ──────────────────────────────────────────────────────────


def _collector_status_lines(results: list[CollectorReportResult]) -> str:
    """Render per-collector ok/error status lines for the LLM prompt."""
    lines = []
    for r in sorted(results, key=lambda x: x.collector):
        status = "ok" if r.success else "error"
        line = f"- {r.collector}: {status} ({r.observable_count} observables)"
        if r.error:
            line += f" — {flatten_untrusted(r.error)}"
        lines.append(line)
    return "\n".join(lines) or "_(none)_"


def _format_observables(items: list[tuple[str, str]]) -> str:
    """Render (stix_type, value) pairs grouped by type for the LLM prompt."""
    if not items:
        return "_(none)_"
    grouped: dict[str, list[str]] = defaultdict(list)
    for stix_type, value in items:
        grouped[stix_type].append(value)
    lines = []
    for stix_type_key in sorted(grouped):
        vals = sorted(flatten_untrusted(v) for v in grouped[stix_type_key])
        lines.append(f"**{stix_type_key}**: " + ", ".join(f"`{v}`" for v in vals))
    return "\n".join(lines)


def _format_relationships(bundles: list[dict[str, Any]]) -> str:
    """Render STIX relationships from all bundles as a sorted bullet list."""
    rels = []
    for b in bundles:
        for obj in b.get("objects", []):
            if isinstance(obj, dict) and obj.get("type") == "relationship":
                rels.append(obj)
    if not rels:
        return "_(none)_"
    lines = [
        f"- `{flatten_untrusted(r.get('relationship_type', ''))}`: "
        f"{flatten_untrusted(r.get('source_ref', ''))} → {flatten_untrusted(r.get('target_ref', ''))}"
        for r in sorted(
            rels,
            key=lambda r: (
                str(r.get("relationship_type", "")),
                str(r.get("source_ref", "")),
            ),
        )
    ]
    return "\n".join(lines)


def _interleave_by_collector(items: list[ReportObservable]) -> list[ReportObservable]:
    """
    Round-robin across collectors, so that when the prompt budget truncates
    the list every source is still represented. In collector order a chatty
    SpiderFoot run (hundreds of DNS records) pushed OpenOSINT's and
    SocialOSINT's findings out of the prompt entirely.
    """
    queues: dict[str, deque[ReportObservable]] = defaultdict(deque)
    for item in items:
        queues[item.collector].append(item)
    order = sorted(queues)
    interleaved: list[ReportObservable] = []
    while any(queues.values()):
        for name in order:
            if queues[name]:
                interleaved.append(queues[name].popleft())
    return interleaved


def _format_qualified_evidence(items: list[dict[str, Any]]) -> str:
    """Render high/medium qualified evidence rows for the synthesis prompt."""
    selected = [
        item for item in items if str(item.get("relevance", "")).lower() in {"high", "medium"}
    ]
    if not selected:
        return "_(none)_"
    lines = []
    for item in sorted(
        selected,
        key=lambda row: (
            0 if str(row.get("relevance", "")).lower() == "high" else 1,
            -float(row.get("confidence", 0.0) or 0.0),
            str(row.get("url", "")),
        ),
    ):
        lines.append(
            "- "
            + " | ".join(
                [
                    f"category={flatten_untrusted(str(item.get('category', '')))}",
                    f"relevance={flatten_untrusted(str(item.get('relevance', '')))}",
                    f"confidence={float(item.get('confidence', 0.0) or 0.0):.2f}",
                    f"title={flatten_untrusted(str(item.get('title', '')))}",
                    f"url={flatten_untrusted(str(item.get('url', '')))}",
                    f"rationale={flatten_untrusted(str(item.get('rationale', '')))}",
                ]
            )
        )
    return "\n".join(lines)


def _build_user_prompt(
    target: Target,
    report_data: RunReportData,
    history: list[tuple[int, list[str]]],
) -> str:
    """
    Build the user-facing prompt by rendering prompts/user.txt.

    At most settings.llm_max_observables_in_prompt observables are shown:
    new ones first, then existing ones with what is left of the budget, each
    group sampled round-robin across collectors. The budget applies to new
    observables too — on a first run everything is new, and "always include
    all new" meant an unbounded prompt exactly when it was largest.
    """
    max_obs = max(0, settings.llm_max_observables_in_prompt)
    lang = resolve_language(target.language)

    new_all = _interleave_by_collector([o for o in report_data.observables if o.is_new])
    existing_all = _interleave_by_collector([o for o in report_data.observables if not o.is_new])
    new_shown = new_all[:max_obs]
    existing_shown = existing_all[: max(0, max_obs - len(new_shown))]

    new_obs = [(o.stix_type, o.value) for o in new_shown]
    shown_obs = new_obs + [(o.stix_type, o.value) for o in existing_shown]
    total_count = len(report_data.observables)
    shown_count = len(shown_obs)

    # History block
    history_lines = []
    for run_id, new_vals in history:
        if new_vals:
            history_lines.append(
                f"Run {run_id}: {len(new_vals)} new — "
                + ", ".join(f"`{flatten_untrusted(v)}`" for v in new_vals[:20])
            )
        else:
            history_lines.append(f"Run {run_id}: no new observables")
    history_str = "\n".join(history_lines) if history_lines else "_(no prior runs)_"

    return _USER_PROMPT_TEMPLATE.format(
        TARGET_FQDN=target.fqdn,
        PURPOSE=target.purpose,
        COLLECTOR_STATUS=_collector_status_lines(report_data.collector_results),
        NEW_COUNT=len(new_all),
        NEW_OBSERVABLES=_format_observables(new_obs),
        SHOWN_COUNT=shown_count,
        TOTAL_COUNT=total_count,
        FULL_INVENTORY=_format_observables(shown_obs),
        RELATIONSHIPS=_format_relationships(report_data.bundles),
        EVIDENCE=_format_qualified_evidence(report_data.evidence),
        HISTORY_COUNT=len(history),
        HISTORY=history_str,
        LANGUAGE=lang,
    )


def _build_repair_prompt(original_user: str, bad_response: str, error: str) -> str:
    """Re-ask the LLM for valid JSON after an unparseable first response."""
    return (
        f"{original_user}\n\n"
        f"---\n"
        f"Your previous response could not be parsed.  Error: {error}\n"
        f"Previous response length: {len(bad_response)} chars.\n"
        f"Please reply ONLY with a valid JSON object matching the required schema.\n"
    )


# ─── JSON extraction and validation ──────────────────────────────────────────


def _extract_and_validate(target_id: str, run_id: int, raw: str) -> tuple[Finding | None, str]:
    """
    Parse *raw* LLM response into a Finding.

    Returns (Finding, "") on success, (None, error_message) on failure.
    """
    try:
        # Try markdown code-fence block first.
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
        if m:
            data = json.loads(m.group(1))
        else:
            # Fall back to the outermost {...} span.
            m2 = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m2:
                return None, "No JSON object found in response"
            data = json.loads(m2.group(0))

        output = _FindingOutput.model_validate(data)
        finding = Finding(
            target_id=target_id,
            run_id=run_id,
            summary=output.summary,
            new_since_last_run=output.new_since_last_run,
            risk_level=output.risk_level,
            risk_justification=output.risk_justification,
            suggested_pivots=output.suggested_pivots,
        )
        return finding, ""
    except (json.JSONDecodeError, ValidationError, KeyError, ValueError) as exc:
        return None, str(exc)


# ─── Database helpers ─────────────────────────────────────────────────────────


async def _fetch_history(target_id: str, current_run_id: int) -> list[tuple[int, list[str]]]:
    """
    Return (run_id, [new_values]) for the last N-1 completed runs before
    *current_run_id*, where N = settings.synthesis_history_runs.

    Only runs that collected something (SUCCESS, PARTIAL) count as history: a
    FAILED run has no observables, so telling the model "run 12: no new
    observables" for it would be wrong, and a PENDING/RUNNING row is not a
    run yet.
    """
    n = max(0, settings.synthesis_history_runs - 1)
    if n == 0:
        return []
    async with get_session() as session:
        # Fetch the N most recent prior run IDs for this target.
        run_stmt = (
            select(Run)
            .where(Run.target_id == target_id)
            .where(Run.id < current_run_id)
            .where(col(Run.status).in_([RunStatus.SUCCESS, RunStatus.PARTIAL]))
            .order_by(Run.id.desc())  # type: ignore[union-attr]
            .limit(n)
        )
        prior_runs = (await session.exec(run_stmt)).all()
        if not prior_runs:
            return []

        prior_run_ids = [r.id for r in prior_runs if r.id is not None]

        history: list[tuple[int, list[str]]] = []
        for rid in sorted(prior_run_ids):
            obs_stmt = (
                select(RunObservable)
                .where(RunObservable.run_id == rid)
                .where(RunObservable.is_new == True)  # noqa: E712
            )
            obs = (await session.exec(obs_stmt)).all()
            history.append((rid, [o.value for o in obs]))
    return history


async def _persist_finding(
    finding: Finding,
    *,
    provider: str,
    model: str,
    duration_ms: int,
    raw_response: str,
) -> None:
    """Persist a synthesized Finding plus its generation metadata (provider,
    model, latency and raw LLM response) as a FindingRecord row."""
    record = FindingRecord(
        run_id=finding.run_id,
        target_id=finding.target_id,
        summary=finding.summary,
        new_since_last_run=json.dumps(finding.new_since_last_run, ensure_ascii=False),
        risk_level=finding.risk_level,
        risk_justification=finding.risk_justification,
        suggested_pivots=json.dumps(finding.suggested_pivots, ensure_ascii=False),
        generated_at=finding.generated_at,
        provider=provider,
        model=model,
        duration_ms=duration_ms,
        raw_response=raw_response,
    )
    async with get_session() as session:
        session.add(record)
        await session.commit()


async def _annotate_run_error(run_id: int, message: str) -> None:
    """Append a synthesis failure note to the Run's error field (never overwrites)."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run:
            run.error = f"{run.error}; {message}" if run.error else message
            session.add(run)
            await session.commit()


# ─── Public API ───────────────────────────────────────────────────────────────


async def synthesize(
    target: Target,
    run_id: int,
    report_data: RunReportData,
) -> tuple[Finding | None, str]:
    """
    Produce a Finding for a completed run.

    Returns ``(finding, status)`` where *status* is one of:

    - ``"ok"``      — finding produced and persisted.
    - ``"skipped"`` — no LLM provider is configured; finding is None.
    - ``"failed"``  — provider configured but the call failed; Run.error
                      is annotated and finding is None.

    Never raises.
    """
    from orchestrator.synthesizer.providers import get_client

    client = get_client(target)
    if client is None:
        return None, "skipped"
    if not await consume_budget("llm"):
        # Public demo only: recorded like a skipped synthesis, with the reason.
        await _annotate_run_error(run_id, "synthesis: the demo's daily LLM budget is exhausted")
        return None, "skipped"

    try:
        # The same name the client puts in the metrics' ``provider`` label, so
        # a finding joins with llm_requests_total (nebius and openai share a
        # module). Inside the try: a client missing the protocol member is a
        # synthesis failure, not an unhandled exception.
        provider_name = client.provider
        history = await _fetch_history(target.id, run_id)
        user_prompt = _build_user_prompt(target, report_data, history)

        logger.debug(
            "Synthesis start: run=%d system_prompt_len=%d user_prompt_len=%d",
            run_id,
            len(_SYSTEM_PROMPT),
            len(user_prompt),
        )

        t0 = time.monotonic()
        raw = await _complete_with_optional_schema(
            client,
            _SYSTEM_PROMPT,
            user_prompt,
            timeout=settings.llm_timeout_seconds,
            model_route="reasoning",
            response_schema=_FINDING_JSON_SCHEMA,
        )
        duration_ms = int((time.monotonic() - t0) * 1000)

        logger.debug(
            "Synthesis raw response: run=%d response_len=%d duration_ms=%d",
            run_id,
            len(raw),
            duration_ms,
        )

        finding, error = _extract_and_validate(target.id, run_id, raw)

        if finding is None:
            # One retry with a repair prompt.
            logger.warning("Synthesis JSON parse failed (run=%d): %s — retrying", run_id, error)
            repair_prompt = _build_repair_prompt(user_prompt, raw, error)
            raw2 = await _complete_with_optional_schema(
                client,
                _SYSTEM_PROMPT,
                repair_prompt,
                timeout=settings.llm_timeout_seconds,
                model_route="reasoning",
                response_schema=_FINDING_JSON_SCHEMA,
            )
            duration_ms = int((time.monotonic() - t0) * 1000)
            # Regardless of whether the retry parses, use raw2 as the auditable response.
            raw = raw2
            finding, error2 = _extract_and_validate(target.id, run_id, raw2)

            if finding is None:
                logger.warning(
                    "Synthesis retry also failed (run=%d): %s — returning unknown finding",
                    run_id,
                    error2,
                )
                finding = Finding(
                    target_id=target.id,
                    run_id=run_id,
                    summary=t("synthesis_failed", language=target.language, error=error2),
                    risk_level="unknown",
                )

        await _persist_finding(
            finding,
            provider=provider_name,
            # The model the client really sent the request to: Ollama ignores
            # the route and serves OLLAMA_MODEL, so resolving it here would
            # record a model that was never used.
            model=client.model_for_route("reasoning"),
            duration_ms=duration_ms,
            raw_response=raw,
        )
        return finding, "ok"

    except Exception as exc:  # noqa: BLE001
        logger.exception("LLM synthesis error for run %d: %s", run_id, exc)
        await _annotate_run_error(run_id, f"synthesis: {exc}")
        return None, "failed"
