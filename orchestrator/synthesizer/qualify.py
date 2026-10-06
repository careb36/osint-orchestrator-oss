"""Evidence qualification on the fast LLM route."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.i18n import resolve_language
from orchestrator.models import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceQualification,
    EvidenceRelevance,
    Run,
    Target,
)
from orchestrator.synthesizer.providers import LLMClient, get_client
from orchestrator.textsafe import flatten_untrusted

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_QUALIFY_SYSTEM_PROMPT = (_PROMPTS_DIR / "qualify_system.txt").read_text(encoding="utf-8")

# Small batches: a long structured answer is the one a model truncates.
_BATCH_SIZE = 5
_MAX_RATIONALE_LEN = 280
_VALID_CATEGORIES = frozenset(item.value for item in EvidenceCategory)
_VALID_RELEVANCE = frozenset(item.value for item in EvidenceRelevance)
_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "category": {"type": "string", "enum": sorted(_VALID_CATEGORIES)},
                    "relevance": {"type": "string", "enum": sorted(_VALID_RELEVANCE)},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "rationale": {"type": "string", "maxLength": _MAX_RATIONALE_LEN},
                },
                "required": ["index", "category", "relevance", "confidence", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}


def _build_user_prompt(target: Target, batch: list[EvidenceItem]) -> str:
    terms = [flatten_untrusted(term) for term in target.collectors.tavily.search_terms]
    entity = ", ".join(f'"{term}"' for term in terms if term) or "(the domain itself)"
    lines = [
        "# Evidence qualification request",
        f"Entity under review: domain {flatten_untrusted(target.fqdn)}; search terms: {entity}",
        f"Language for rationale: {resolve_language(target.language)}",
        "",
        "Classify each item and return only JSON matching the requested schema.",
        "",
        "===== BEGIN UNTRUSTED DATA =====",
    ]
    for index, item in enumerate(batch):
        title = flatten_untrusted(item.title)
        snippet = flatten_untrusted(item.snippet)
        query = flatten_untrusted(item.query)
        published = flatten_untrusted(item.published) if item.published is not None else ""
        url = flatten_untrusted(item.url)
        lines.extend(
            [
                f"- index: {index}",
                f"  title: {title}",
                f"  url: {url}",
                f"  published: {published}",
                f"  query: {query}",
                f"  snippet: {snippet}",
            ]
        )
    lines.append("===== END UNTRUSTED DATA =====")
    return "\n".join(lines)


def _extract_json(raw: str) -> dict[str, Any] | None:
    try:
        block = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw, re.DOTALL)
        if block:
            data = json.loads(block.group(1))
        else:
            outer = re.search(r"\{.*\}", raw, re.DOTALL)
            if not outer:
                return None
            data = json.loads(outer.group(0))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _run_qualifications_query(run_id: int):
    return (
        select(EvidenceQualification)
        .where(EvidenceQualification.run_id == run_id)
        .order_by(EvidenceQualification.url.asc(), EvidenceQualification.id.asc())
    )


def _validated_rows(
    *,
    payload: dict[str, Any],
    batch: list[EvidenceItem],
    run_id: int,
    target_id: str,
    provider: str,
    model: str,
) -> list[EvidenceQualification]:
    rows: list[EvidenceQualification] = []
    values = payload.get("items")
    if not isinstance(values, list):
        return rows
    seen_indexes: set[int] = set()
    for value in values:
        if not isinstance(value, dict):
            continue
        index = value.get("index")
        category = value.get("category")
        relevance = value.get("relevance")
        confidence = value.get("confidence")
        rationale = value.get("rationale")
        # bool is an int subclass: True must not pass as index 1 / confidence 1.0.
        if type(index) is not int or index < 0 or index >= len(batch) or index in seen_indexes:
            continue
        if not isinstance(category, str) or category not in _VALID_CATEGORIES:
            continue
        if not isinstance(relevance, str) or relevance not in _VALID_RELEVANCE:
            continue
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            continue
        if not (0 <= float(confidence) <= 1):
            continue
        if not isinstance(rationale, str):
            continue
        seen_indexes.add(index)
        item = batch[index]
        rows.append(
            EvidenceQualification(
                run_id=run_id,
                target_id=target_id,
                url=item.url,
                title=item.title,
                category=category,
                relevance=relevance,
                confidence=float(confidence),
                rationale=flatten_untrusted(rationale)[:_MAX_RATIONALE_LEN],
                provider=provider,
                model=model,
            )
        )
    return rows


async def _annotate_run_error(run_id: int, message: str) -> None:
    session_factory = get_session
    async with session_factory() as session:
        run = await session.get(Run, run_id)
        if run:
            run.error = f"{run.error}; {message}" if run.error else message
            session.add(run)
            await session.commit()


async def qualify_evidence(
    target: Target,
    run_id: int,
    items: list[EvidenceItem],
    *,
    client: LLMClient | None = None,
) -> list[EvidenceQualification]:
    """Classify web evidence in bounded batches; invalid rows are ignored."""
    if not settings.llm_qualify_enabled:
        return []
    max_items = settings.llm_qualify_max_items
    if max_items <= 0:
        return []
    limited = items[:max_items]
    if not limited:
        return []
    client = client or get_client(target)
    if client is None:
        return []
    provider = client.provider
    model = client.model_for_route("fast")
    rows: list[EvidenceQualification] = []
    failures: list[str] = []
    pending = [limited[i : i + _BATCH_SIZE] for i in range(0, len(limited), _BATCH_SIZE)]
    # Two passes at most: items a batch left unqualified (a truncated or
    # unparseable answer, a skipped index) are asked for once more.
    for attempt in (1, 2):
        retry: list[EvidenceItem] = []
        for batch in pending:
            try:
                raw = await client.complete(
                    _QUALIFY_SYSTEM_PROMPT,
                    _build_user_prompt(target, batch),
                    timeout=settings.llm_timeout_seconds,
                    model_route="fast",
                    response_schema=_RESPONSE_SCHEMA,
                )
            except Exception as exc:  # noqa: BLE001
                # The provider client already retried transient errors.
                failures.append(str(exc))
                logger.exception(
                    "Evidence qualification failed target=%s run_id=%d attempt=%d",
                    target.id,
                    run_id,
                    attempt,
                    extra={"target_id": target.id, "run_id": run_id, "error_detail": str(exc)},
                )
                continue
            payload = _extract_json(raw)
            batch_rows = (
                _validated_rows(
                    payload=payload,
                    batch=batch,
                    run_id=run_id,
                    target_id=target.id,
                    provider=provider,
                    model=model,
                )
                if payload is not None
                else []
            )
            rows.extend(batch_rows)
            qualified_urls = {row.url for row in batch_rows}
            missing = [item for item in batch if item.url not in qualified_urls]
            if missing:
                # Unqualified items never reach the synthesis; make the gap
                # visible instead of dropping it silently.
                logger.warning(
                    "Evidence qualification incomplete target=%s run_id=%d attempt=%d "
                    "qualified=%d of %d parseable=%s",
                    target.id,
                    run_id,
                    attempt,
                    len(batch_rows),
                    len(batch),
                    payload is not None,
                    extra={
                        "target_id": target.id,
                        "run_id": run_id,
                        "qualified": len(batch_rows),
                        "batch_size": len(batch),
                    },
                )
                retry.extend(missing)
        if not retry or attempt == 2:
            break
        pending = [retry[i : i + _BATCH_SIZE] for i in range(0, len(retry), _BATCH_SIZE)]
    logger.info(
        "Evidence qualified target=%s run_id=%d qualified=%d of %d model=%s",
        target.id,
        run_id,
        len(rows),
        len(limited),
        model,
        extra={"target_id": target.id, "run_id": run_id, "qualified": len(rows), "model": model},
    )
    if failures:
        unique_failures = list(dict.fromkeys(failures))
        message = unique_failures[0]
        if len(unique_failures) > 1:
            message = f"{message}; +{len(unique_failures) - 1} more"
        await _annotate_run_error(run_id, f"qualification: {message}")
    return rows


async def persist_qualifications(rows: list[EvidenceQualification]) -> None:
    """Store qualification rows for one run."""
    if not rows:
        return
    async with get_session() as session:
        session.add_all(rows)
        await session.commit()


async def load_run_qualifications(
    run_id: int, *, session: AsyncSession | None = None
) -> list[EvidenceQualification]:
    """Read persisted qualifications for one run."""
    if session is None:
        async with get_session() as own_session:
            result = await own_session.exec(_run_qualifications_query(run_id))
            return result.all()
    result = await session.exec(_run_qualifications_query(run_id))
    return result.all()
