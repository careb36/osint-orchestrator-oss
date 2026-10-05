"""Public demo mode: allowlist, usage limits, call budgets and public views.

Everything here is inert unless ``DEMO_MODE=true``. In demo mode an anonymous
visitor can only start runs on the operator's allowlist of targets, within a
per-IP and a global daily limit, and every Tavily and LLM call is drawn from a
daily budget. Public views never carry the model's synthesis: no summary, no
``risk_level``, no ``risk_justification``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import Request
from sqlalchemy import delete
from sqlmodel import Column, DateTime, SQLModel, select
from sqlmodel import Field as SQLField

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.evidence import build_manifest, canonical_json, sha256_file, write_manifest_file
from orchestrator.i18n import resolve_language, t
from orchestrator.models import (
    EvidenceQualification,
    FindingRecord,
    Run,
    RunStatus,
    Target,
)
from orchestrator.targets import load_targets

logger = logging.getLogger(__name__)

_DEFAULT_SECRET_KEY = "insecure-dev-key"
_GLOBAL = "global"
_COUNTER_RETENTION_DAYS = 2
BudgetKind = Literal["tavily", "llm"]


class DemoDailyUsage(SQLModel, table=True):
    """Daily usage counters of the public demo (one global row, one per client)."""

    __tablename__ = "demo_daily_usage"

    id: int | None = SQLField(default=None, primary_key=True)
    day: str = SQLField(index=True)
    scope: str = SQLField(index=True)
    client_ip_hash: str = SQLField(index=True)
    run_count: int = 0
    tavily_calls: int = 0
    llm_calls: int = 0
    updated_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


# ─── Allowlist and startup validation ────────────────────────────────────────


def load_demo_targets() -> list[Target]:
    """The allowlist: targets of ``DEMO_TARGETS_FILE`` (same schema as targets.yaml)."""
    targets, _errors = load_targets(settings.demo_targets_file)
    return [target for target in targets if target.enabled]


def demo_target(target_id: str) -> Target | None:
    """The allowlisted target with this id, or None."""
    return next((target for target in load_demo_targets() if target.id == target_id), None)


def _uses_nebius(target: Target) -> bool:
    """True when this target's synthesis goes to Nebius (see providers.get_client)."""
    if settings.llm_provider == "none":
        return False  # synthesis is off for every target; no client is ever built
    if target.llm == "nebius":
        return True
    return target.llm == "openai" and settings.llm_provider == "nebius"


def _enabled_collectors(target: Target) -> list[str]:
    collectors = target.collectors
    return [
        name
        for name in ("openosint", "spiderfoot", "socialosint", "amass", "tavily")
        if getattr(collectors, name).enabled
    ]


def validate_demo_mode() -> None:
    """Refuse to start a demo deployment that is unsafe to expose.

    Raises RuntimeError with every problem found, so one restart fixes all.
    """
    if not settings.demo_mode:
        return
    problems: list[str] = []
    if settings.opencti_enabled:
        problems.append("OPENCTI_ENABLED must be false")
    if settings.orchestrator_secret_key in ("", _DEFAULT_SECRET_KEY):
        problems.append(
            "ORCHESTRATOR_SECRET_KEY must be set (it signs manifests and hashes client IPs)"
        )
    if not settings.orchestrator_api_key.strip():
        problems.append("ORCHESTRATOR_API_KEY must be set (protected routes stay protected)")
    for name in ("demo_max_runs_per_ip_per_day", "demo_max_runs_per_day"):
        if getattr(settings, name) <= 0:
            problems.append(f"{name.upper()} must be > 0")
    for name in ("demo_tavily_calls_per_day", "demo_llm_calls_per_day", "demo_trusted_proxy_hops"):
        if getattr(settings, name) < 0:
            problems.append(f"{name.upper()} must be >= 0")

    targets, errors = load_targets(settings.demo_targets_file)
    if errors:
        problems.append(f"DEMO_TARGETS_FILE {settings.demo_targets_file}: invalid {errors}")
    enabled = [target for target in targets if target.enabled]
    if not enabled and not errors:
        problems.append(f"DEMO_TARGETS_FILE {settings.demo_targets_file} lists no enabled target")
    for target in enabled:
        extra = [name for name in _enabled_collectors(target) if name != "tavily"]
        if extra or not target.collectors.tavily.enabled:
            problems.append(
                f"demo target {target.id}: only the tavily collector may be enabled "
                f"(enabled: {_enabled_collectors(target)})"
            )
    # A demo that starts with a half-filled .env is worse than one that refuses
    # to start: every run would fail or come back empty in front of the audience.
    if enabled and not settings.tavily_api_key.strip():
        problems.append("TAVILY_API_KEY must be set (every demo target collects with Tavily)")
    if any(_uses_nebius(target) for target in enabled):
        if not settings.nebius_api_key.strip():
            problems.append("NEBIUS_API_KEY must be set (demo targets synthesise with llm: nebius)")
        for name in ("llm_model_reasoning", "llm_model_fast"):
            if not getattr(settings, name).strip():
                problems.append(
                    f"{name.upper()} must name a Nemotron model served to your Nebius key"
                )
    if problems:
        raise RuntimeError("DEMO_MODE=true is misconfigured: " + "; ".join(problems))
    logger.info(
        "Demo mode enabled targets=%d runs_per_ip_per_day=%d runs_per_day=%d "
        "tavily_calls_per_day=%d llm_calls_per_day=%d",
        len(enabled),
        settings.demo_max_runs_per_ip_per_day,
        settings.demo_max_runs_per_day,
        settings.demo_tavily_calls_per_day,
        settings.demo_llm_calls_per_day,
    )


# ─── Client identity ──────────────────────────────────────────────────────────


def client_ip(request: Request) -> str:
    """The visitor's address, honouring ``DEMO_TRUSTED_PROXY_HOPS``.

    With N trusted proxies in front, the client is the N-th address from the
    right of ``X-Forwarded-For``; anything further left is supplied by the
    client and must not be trusted. With 0 hops the socket peer is used.
    """
    peer = request.client.host if request.client else ""
    hops = settings.demo_trusted_proxy_hops
    if hops <= 0:
        return peer
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",")]
    forwarded = [part for part in forwarded if part]
    if len(forwarded) >= hops:
        return forwarded[-hops]
    return peer


def hash_client_ip(raw_ip: str | None) -> str:
    """HMAC-SHA256 of the address: usage is counted without storing the IP."""
    key = settings.orchestrator_secret_key.encode("utf-8")
    return hmac.new(key, (raw_ip or "").strip().encode("utf-8"), hashlib.sha256).hexdigest()


# ─── Daily limits and budgets ─────────────────────────────────────────────────


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def seconds_until_reset() -> int:
    """Seconds until the counters reset (next UTC midnight)."""
    now = datetime.now(UTC)
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds()))


async def _row(session: Any, day: str, scope: str, ip_hash: str) -> DemoDailyUsage:
    result = await session.exec(
        select(DemoDailyUsage).where(
            DemoDailyUsage.day == day,
            DemoDailyUsage.scope == scope,
            DemoDailyUsage.client_ip_hash == ip_hash,
        )
    )
    row = result.first()
    if row is None:
        row = DemoDailyUsage(day=day, scope=scope, client_ip_hash=ip_hash)
        session.add(row)
    return row


async def claim_run(raw_ip: str) -> str | None:
    """Count one run for this client, or return the i18n key of the limit hit.

    Check and increment happen in one transaction, so two concurrent requests
    cannot both take the last slot. Counter rows older than two days are
    removed here: only an HMAC of the address is ever stored, and not for long.
    """
    day = _today()
    cutoff = (datetime.now(UTC) - timedelta(days=_COUNTER_RETENTION_DAYS)).strftime("%Y-%m-%d")
    async with get_session() as session:
        await session.exec(delete(DemoDailyUsage).where(DemoDailyUsage.day < cutoff))
        total = await _row(session, day, _GLOBAL, _GLOBAL)
        mine = await _row(session, day, "ip", hash_client_ip(raw_ip))
        reason: str | None = None
        if mine.run_count >= settings.demo_max_runs_per_ip_per_day:
            reason = "demo.limit_per_ip"
        elif total.run_count >= settings.demo_max_runs_per_day:
            reason = "demo.limit_global"
        else:
            now = datetime.now(UTC)
            total.run_count += 1
            mine.run_count += 1
            total.updated_at = mine.updated_at = now
        await session.commit()
    return reason


async def release_run(raw_ip: str) -> None:
    """Give back a run claimed by ``claim_run`` that did not start (409)."""
    async with get_session() as session:
        for scope, ip_hash in ((_GLOBAL, _GLOBAL), ("ip", hash_client_ip(raw_ip))):
            row = await _row(session, _today(), scope, ip_hash)
            row.run_count = max(0, row.run_count - 1)
        await session.commit()


async def consume_budget(kind: BudgetKind) -> bool:
    """Take one call from today's Tavily or LLM budget; False when it is spent.

    Always True outside demo mode. Callers must not make the call on False.
    """
    if not settings.demo_mode:
        return True
    limit = (
        settings.demo_tavily_calls_per_day if kind == "tavily" else settings.demo_llm_calls_per_day
    )
    column = "tavily_calls" if kind == "tavily" else "llm_calls"
    async with get_session() as session:
        total = await _row(session, _today(), _GLOBAL, _GLOBAL)
        used = getattr(total, column)
        allowed = used < limit
        if allowed:
            setattr(total, column, used + 1)
            total.updated_at = datetime.now(UTC)
        await session.commit()
    if not allowed:
        logger.warning(
            "Demo daily %s budget exhausted limit=%d; call not made",
            kind,
            limit,
            extra={"status": "demo_budget_exhausted", "collector": kind},
        )
    return allowed


# ─── Public views (never carry the risk assessment) ───────────────────────────


def public_target(target: Target) -> dict[str, Any]:
    """What a visitor may know about an allowlisted target."""
    return {
        "id": target.id,
        "fqdn": target.fqdn,
        "search_terms": list(target.collectors.tavily.search_terms),
    }


def public_run(run: Run) -> dict[str, Any]:
    """Run status for the public page: no error text, no file paths."""
    return {
        "run_id": run.id,
        "target_id": run.target_id,
        "status": run.status.value if isinstance(run.status, RunStatus) else str(run.status),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "new_observables": run.new_observables,
        "sealed": run.manifest_sha256 is not None,
    }


_PUBLIC_FINDING_FIELDS = ("run_id", "target_id", "provider", "model", "duration_ms", "generated_at")
_SYNTHESIS_HEADINGS = ("## Síntesis", "## Synthesis")


def public_finding(record: FindingRecord) -> dict[str, Any]:
    """That a synthesis exists, which model wrote it and how long it took.

    The synthesis itself (summary, risk level, justification, pivots) is free
    model prose about a named entity; it is for the operator, never public.
    The public page shows the qualified evidence instead, where every row is
    tied to its source.
    """
    payload = record.to_api_dict()
    return {key: payload.get(key) for key in _PUBLIC_FINDING_FIELDS}


def _without_synthesis(markdown: str, notice: str) -> str:
    """The report with its synthesis section replaced by *notice*."""
    kept: list[str] = []
    skipping = False
    for line in markdown.splitlines():
        if line.startswith(_SYNTHESIS_HEADINGS):
            skipping = True
            kept.extend([line, notice])
            continue
        if skipping and line.startswith("## "):
            skipping = False
        if not skipping:
            kept.append(line)
    return "\n".join(kept) + "\n"


def public_report(markdown: str, language: str | None) -> str:
    """The report as served publicly: disclaimer first, no synthesis section."""
    lang = resolve_language(language)
    body = _without_synthesis(markdown, t("demo.synthesis_withheld", language=lang))
    return f"> {t('demo.disclaimer', language=lang)}\n\n{body}"


# ─── Seed data ────────────────────────────────────────────────────────────────

SEED_VERSION = 1


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


async def import_seed_if_empty(seed_dir: str | Path = "demo/seed") -> int:
    """Load ``demo/seed/*.json`` once, when no demo target has a run yet.

    Each seed run gets a new run id and its own directory, and is sealed again
    with this deployment's ``ORCHESTRATOR_SECRET_KEY`` (seed files carry no
    signature and no key), so imported runs verify with ``chain/verify`` like
    any run made here. Returns the number of runs imported.
    """
    allowlist = {target.id: target for target in load_demo_targets()}
    files = sorted(Path(seed_dir).glob("*.json"))
    if not allowlist or not files:
        return 0
    async with get_session() as session:
        existing = await session.exec(select(Run.id).where(Run.target_id.in_(list(allowlist))))
        if existing.first() is not None:
            return 0

    imported = 0
    for path in files:
        try:
            seed = json.loads(path.read_text(encoding="utf-8"))
            if seed.get("seed_version") != SEED_VERSION:
                raise ValueError(f"unsupported seed_version {seed.get('seed_version')!r}")
            target = allowlist.get(seed["run"]["target_id"])
            if target is None:
                raise ValueError(f"target {seed['run']['target_id']!r} is not on the allowlist")
            await _import_seed_run(seed, target)
            imported += 1
        except Exception:  # noqa: BLE001 - a bad seed file must not stop the demo
            logger.exception("Demo seed not imported file=%s", path.name)
    if imported:
        logger.info("Demo seed imported runs=%d of %d files", imported, len(files))
    return imported


async def _import_seed_run(seed: dict[str, Any], target: Target) -> None:
    source = seed["run"]
    started = _parse_dt(source["started_at"]) or datetime.now(UTC)
    finished = _parse_dt(source.get("finished_at")) or started
    async with get_session() as session:
        run = Run(
            target_id=target.id,
            started_at=started,
            finished_at=finished,
            status=RunStatus(source["status"]),
            collectors_run=source.get("collectors_run") or "",
            new_observables=int(source.get("new_observables") or 0),
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

        day = started.astimezone(UTC).strftime("%Y-%m-%d")
        run_dir = Path(target.report_dir) / day / target.id / f"run-{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        for name, content in sorted(seed.get("files", {}).items()):
            if Path(name).name != name or name == "manifest.json":
                raise ValueError(f"unsafe seed file name {name!r}")
            (run_dir / name).write_text(content, encoding="utf-8")
        report_path = run_dir / "report.md"
        if not report_path.exists():
            raise ValueError("seed has no report.md")

        finding = seed.get("finding")
        if finding:
            session.add(
                FindingRecord(
                    run_id=run_id,
                    target_id=target.id,
                    # Seeds carry no synthesis text and no risk assessment
                    # (public data set): only which model ran and for how long.
                    summary="",
                    risk_level="unknown",
                    risk_justification="",
                    provider=finding.get("provider", ""),
                    model=finding.get("model", ""),
                    duration_ms=int(finding.get("duration_ms") or 0),
                )
            )
        for row in seed.get("evidence", []):
            session.add(
                EvidenceQualification(
                    run_id=run_id,
                    target_id=target.id,
                    url=row["url"],
                    title=row.get("title", ""),
                    category=row["category"],
                    relevance=row["relevance"],
                    confidence=float(row["confidence"]),
                    rationale=row.get("rationale", ""),
                    provider=row.get("provider", ""),
                    model=row.get("model", ""),
                )
            )

        previous = await session.exec(
            select(Run.manifest_sha256)
            .where(Run.target_id == target.id)
            .where(Run.manifest_sha256.is_not(None))
            .where(Run.id != run_id)
            .order_by(Run.started_at.desc(), Run.id.desc())
            .limit(1)
        )
        artefacts = {
            item.name: sha256_file(item)
            for item in sorted(run_dir.iterdir())
            if item.is_file() and item.name != "manifest.json"
        }
        manifest = build_manifest(
            run_id=run_id,
            target_id=target.id,
            started_at=started,
            finished_at=finished,
            status=source["status"],
            collectors_run=[c for c in (source.get("collectors_run") or "").split(",") if c],
            artefacts=artefacts,
            previous_manifest_sha256=previous.first(),
            secret_key=settings.orchestrator_secret_key,
        )
        run.report_path = str(report_path)
        run.manifest_sha256 = write_manifest_file(report_path=report_path, manifest=manifest)
        session.add(run)
        await session.commit()


def export_seed(
    *,
    run: dict[str, Any],
    finding: dict[str, Any] | None,
    evidence: list[dict[str, Any]],
    run_dir: Path,
) -> str:
    """Seed JSON for one run: no risk fields, no signature, no key, no raw model output."""
    files: dict[str, str] = {}
    for item in sorted(run_dir.iterdir()):
        if (
            not item.is_file()
            or item.suffix not in {".md", ".json"}
            or item.name == "manifest.json"
        ):
            continue
        text = item.read_text(encoding="utf-8")
        if item.name == "report.md":
            text = _without_synthesis(text, "_Synthesis not included in the public data set._")
        files[item.name] = text
    clean_finding = None
    if finding:
        clean_finding = {
            key: finding.get(key) for key in ("provider", "model", "duration_ms", "generated_at")
        }
    seed = {
        "seed_version": SEED_VERSION,
        "run": {
            key: run.get(key)
            for key in (
                "target_id",
                "started_at",
                "finished_at",
                "status",
                "collectors_run",
                "new_observables",
            )
        },
        "finding": clean_finding,
        "evidence": [
            {
                key: row.get(key)
                for key in (
                    "url",
                    "title",
                    "category",
                    "relevance",
                    "confidence",
                    "rationale",
                    "provider",
                    "model",
                )
            }
            for row in evidence
        ],
        "files": files,
    }
    return canonical_json(seed)
