"""Demo-mode helpers: allowlist, startup validation and daily budget accounting."""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlmodel import Column, DateTime, SQLModel
from sqlmodel import Field as SQLField

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.models import Target

logger = logging.getLogger(__name__)

_DEMO_TARGETS_ERROR = "<targets-file>"


class DemoDailyUsage(SQLModel, table=True):
    """Persisted daily usage counters for the public demo deployment."""

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


def _today_key() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def hash_client_ip(raw_ip: str | None) -> str:
    """HMAC-SHA256 the client IP so a public demo can count usage without storing it."""
    cleaned = (raw_ip or "").strip()
    if not cleaned:
        return "anonymous"
    secret = (settings.orchestrator_secret_key or "demo-mode").encode("utf-8")
    return hmac.new(secret, cleaned.encode("utf-8"), hashlib.sha256).hexdigest()


async def record_demo_usage(
    *, client_ip: str | None, increment_run: bool = False, tavily_calls: int = 0, llm_calls: int = 0
) -> dict[str, int | str]:
    """Update the daily counters and return the remaining budgets."""
    today = _today_key()
    ip_hash = hash_client_ip(client_ip)
    async with get_session() as session:
        stmt = select(DemoDailyUsage).where(
            DemoDailyUsage.day == today,
            DemoDailyUsage.scope == "global",
        )
        row = (await session.exec(stmt)).first()
        if row is None:
            row = DemoDailyUsage(
                day=today,
                scope="global",
                client_ip_hash="global",
                run_count=0,
                tavily_calls=0,
                llm_calls=0,
            )
            session.add(row)

        if increment_run:
            row.run_count += 1

        row.tavily_calls += max(0, int(tavily_calls))
        row.llm_calls += max(0, int(llm_calls))
        row.updated_at = datetime.now(UTC)

        ip_row = (await session.exec(select(DemoDailyUsage).where(
            DemoDailyUsage.day == today,
            DemoDailyUsage.scope == "ip",
            DemoDailyUsage.client_ip_hash == ip_hash,
        ))).first()
        if ip_row is None:
            ip_row = DemoDailyUsage(
                day=today,
                scope="ip",
                client_ip_hash=ip_hash,
                run_count=0,
                tavily_calls=0,
                llm_calls=0,
            )
            session.add(ip_row)
        if increment_run:
            ip_row.run_count += 1
        ip_row.tavily_calls += max(0, int(tavily_calls))
        ip_row.llm_calls += max(0, int(llm_calls))
        ip_row.updated_at = datetime.now(UTC)
        await session.commit()

    return {
        "global_runs": row.run_count,
        "ip_runs": ip_row.run_count,
        "global_tavily_calls": row.tavily_calls,
        "global_llm_calls": row.llm_calls,
    }


async def demo_usage_available(*, client_ip: str | None, increment_run: bool = False, tavily_calls: int = 0, llm_calls: int = 0) -> tuple[bool, str | None]:
    """Return (allowed, reason) for a demo request based on the rolling daily budgets."""
    if not settings.demo_mode:
        return True, None

    today = _today_key()
    ip_hash = hash_client_ip(client_ip)
    async with get_session() as session:
        global_row = (await session.exec(select(DemoDailyUsage).where(
            DemoDailyUsage.day == today,
            DemoDailyUsage.scope == "global",
        ))).first()
        ip_row = (await session.exec(select(DemoDailyUsage).where(
            DemoDailyUsage.day == today,
            DemoDailyUsage.scope == "ip",
            DemoDailyUsage.client_ip_hash == ip_hash,
        ))).first()

    global_runs = int(getattr(global_row, "run_count", 0) or 0)
    ip_runs = int(getattr(ip_row, "run_count", 0) or 0)
    global_tavily = int(getattr(global_row, "tavily_calls", 0) or 0)
    global_llm = int(getattr(global_row, "llm_calls", 0) or 0)

    if increment_run:
        global_runs += 1
        ip_runs += 1
    if tavily_calls:
        global_tavily += tavily_calls
    if llm_calls:
        global_llm += llm_calls

    if ip_runs > settings.demo_max_runs_per_ip_per_day:
        return False, "demo_run_limit_per_ip_exceeded"
    if global_runs > settings.demo_max_runs_per_day:
        return False, "demo_run_limit_exceeded"
    if global_tavily > settings.demo_tavily_calls_per_day:
        return False, "demo_tavily_budget_exceeded"
    if global_llm > settings.demo_llm_calls_per_day:
        return False, "demo_llm_budget_exceeded"
    return True, None


def load_demo_targets(path: str) -> tuple[list[Target], list[str], bool]:
    """Load allowlisted demo targets from the demo targets file."""
    targets_path = Path(path)
    if not targets_path.exists():
        logger.warning("demo targets file not found: %s", path)
        return [], [_DEMO_TARGETS_ERROR], True

    try:
        data = yaml.safe_load(targets_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Invalid demo targets file %s: %s", path, exc)
        return [], [_DEMO_TARGETS_ERROR], True

    if not isinstance(data, dict):
        logger.error("Invalid demo targets file %s: top level must be a mapping", path)
        return [], [_DEMO_TARGETS_ERROR], True

    raw_targets = data.get("targets", [])
    if not isinstance(raw_targets, list):
        logger.error("Invalid demo targets file %s: 'targets' must be a list", path)
        return [], [_DEMO_TARGETS_ERROR], True

    loaded: list[Target] = []
    invalid: list[str] = []
    for idx, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            invalid.append(f"<index {idx}>")
            continue
        try:
            loaded.append(Target(**raw))
        except Exception as exc:  # noqa: BLE001
            target_id = str(raw.get("id", f"<index {idx}>"))
            logger.warning("Skipping invalid demo target %s from %s: %s", target_id, path, exc)
            invalid.append(target_id)
    return loaded, sorted(set(invalid)), False


def validate_demo_mode() -> None:
    """Validate demo mode settings before the scheduler and API start.'""
    if not settings.demo_mode:
        return
    if not settings.demo_targets_file:
        raise RuntimeError("DEMO_TARGETS_FILE must be set when DEMO_MODE=true")
    targets, invalid, load_failed = load_demo_targets(settings.demo_targets_file)
    if load_failed:
        raise RuntimeError(f"Demo mode targets file could not be loaded: {settings.demo_targets_file}")
    if invalid:
        raise RuntimeError(f"Demo mode targets file contains invalid entries: {', '.join(invalid)}")
    if not targets:
        raise RuntimeError(f"Demo mode targets file is empty: {settings.demo_targets_file}")
    if settings.demo_max_runs_per_ip_per_day <= 0:
        raise RuntimeError("DEMO_MAX_RUNS_PER_IP_PER_DAY must be > 0")
    if settings.demo_max_runs_per_day <= 0:
        raise RuntimeError("DEMO_MAX_RUNS_PER_DAY must be > 0")
    if settings.demo_tavily_calls_per_day < 0:
        raise RuntimeError("DEMO_TAVILY_CALLS_PER_DAY must be >= 0")
    if settings.demo_llm_calls_per_day < 0:
        raise RuntimeError("DEMO_LLM_CALLS_PER_DAY must be >= 0")
    if settings.demo_trusted_proxy_hops < 0:
        raise RuntimeError("DEMO_TRUSTED_PROXY_HOPS must be >= 0")


def _strip_demo_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_demo_fields(item)
            for key, item in value.items()
            if key not in {"risk_level", "risk_justification"}
        }
    if isinstance(value, list):
        return [_strip_demo_fields(item) for item in value]
    return value


def strip_demo_risk_fields(payload: Any) -> Any:
    """Remove persisted risk fields from public demo responses."""
    return _strip_demo_fields(payload)
