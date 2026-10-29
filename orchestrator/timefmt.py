"""
Operator-facing timestamps: the local date and time beside the UTC instant.

Reports and alert e-mails are read and filed by people in one time zone
(``ORCHESTRATOR_TIMEZONE``); the database, the manifests and the API stay in
UTC. Every human timestamp therefore carries both:
``25/10/2026 00:20 -03 (2026-10-25T03:20:06Z)``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, tzinfo
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from orchestrator.config import settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def _zone(name: str) -> tzinfo:
    """Resolve *name*, falling back to UTC once per distinct bad value.

    A misspelt zone must not take a report or an alert down: the UTC instant
    is printed next to the local one anyway, so falling back loses
    convenience, not evidence. The cache keeps the warning to one line per
    value instead of one per timestamp.
    """
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        logger.warning("Unknown ORCHESTRATOR_TIMEZONE %r; dates fall back to UTC", name)
        return UTC


def operator_zone() -> tzinfo:
    """The configured operator time zone (``ORCHESTRATOR_TIMEZONE``), UTC if blank."""
    return _zone((settings.orchestrator_timezone or "UTC").strip() or "UTC")


def local_stamp(dt: datetime | None, lang: str, *, code: bool = False) -> str:
    """``dd/mm/yyyy HH:MM <zone> (<UTC ISO>)`` for Spanish, ISO-like for English.

    Naive datetimes are taken as UTC (SQLite returns them naive). ``code``
    wraps the UTC instant in backticks for Markdown. ``None`` renders "-".
    """
    if dt is None:
        return "-"
    aware = dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    zone = operator_zone()
    local = aware.astimezone(zone)
    human = local.strftime("%d/%m/%Y %H:%M" if lang == "es" else "%Y-%m-%d %H:%M")
    zone_name = local.tzname() or str(zone)
    utc_iso = aware.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    instant = f"`{utc_iso}`" if code else utc_iso
    return f"{human} {zone_name} ({instant})"
