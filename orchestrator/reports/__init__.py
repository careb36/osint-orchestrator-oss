"""
Deterministic daily report generation (Phase 2).

Outputs under daily_reports/YYYY-MM-DD/<target_id>/run-<run_id>/ (one
directory per run, so several runs of a target on the same day never
overwrite each other's artefacts):
  - report.md
  - bundle.stix.json
  - delta.json
  - report.pdf (optional; best-effort via fpdf2)

Also maintains daily_reports/YYYY-MM-DD/index.md.
"""

from __future__ import annotations

import contextlib
import json
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from orchestrator.i18n import resolve_language, t
from orchestrator.models import Finding

try:
    import fcntl
except ImportError:  # pragma: no cover — Windows dev box; the lock is advisory
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


_TEXT: dict[str, dict[str, str]] = {
    "title": {"es": "# Reporte diario OSINT", "en": "# Daily OSINT report"},
    "target": {"es": "Objetivo", "en": "Target"},
    "run_id": {"es": "Run ID", "en": "Run ID"},
    "status": {"es": "Estado", "en": "Status"},
    "started_at": {"es": "Inicio (UTC)", "en": "Started (UTC)"},
    "finished_at": {"es": "Fin (UTC)", "en": "Finished (UTC)"},
    "authorization": {"es": "Autorización", "en": "Authorization"},
    "purpose": {"es": "Propósito", "en": "Purpose"},
    "collectors": {"es": "## Estado por collector", "en": "## Collector status"},
    "collector": {"es": "Collector", "en": "Collector"},
    "ok": {"es": "Resultado", "en": "Result"},
    "observables": {"es": "Observables", "en": "Observables"},
    "error": {"es": "Error", "en": "Error"},
    "new_first": {
        "es": "## Nuevo desde la última corrida",
        "en": "## New since previous run",
    },
    "inventory": {"es": "## Inventario completo", "en": "## Full inventory"},
    "relationships": {"es": "## Relaciones", "en": "## Relationships"},
    "qualified_evidence": {"es": "## Evidencia calificada", "en": "## Qualified evidence"},
    "qualified_evidence_category": {"es": "Categoría", "en": "Category"},
    "qualified_evidence_relevance": {"es": "Relevancia", "en": "Relevance"},
    "qualified_evidence_confidence": {"es": "Confianza", "en": "Confidence"},
    "qualified_evidence_title": {"es": "Título", "en": "Title"},
    "qualified_evidence_rationale": {"es": "Justificación", "en": "Rationale"},
    "errors": {"es": "## Errores", "en": "## Errors"},
    "synthesis": {"es": "## Síntesis", "en": "## Synthesis"},
    "synthesis_risk": {"es": "**Riesgo**", "en": "**Risk**"},
    "synthesis_pivots": {"es": "**Pivots sugeridos**", "en": "**Suggested pivots**"},
    "none": {"es": "_Sin elementos_", "en": "_No items_"},
    "index_title": {"es": "# Resumen diario", "en": "# Daily summary"},
    "index_target": {"es": "Objetivo", "en": "Target"},
    "index_status": {"es": "Estado", "en": "Status"},
    "index_new": {"es": "Nuevos", "en": "New"},
    "index_risk": {"es": "Riesgo", "en": "Risk"},
    "index_report": {"es": "Reporte", "en": "Report"},
    "index_view": {"es": "ver", "en": "view"},
}


class CollectorReportResult(BaseModel):
    """Per-collector outcome row rendered in the report's collector-status table."""

    collector: str
    success: bool
    error: str | None = None
    observable_count: int = 0


class ReportObservable(BaseModel):
    """One observable as rendered in the report inventory (delta flag included)."""

    stix_id: str
    stix_type: str
    value: str
    is_new: bool
    # Which collector produced it; lets the synthesizer sample fairly across
    # sources instead of letting the chattiest one fill the prompt.
    collector: str = ""


class RunReportData(BaseModel):
    """Everything ``generate_report`` needs — run data only, no I/O.

    Reporting is deterministic: same input, byte-identical artifacts. The
    pipeline builds this from the Run row, collector results and merged
    observables; ``bundles`` are the raw STIX bundles emitted per collector.
    """

    target_id: str
    target_fqdn: str
    authorization: str
    purpose: str
    run_id: int
    run_status: str
    run_started_at: datetime
    run_finished_at: datetime | None = None
    collector_results: list[CollectorReportResult] = Field(default_factory=list)
    bundles: list[dict[str, Any]] = Field(default_factory=list)
    observables: list[ReportObservable] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    language: str | None = None


def _msg(key: str, lang: str) -> str:
    """Look up a report label in the local catalogue (report-only strings)."""
    return _TEXT[key][lang]


def _as_dict(obj: Any) -> dict[str, Any]:
    """Coerce a STIX object (dict or dict-like) to a plain dict."""
    if isinstance(obj, dict):
        return obj
    return dict(obj)


def _bundle_date(run_started_at: datetime) -> str:
    """Return the UTC YYYY-MM-DD directory name for a run's artifacts."""
    return _ensure_utc(run_started_at).astimezone(UTC).strftime("%Y-%m-%d")


def _deterministic_bundle_id(object_ids: list[str]) -> str:
    """Derive a stable bundle id (uuid5) from the sorted member object ids."""
    seed = "|".join(sorted(object_ids)) or "empty"
    return f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def stix_object_value(stix_obj: dict[str, Any]) -> str:
    """Extract the human-meaningful value of a STIX object for display.

    Most observables carry ``value``; the exceptions map to their natural
    key: AS number for ``autonomous-system``, first hash for ``file``,
    subject for ``x509-certificate``, ``user_id`` for ``user-account``, and
    ``name`` for ``identity``/``indicator``. Returns "" when none applies.
    """
    if "value" in stix_obj and stix_obj["value"]:
        return str(stix_obj["value"])
    if stix_obj.get("type") == "autonomous-system":
        number = stix_obj.get("number")
        return f"AS{number}" if number is not None else str(stix_obj.get("name", ""))
    if stix_obj.get("type") == "file":
        hashes = stix_obj.get("hashes", {})
        if isinstance(hashes, dict) and hashes:
            algo = sorted(hashes)[0]
            return str(hashes[algo])
    if stix_obj.get("type") == "x509-certificate":
        return str(stix_obj.get("subject", ""))
    if stix_obj.get("type") == "user-account":
        return str(stix_obj.get("user_id", ""))
    if stix_obj.get("type") == "identity":
        return str(stix_obj.get("name", ""))
    if stix_obj.get("type") == "indicator":
        return str(stix_obj.get("name", ""))
    return ""


def _ensure_utc(dt: datetime) -> datetime:
    """Attach UTC to naive datetimes; pass aware ones through unchanged."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _merge_bundles(bundles: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge collector bundles into one deduplicated, deterministically ordered bundle.

    Objects are keyed by STIX id (first occurrence wins), sorted by id, and
    the bundle id is a uuid5 over the member ids — so the same inputs always
    produce a byte-identical ``bundle.stix.json``.
    """
    dedup: dict[str, dict[str, Any]] = {}
    for bundle in bundles:
        for item in bundle.get("objects", []):
            obj = _as_dict(item)
            stix_id = str(obj.get("id", ""))
            if not stix_id:
                continue
            dedup.setdefault(stix_id, obj)
    ordered = sorted(dedup.values(), key=lambda o: str(o.get("id", "")))
    bundle_id = _deterministic_bundle_id([str(o.get("id", "")) for o in ordered])
    return {"type": "bundle", "id": bundle_id, "objects": ordered}


def _collector_table(data: RunReportData, lang: str) -> list[str]:
    """Render the Markdown collector-status table (sorted by collector name)."""
    lines = [
        f"| {_msg('collector', lang)} | {_msg('ok', lang)} | {_msg('observables', lang)} | {_msg('error', lang)} |",
        "|---|---|---:|---|",
    ]
    for result in sorted(data.collector_results, key=lambda r: r.collector):
        outcome = "ok" if result.success else "error"
        lines.append(
            f"| {result.collector} | {outcome} | {result.observable_count} | {result.error or ''} |"
        )
    return lines


def _new_section(observables: list[ReportObservable], lang: str) -> list[str]:
    """Render the delta-first section: observables new since the previous run."""
    rows = [o for o in observables if o.is_new]
    lines = [_msg("new_first", lang)]
    if not rows:
        lines.append(_msg("none", lang))
        return lines
    for obs in sorted(rows, key=lambda o: (o.stix_type, o.value, o.stix_id)):
        lines.append(f"- `{obs.stix_type}` `{obs.value}` ({obs.stix_id})")
    return lines


def _inventory_section(observables: list[ReportObservable], lang: str) -> list[str]:
    """Render the full observable inventory, grouped by STIX type."""
    lines = [_msg("inventory", lang)]
    if not observables:
        lines.append(_msg("none", lang))
        return lines
    by_type: dict[str, list[ReportObservable]] = defaultdict(list)
    for obs in observables:
        by_type[obs.stix_type].append(obs)
    for stix_type in sorted(by_type):
        lines.append(f"### {stix_type}")
        for obs in sorted(by_type[stix_type], key=lambda o: (o.value, o.stix_id)):
            suffix = " [new]" if obs.is_new else ""
            lines.append(f"- `{obs.value}` ({obs.stix_id}){suffix}")
    return lines


def _relationships_section(bundle: dict[str, Any], lang: str) -> list[str]:
    """Render STIX relationship objects from the merged bundle as a sorted list."""
    rels = [
        obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, dict) and obj.get("type") == "relationship"
    ]
    lines = [_msg("relationships", lang)]
    if not rels:
        lines.append(_msg("none", lang))
        return lines
    for rel in sorted(
        rels,
        key=lambda r: (
            str(r.get("relationship_type", "")),
            str(r.get("source_ref", "")),
            str(r.get("target_ref", "")),
        ),
    ):
        lines.append(
            f"- `{rel.get('relationship_type', '')}`: "
            f"{rel.get('source_ref', '')} -> {rel.get('target_ref', '')}"
        )
    return lines


def _evidence_sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
    relevance_order = {"high": 0, "medium": 1, "low": 2}
    relevance = str(item.get("relevance", "low")).lower()
    confidence = float(item.get("confidence", 0.0) or 0.0)
    url = str(item.get("url", ""))
    return relevance_order.get(relevance, 3), -confidence, url


def _qualified_evidence_section(evidence: list[dict[str, Any]], lang: str) -> list[str]:
    lines = [_msg("qualified_evidence", lang)]
    if not evidence:
        lines.append(_msg("none", lang))
        return lines
    lines.extend(
        [
            (
                f"| {_msg('qualified_evidence_category', lang)} |"
                f" {_msg('qualified_evidence_relevance', lang)} |"
                f" {_msg('qualified_evidence_confidence', lang)} |"
                f" {_msg('qualified_evidence_title', lang)} |"
                f" {_msg('qualified_evidence_rationale', lang)} |"
            ),
            "|---|---|---:|---|---|",
        ]
    )
    for item in sorted(evidence, key=_evidence_sort_key):
        title = str(item.get("title", "")).replace("|", " ")
        url = str(item.get("url", ""))
        title_cell = f"[{title}]({url})" if title and url else title
        lines.append(
            "| "
            + " | ".join(
                [
                    str(item.get("category", "")),
                    str(item.get("relevance", "")),
                    f"{float(item.get('confidence', 0.0) or 0.0):.2f}",
                    title_cell,
                    str(item.get("rationale", "")).replace("|", " "),
                ]
            )
            + " |"
        )
    return lines


def _errors_section(errors: list[str], lang: str) -> list[str]:
    """Render the run's collected error strings as a bullet list."""
    lines = [_msg("errors", lang)]
    if not errors:
        lines.append(_msg("none", lang))
        return lines
    for err in errors:
        lines.append(f"- {err}")
    return lines


def _synthesis_section(
    finding: Finding | None,
    lang: str,
    synthesis_status: Literal["ok", "skipped", "failed"] = "skipped",
) -> list[str]:
    """Render the LLM synthesis section (summary, risk, suggested pivots).

    Without a finding, renders the i18n message matching *synthesis_status*:
    "skipped" (no provider configured) or "failed" (the LLM call errored).
    """
    lines = [_msg("synthesis", lang)]
    if finding is None:
        # "synthesis_failed" carries an {error} placeholder for the run record;
        # the report has no error text to give it, so it uses the plain key.
        key = "synthesis_skipped" if synthesis_status == "skipped" else "synthesis_unavailable"
        lines.append(t(key, language=lang))
        return lines
    lines.append(finding.summary)
    lines.append("")
    lines.append(
        f"{_msg('synthesis_risk', lang)}: `{finding.risk_level}`"
        + (f" — {finding.risk_justification}" if finding.risk_justification else "")
    )
    if finding.suggested_pivots:
        lines.append("")
        lines.append(f"{_msg('synthesis_pivots', lang)}:")
        for pivot in finding.suggested_pivots:
            lines.append(f"- {pivot}")
    return lines


def _markdown_content(
    data: RunReportData,
    bundle: dict[str, Any],
    lang: str,
    finding: Finding | None = None,
    synthesis_status: Literal["ok", "skipped", "failed"] = "skipped",
) -> str:
    """Assemble the full report.md content in a fixed section order.

    Header (traceability fields incl. authorization/purpose) → collector
    status → delta → inventory → relationships → errors → synthesis. The
    order is part of the operator contract; sections are always present.
    """
    started = _ensure_utc(data.run_started_at).astimezone(UTC).isoformat()
    finished = (
        _ensure_utc(data.run_finished_at).astimezone(UTC).isoformat()
        if data.run_finished_at
        else "-"
    )
    lines = [
        _msg("title", lang),
        "",
        f"- **{_msg('target', lang)}:** `{data.target_id}` ({data.target_fqdn})",
        f"- **{_msg('run_id', lang)}:** `{data.run_id}`",
        f"- **{_msg('status', lang)}:** `{data.run_status}`",
        f"- **{_msg('started_at', lang)}:** `{started}`",
        f"- **{_msg('finished_at', lang)}:** `{finished}`",
        f"- **{_msg('authorization', lang)}:** {data.authorization}",
        f"- **{_msg('purpose', lang)}:** {data.purpose}",
        "",
        *_synthesis_section(finding, lang, synthesis_status),
        "",
        _msg("collectors", lang),
        *_collector_table(data, lang),
        "",
        *_new_section(data.observables, lang),
        "",
        *_inventory_section(data.observables, lang),
        "",
        *_relationships_section(bundle, lang),
        "",
        *_qualified_evidence_section(data.evidence, lang),
        "",
        *_errors_section(data.errors, lang),
        "",
    ]
    return "\n".join(lines)


def _write_json(path: Path, payload: Any) -> None:
    """Write JSON deterministically: sorted keys, compact separators, no ASCII escapes."""
    content = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )
    path.write_text(f"{content}\n", encoding="utf-8")


def _json_default(value: Any) -> Any:
    """json.dumps fallback: ISO-format datetimes, str() anything else."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _write_optional_pdf(path: Path, markdown: str, *, created_at: datetime | None = None) -> None:
    """Render a readable Unicode PDF, resetting the cursor after every block.

    Fonts are bundled so Docker and local runs use the same licensed typeface.
    Failure remains best-effort here; the pipeline records an incomplete report
    if the PDF was not produced. Existing sealed artifacts are never rewritten.
    """
    try:
        import re

        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
        from fpdf.fonts import TTFFont

        fonts = Path(__file__).parent / "fonts"
        pdf = FPDF()
        pdf.set_margins(16, 16, 16)
        pdf.set_auto_page_break(auto=True, margin=16)
        pdf.add_font("Report", fname=str(fonts / "DejaVuSans.ttf"))
        pdf.add_font("Report", style="B", fname=str(fonts / "DejaVuSans-Bold.ttf"))
        pdf.add_page()
        for raw in markdown.splitlines():
            if not raw.strip():
                pdf.ln(3)
                continue
            heading = raw.startswith("#")
            # Preserve the destination of every citation when removing markup.
            line = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", raw)
            line = line.lstrip("# ") if heading else line
            line = line.replace("`", "").replace("**", "").expandtabs(4)
            if re.fullmatch(r"[|: \-]+", line):
                continue
            pdf.set_font("Report", style="B" if heading else "", size=14 if heading else 10)
            assert isinstance(pdf.current_font, TTFFont)
            if any(ord(character) not in pdf.current_font.cmap for character in line):
                raise ValueError("Report contains characters unsupported by the bundled font")
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=6, text=line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_creation_date(_ensure_utc(created_at) if created_at else datetime.now(UTC))
        pdf.output(str(path))
    except Exception as exc:  # noqa: BLE001 — the caller checks the required artifact
        logger.warning("PDF generation failed: %s", exc)


def _read_index_rows(path: Path) -> dict[str, tuple[str, str, str, str]]:
    """Return {target_id: (status, new_count, risk_level, report_link)}."""
    if not path.exists():
        return {}
    rows: dict[str, tuple[str, str, str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        parts = [p.strip() for p in line.strip().split("|")[1:-1]]
        if parts[0].lower() in {"objetivo", "target"}:
            continue
        if len(parts) == 5:
            rows[parts[0]] = (parts[1], parts[2], parts[3], parts[4])
    return rows


def _write_daily_index(
    date_dir: Path,
    target_id: str,
    run_id: int,
    run_status: str,
    new_count: int,
    risk_level: str,
    lang: str,
) -> None:
    """Update daily_reports/YYYY-MM-DD/index.md with this target's latest row.

    Existing rows are parsed back from the file, replaced per target and
    rewritten sorted, so the index survives multiple targets finishing in any
    order.
    """
    index_path = date_dir / "index.md"
    # Two targets finishing in the same minute rewrite the same file; without
    # the lock the second read-modify-write silently drops the first row.
    with _index_lock(date_dir):
        _rewrite_daily_index(index_path, target_id, run_id, run_status, new_count, risk_level, lang)


@contextlib.contextmanager
def _index_lock(date_dir: Path):
    with open(date_dir / ".index.lock", "a", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_UN)


def _rewrite_daily_index(
    index_path: Path,
    target_id: str,
    run_id: int,
    run_status: str,
    new_count: int,
    risk_level: str,
    lang: str,
) -> None:
    rows = _read_index_rows(index_path)
    link_text = _msg("index_view", lang)
    rows[target_id] = (
        run_status,
        str(new_count),
        risk_level,
        f"[{link_text}](./{target_id}/run-{run_id}/report.md)",
    )

    lines = [
        _msg("index_title", lang),
        "",
        (
            f"| {_msg('index_target', lang)} | {_msg('index_status', lang)} |"
            f" {_msg('index_new', lang)} | {_msg('index_risk', lang)} |"
            f" {_msg('index_report', lang)} |"
        ),
        "|---|---|---:|---|---|",
    ]
    for key in sorted(rows):
        status, count, risk, report = rows[key]
        lines.append(f"| {key} | {status} | {count} | {risk} | {report} |")
    lines.append("")
    index_path.write_text("\n".join(lines), encoding="utf-8")


async def generate_report(
    data: RunReportData,
    report_dir: str = "daily_reports",
    language: str | None = None,
    finding: Finding | None = None,
    synthesis_status: Literal["ok", "skipped", "failed"] = "skipped",
) -> Path:
    """
    Generate deterministic report artifacts from run data only.

    Reporting never calls collectors and never queries OpenCTI.
    *finding* is the synthesized Finding for the synthesis section; if None,
    the section renders a message based on *synthesis_status*:
    "skipped" when no provider is configured, "failed" when the LLM call
    errored.
    """
    lang = resolve_language(language or data.language)
    day = _bundle_date(data.run_started_at)
    # One directory per run: runs of the same target on the same day (manual
    # runs, retries) must not overwrite each other's evidence.
    date_dir = Path(report_dir) / day
    base = date_dir / data.target_id / f"run-{data.run_id}"
    base.mkdir(parents=True, exist_ok=True)

    merged_bundle = _merge_bundles(data.bundles)
    observables = sorted(data.observables, key=lambda o: (o.stix_type, o.value, o.stix_id))
    delta = [
        {"stix_id": o.stix_id, "stix_type": o.stix_type, "value": o.value}
        for o in observables
        if o.is_new
    ]

    report_md = _markdown_content(data, merged_bundle, lang, finding, synthesis_status)
    report_md_path = base / "report.md"
    bundle_path = base / "bundle.stix.json"
    delta_path = base / "delta.json"
    pdf_path = base / "report.pdf"

    report_md_path.write_text(report_md, encoding="utf-8")
    _write_json(bundle_path, merged_bundle)
    _write_json(delta_path, delta)
    _write_optional_pdf(pdf_path, report_md, created_at=data.run_finished_at or data.run_started_at)
    risk_level = finding.risk_level if finding is not None else "—"
    _write_daily_index(
        date_dir, data.target_id, data.run_id, data.run_status, len(delta), risk_level, lang
    )

    logger.info(
        "Report generated: run=%d target=%s path=%s",
        data.run_id,
        data.target_id,
        report_md_path,
    )
    return report_md_path
