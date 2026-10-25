"""Shared-practice dossiers, professional review and immutable report versions."""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import update
from sqlmodel import col, select

from orchestrator.auth import require_api_key, require_person
from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.evidence import canonical_json, split_keys, verify_target_chain
from orchestrator.i18n import resolve_language, t
from orchestrator.models import (
    Dossier,
    DossierEvent,
    DossierReport,
    DossierRun,
    EvidenceQualification,
    EvidenceReview,
    FindingRecord,
    Run,
)
from orchestrator.reports import _write_optional_pdf

router = APIRouter(prefix="/cases", dependencies=[Depends(require_api_key)])


class DossierBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    entity_name: str = Field(min_length=1, max_length=200)
    entity_type: Literal["person", "company"]
    identifier: str = Field(default="", max_length=100)
    country: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=1, max_length=2000)

    @field_validator("title", "entity_name", "country", "purpose")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class RevisionBody(BaseModel):
    revision: int = Field(ge=1)


class DossierUpdate(DossierBody, RevisionBody):
    pass


class SourceBody(RevisionBody):
    run_id: int = Field(ge=1)


class ReviewBody(RevisionBody):
    evidence_id: int = Field(ge=1)
    decision: Literal["confirmed", "dismissed"]
    reason: str = Field(min_length=10, max_length=2000)


class FinalBody(RevisionBody):
    risk_level: Literal["unknown", "low", "medium", "high", "critical"]
    conclusion: str = Field(min_length=20, max_length=8000)
    acknowledge_limitations: Literal[True]


class ReopenBody(RevisionBody):
    reason: str = Field(min_length=10, max_length=2000)


async def _get(session, case_id: int) -> Dossier:
    dossier = await session.get(Dossier, case_id)
    if not dossier:
        raise HTTPException(404, t("case_missing"))
    return dossier


async def _advance(session, dossier: Dossier, revision: int, state="in_review", reopen=False):
    if dossier.revision != revision or (dossier.state == "finalized" and not reopen):
        raise HTTPException(409, t("case_conflict"))
    result = await session.exec(
        update(Dossier)
        .where(col(Dossier.id) == dossier.id, col(Dossier.revision) == revision)
        .values(revision=revision + 1, state=state)
    )
    if result.rowcount != 1:
        raise HTTPException(409, t("case_conflict"))


def _event(session, case_id: int, actor: dict, action: str, details: dict):
    session.add(
        DossierEvent(
            dossier_id=case_id,
            actor_id=actor["id"],
            actor_name=actor["display_name"],
            action=action,
            details_json=canonical_json(details),
        )
    )


def _reviewer(request: Request) -> dict:
    actor = require_person(request)
    if actor["role"] != "accountant":
        raise HTTPException(403, t("reviewer_required"))
    return actor


async def _sources(session, case_id: int):
    ids = (
        await session.exec(select(DossierRun.run_id).where(DossierRun.dossier_id == case_id))
    ).all()
    runs = list((await session.exec(select(Run).where(col(Run.id).in_(ids)))).all()) if ids else []
    evidence = (
        list(
            (
                await session.exec(
                    select(EvidenceQualification).where(col(EvidenceQualification.run_id).in_(ids))
                )
            ).all()
        )
        if ids
        else []
    )
    return runs, evidence


@router.get("")
async def list_cases(request: Request, limit: int = 100, offset: int = 0):
    require_person(request)
    if not 1 <= limit <= 200 or offset < 0:
        raise HTTPException(422, t("case_reason"))
    async with get_session() as session:
        return (
            await session.exec(
                select(Dossier).order_by(col(Dossier.id).desc()).offset(offset).limit(limit)
            )
        ).all()


@router.post("", status_code=201)
async def create_case(body: DossierBody, request: Request):
    actor = require_person(request)
    async with get_session() as session:
        dossier = Dossier(**body.model_dump(), owner_id=actor["id"])
        session.add(dossier)
        await session.flush()
        assert dossier.id is not None
        _event(session, dossier.id, actor, "created", body.model_dump())
        await session.commit()
        await session.refresh(dossier)
        return dossier


@router.get("/{case_id}")
async def get_case(case_id: int, request: Request):
    require_person(request)
    async with get_session() as session:
        dossier = await _get(session, case_id)
        runs, evidence = await _sources(session, case_id)
        reviews = (
            await session.exec(select(EvidenceReview).where(EvidenceReview.dossier_id == case_id))
        ).all()
        events = (
            await session.exec(
                select(DossierEvent)
                .where(DossierEvent.dossier_id == case_id)
                .order_by(col(DossierEvent.id))
            )
        ).all()
        reports = (
            await session.exec(
                select(DossierReport.id, DossierReport.version, DossierReport.created_at)
                .where(DossierReport.dossier_id == case_id)
                .order_by(col(DossierReport.version))
            )
        ).all()
        return {
            "case": dossier.model_dump(),
            "runs": [r.model_dump() for r in runs],
            "evidence": [e.model_dump() for e in evidence],
            "reviews": [r.model_dump() for r in reviews],
            "events": [dict(e.model_dump(), details=json.loads(e.details_json)) for e in events],
            "reports": [
                {"version": version, "created_at": created} for _, version, created in reports
            ],
        }


@router.post("/{case_id}")
async def edit_case(case_id: int, body: DossierUpdate, request: Request):
    actor = require_person(request)
    async with get_session() as session:
        dossier = await _get(session, case_id)
        await _advance(session, dossier, body.revision)
        changes = body.model_dump(exclude={"revision"})
        for key, value in changes.items():
            setattr(dossier, key, value)
        session.add(dossier)
        _event(session, case_id, actor, "updated", changes)
        await session.commit()
        return {"revision": body.revision + 1}


@router.post("/{case_id}/sources")
async def attach_source(case_id: int, body: SourceBody, request: Request):
    actor = require_person(request)
    async with get_session() as session:
        dossier = await _get(session, case_id)
        if not await session.get(Run, body.run_id):
            raise HTTPException(422, t("case_source"))
        if (
            await session.exec(
                select(DossierRun.id).where(
                    DossierRun.dossier_id == case_id, DossierRun.run_id == body.run_id
                )
            )
        ).first():
            raise HTTPException(409, t("case_conflict"))
        await _advance(session, dossier, body.revision)
        session.add(DossierRun(dossier_id=case_id, run_id=body.run_id))
        _event(session, case_id, actor, "source_attached", {"run_id": body.run_id})
        await session.commit()
        return {"revision": body.revision + 1}


@router.post("/{case_id}/reviews")
async def review_evidence(case_id: int, body: ReviewBody, request: Request):
    actor = _reviewer(request)
    if len(body.reason.strip()) < 10:
        raise HTTPException(422, t("case_reason"))
    async with get_session() as session:
        dossier = await _get(session, case_id)
        _, evidence = await _sources(session, case_id)
        if body.evidence_id not in {e.id for e in evidence}:
            raise HTTPException(422, t("case_evidence"))
        await _advance(session, dossier, body.revision)
        review = (
            await session.exec(
                select(EvidenceReview).where(
                    EvidenceReview.dossier_id == case_id,
                    EvidenceReview.evidence_id == body.evidence_id,
                )
            )
        ).first()
        if review is None:
            review = EvidenceReview(
                dossier_id=case_id,
                evidence_id=body.evidence_id,
                decision=body.decision,
                reason=body.reason.strip(),
                actor_id=actor["id"],
            )
        else:
            review.decision, review.reason, review.actor_id = (
                body.decision,
                body.reason.strip(),
                actor["id"],
            )
        session.add(review)
        _event(session, case_id, actor, "evidence_reviewed", body.model_dump(exclude={"revision"}))
        await session.commit()
        return {"revision": body.revision + 1}


@router.post("/{case_id}/finalize", status_code=201)
async def finalize_case(case_id: int, body: FinalBody, request: Request):
    actor = _reviewer(request)
    if len(body.conclusion.strip()) < 20:
        raise HTTPException(422, t("case_reason"))
    async with get_session() as session:
        dossier = await _get(session, case_id)
        runs, evidence = await _sources(session, case_id)
        if not runs or any(
            r.status != "success"
            or r.collection_status != "ok"
            or r.qualification_status not in ("ok", "skipped")
            or r.synthesis_status not in ("ok", "skipped")
            or r.report_status != "ok"
            or r.integrity_status != "ok"
            for r in runs
        ):
            raise HTTPException(409, t("case_source"))
        reviews = (
            await session.exec(select(EvidenceReview).where(EvidenceReview.dossier_id == case_id))
        ).all()
        reviewed = {r.evidence_id for r in reviews}
        if any(e.id not in reviewed for e in evidence) or any(
            r.evidence_collected is None or r.evidence_qualified != r.evidence_collected
            for r in runs
        ):
            raise HTTPException(409, t("case_evidence"))
        for target_id in {r.target_id for r in runs}:
            check = await verify_target_chain(
                target_id=target_id,
                secret_key=settings.orchestrator_secret_key,
                session=session,
                previous_keys=split_keys(settings.orchestrator_secret_key_previous),
            )
            if not check["ok"] or not check["checked"]:
                raise HTTPException(409, t("case_integrity"))
        if settings.orchestrator_secret_key in ("", "insecure-dev-key"):
            raise HTTPException(409, t("case_integrity"))
        previous = (
            await session.exec(
                select(DossierReport.version)
                .where(DossierReport.dossier_id == case_id)
                .order_by(col(DossierReport.version).desc())
                .limit(1)
            )
        ).first()
        version = (previous or 0) + 1
        from datetime import UTC, datetime

        findings = (
            await session.exec(
                select(FindingRecord).where(col(FindingRecord.run_id).in_([r.id for r in runs]))
            )
        ).all()
        snapshot = {
            "case": dict(
                dossier.model_dump(mode="json"), state="finalized", revision=body.revision + 1
            ),
            "version": version,
            "approved_by": actor,
            "approved_at": datetime.now(UTC).isoformat(),
            "professional_decision": body.model_dump(exclude={"revision"}),
            "runs": [r.model_dump(mode="json") for r in runs],
            "evidence": [e.model_dump(mode="json") for e in evidence],
            "reviews": [r.model_dump(mode="json") for r in reviews],
            "automated_findings": [f.to_api_dict() for f in findings],
        }
        # Canonical JSON handles datetime values in model-dumped findings explicitly.
        snapshot_json = json.dumps(
            snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        )
        signature = hmac.new(
            settings.orchestrator_secret_key.encode(), snapshot_json.encode(), hashlib.sha256
        ).hexdigest()
        lang = resolve_language(
            request.headers.get("accept-language", "es").split(",")[0].split("-")[0]
        )
        text = _report_text(snapshot, lang)
        with tempfile.TemporaryDirectory(prefix="dossier-report-") as tmp:
            path = Path(tmp) / "report.pdf"
            _write_optional_pdf(path, text)
            if not path.is_file():
                raise HTTPException(503, t("case_source"))
            pdf = path.read_bytes()
        snapshot["pdf_sha256"] = hashlib.sha256(pdf).hexdigest()
        snapshot_json = json.dumps(
            snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        )
        signature = hmac.new(
            settings.orchestrator_secret_key.encode(), snapshot_json.encode(), hashlib.sha256
        ).hexdigest()
        await _advance(session, dossier, body.revision, state="finalized")
        session.add(
            DossierReport(
                dossier_id=case_id,
                version=version,
                snapshot_json=snapshot_json,
                markdown=text,
                pdf=pdf,
                signature=signature,
            )
        )
        _event(
            session,
            case_id,
            actor,
            "finalized",
            {
                "version": version,
                "risk_level": body.risk_level,
                "snapshot_sha256": hashlib.sha256(snapshot_json.encode()).hexdigest(),
            },
        )
        await session.commit()
        return {"version": version, "revision": body.revision + 1}


def _report_text(snapshot: dict, lang: str) -> str:
    case, decision = snapshot["case"], snapshot["professional_decision"]
    risk_label = t("dossier_risk_" + decision["risk_level"], language=lang)
    lines = [
        t("dossier_report_title", language=lang),
        "",
        case["entity_name"],
        f"{case['identifier']} · {case['country']}",
        case["purpose"],
        "",
        t("dossier_report_conclusion", language=lang),
        decision["conclusion"],
        f"{t('dossier_report_risk', language=lang)}: {risk_label}",
        "",
        f"{t('dossier_report_author', language=lang)}: {snapshot['approved_by']['display_name']}",
        f"{snapshot['approved_at']} · v{snapshot['version']}",
        "",
        t("dossier_report_limits", language=lang),
        "",
        t("dossier_report_evidence", language=lang),
    ]
    reviews = {r["evidence_id"]: r for r in snapshot["reviews"]}
    for item in snapshot["evidence"]:
        review = reviews[item["id"]]
        lines.extend(
            [
                f"## {item['title']}",
                item["url"],
                t(
                    "dossier_report_confirmed"
                    if review["decision"] == "confirmed"
                    else "dossier_report_dismissed",
                    language=lang,
                ),
                review["reason"],
                "",
            ]
        )
    lines.extend(
        [t("dossier_report_sources", language=lang)]
        + [f"#{r['id']} · {r['target_id']} · {r['manifest_sha256']}" for r in snapshot["runs"]]
    )
    return "\n".join(lines)


@router.post("/{case_id}/reopen")
async def reopen_case(case_id: int, body: ReopenBody, request: Request):
    actor = _reviewer(request)
    async with get_session() as session:
        dossier = await _get(session, case_id)
        if dossier.state != "finalized" or len(body.reason.strip()) < 10:
            raise HTTPException(409, t("case_conflict"))
        await _advance(session, dossier, body.revision, reopen=True)
        _event(session, case_id, actor, "reopened", {"reason": body.reason.strip()})
        await session.commit()
        return {"revision": body.revision + 1}


@router.get("/{case_id}/reports/{version}")
async def get_report(case_id: int, version: int, request: Request):
    require_person(request)
    async with get_session() as session:
        report = (
            await session.exec(
                select(DossierReport).where(
                    DossierReport.dossier_id == case_id, DossierReport.version == version
                )
            )
        ).first()
        if not report:
            raise HTTPException(404, t("case_missing"))
        verified = _verified(report)
        return {
            "snapshot": json.loads(report.snapshot_json),
            "markdown": report.markdown,
            "signature_verified": verified,
        }


@router.get("/{case_id}/reports/{version}/pdf")
async def get_pdf(case_id: int, version: int, request: Request):
    require_person(request)
    async with get_session() as session:
        report = (
            await session.exec(
                select(DossierReport).where(
                    DossierReport.dossier_id == case_id, DossierReport.version == version
                )
            )
        ).first()
        if not report:
            raise HTTPException(404, t("case_missing"))
        if not _verified(report):
            raise HTTPException(409, t("case_integrity"))
        return Response(
            report.pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="case-{case_id}-v{version}.pdf"',
                "Cache-Control": "no-store",
            },
        )


def _verified(report: DossierReport) -> bool:
    try:
        pdf_ok = hmac.compare_digest(
            json.loads(report.snapshot_json)["pdf_sha256"], hashlib.sha256(report.pdf).hexdigest()
        )
        return pdf_ok and any(
            hmac.compare_digest(
                report.signature,
                hmac.new(key.encode(), report.snapshot_json.encode(), hashlib.sha256).hexdigest(),
            )
            for key in [
                settings.orchestrator_secret_key,
                *split_keys(settings.orchestrator_secret_key_previous),
            ]
        )
    except (ValueError, KeyError, TypeError):
        return False
