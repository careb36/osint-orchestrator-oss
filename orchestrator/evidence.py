"""Signed per-run evidence manifests and target-to-target chain verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1
_HASH_PREFIX = "sha256:"
_HMAC_PREFIX = "hmac-sha256:"
_SUPPORTED_MANIFEST_VERSIONS = frozenset({MANIFEST_VERSION})


def canonical_json(data: Any) -> str:
    """Canonical JSON for signatures and deterministic manifests."""
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(data: bytes) -> str:
    """Hex digest for byte content."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """Return a stable sha256:<hex> value for a file on disk."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return f"{_HASH_PREFIX}{digest.hexdigest()}"


def sign_payload(payload: dict[str, Any], *, secret_key: str) -> str:
    """Return the HMAC-SHA256 signature for the canonical payload without a signature."""
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    digest = hmac.new(
        secret_key.encode("utf-8"),
        canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    )
    return f"{_HMAC_PREFIX}{digest.hexdigest()}"


def verify_signature(payload: dict[str, Any], *, secret_key: str, signature: str | None) -> bool:
    """Return True when the manifest signature matches the configured key."""
    if not signature or not signature.startswith(_HMAC_PREFIX):
        return False
    expected = sign_payload(payload, secret_key=secret_key)
    return hmac.compare_digest(signature, expected)


def build_manifest(
    *,
    run_id: int,
    target_id: str,
    started_at: datetime | str,
    finished_at: datetime | str | None,
    status: str,
    collectors_run: list[str],
    artefacts: dict[str, str],
    previous_manifest_sha256: str | None,
    secret_key: str,
) -> dict[str, Any]:
    """Create a signed manifest payload without storing it to disk."""
    if isinstance(started_at, datetime):
        started_at = started_at.astimezone().isoformat()
    if isinstance(finished_at, datetime):
        finished_at = finished_at.astimezone().isoformat()

    payload: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id,
        "target_id": target_id,
        "started_at": str(started_at),
        "finished_at": str(finished_at) if finished_at is not None else None,
        "status": status,
        "collectors_run": list(collectors_run),
        "artefacts": dict(sorted(artefacts.items())),
        "previous_manifest_sha256": previous_manifest_sha256,
    }
    payload["signature"] = sign_payload(payload, secret_key=secret_key)
    return payload


def manifest_path_for_report(report_path: str | None) -> Path | None:
    """Path to the manifest.json in the same run directory as the report."""
    if not report_path:
        return None
    return Path(report_path).with_name("manifest.json")


def write_manifest_file(
    *,
    report_path: str | Path | None,
    manifest: dict[str, Any],
) -> str:
    """Write manifest.json and return its sha256:<hex> digest."""
    manifest_path = manifest_path_for_report(str(report_path) if report_path else None)
    if manifest_path is None:
        raise ValueError("report_path is required to write a manifest")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    return sha256_file(manifest_path)


def load_manifest_file(path: str | Path) -> dict[str, Any]:
    """Parse a manifest.json file from disk."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest payload must be a JSON object")
    return data


def verify_manifest_payload(payload: dict[str, Any], *, secret_key: str) -> tuple[bool, str | None]:
    """Check a manifest payload's version and signature, returning (ok, reason)."""
    version = payload.get("manifest_version")
    if version not in _SUPPORTED_MANIFEST_VERSIONS:
        return False, "unsupported_version"
    signature = payload.get("signature")
    if not isinstance(signature, str):
        return False, "signature"
    sanitized = {k: v for k, v in payload.items() if k != "signature"}
    if not verify_signature(sanitized, secret_key=secret_key, signature=signature):
        return False, "signature_key"
    return True, None


async def verify_target_chain(
    *,
    target_id: str,
    secret_key: str,
    session,
) -> dict[str, Any]:
    """Verify the manifest chain for a target, skipping unsealed runs."""
    from orchestrator.models import Run
    from sqlmodel import select

    result = await session.exec(
        select(Run)
        .where(Run.target_id == target_id)
        .order_by(Run.started_at.asc())
    )
    runs = result.all()
    checked = 0
    unsealed = 0
    previous_manifest_sha256: str | None = None
    first_broken_run_id: int | None = None
    reason: str | None = None
    detail: str | None = None

    for run in runs:
        if run.manifest_sha256 is None:
            unsealed += 1
            continue
        checked += 1
        manifest_path = manifest_path_for_report(run.report_path)
        if manifest_path is None or not manifest_path.exists():
            first_broken_run_id = run.id
            reason = "manifest_missing"
            detail = str(manifest_path.name if manifest_path else "manifest.json")
            break
        try:
            payload = load_manifest_file(manifest_path)
        except (json.JSONDecodeError, OSError, ValueError):
            first_broken_run_id = run.id
            reason = "manifest_missing"
            detail = manifest_path.name
            break
        if payload.get("manifest_version") not in _SUPPORTED_MANIFEST_VERSIONS:
            first_broken_run_id = run.id
            reason = "unsupported_version"
            detail = str(payload.get("manifest_version"))
            break
        if payload.get("previous_manifest_sha256") != previous_manifest_sha256:
            first_broken_run_id = run.id
            reason = "chain_link"
            detail = str(payload.get("previous_manifest_sha256"))
            break
        ok, sig_reason = verify_manifest_payload(payload, secret_key=secret_key)
        if not ok:
            first_broken_run_id = run.id
            reason = sig_reason or "signature"
            detail = str(payload.get("signature", ""))
            break
        artefacts = payload.get("artefacts")
        if not isinstance(artefacts, dict):
            first_broken_run_id = run.id
            reason = "artefact_hash"
            detail = "artefacts"
            break
        for name, expected_hash in artefacts.items():
            file_path = manifest_path.parent / str(name)
            if not file_path.exists():
                first_broken_run_id = run.id
                reason = "artefact_missing"
                detail = str(name)
                break
            actual = sha256_file(file_path)
            if actual != expected_hash:
                first_broken_run_id = run.id
                reason = "artefact_hash"
                detail = str(name)
                break
        if first_broken_run_id is not None:
            break
        actual_manifest_sha256 = sha256_file(manifest_path)
        if actual_manifest_sha256 != run.manifest_sha256:
            first_broken_run_id = run.id
            reason = "chain_link"
            detail = run.manifest_sha256 or "manifest_sha256"
            break
        previous_manifest_sha256 = actual_manifest_sha256

    return {
        "ok": first_broken_run_id is None,
        "checked": checked,
        "unsealed": unsealed,
        "first_broken_run_id": first_broken_run_id,
        "reason": reason,
        "detail": detail,
    }
