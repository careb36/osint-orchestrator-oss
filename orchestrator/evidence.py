"""Signed per-run evidence manifests and target-to-target chain verification."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
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


def _iso_utc(value: datetime) -> str:
    """ISO 8601 in UTC; a naive datetime (SQLite) is UTC, never host-local time.

    ``datetime.astimezone()`` on a naive value assumes the host's zone, which
    would make the same run produce different manifests on different hosts.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


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
        started_at = _iso_utc(started_at)
    if isinstance(finished_at, datetime):
        finished_at = _iso_utc(finished_at)

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


def split_keys(raw: str) -> tuple[str, ...]:
    """Keys from a comma-separated setting, blanks dropped (same rule as API keys)."""
    return tuple(key.strip() for key in raw.split(",") if key.strip())


def verify_manifest_payload(
    payload: dict[str, Any],
    *,
    secret_key: str,
    previous_keys: tuple[str, ...] = (),
) -> tuple[bool, str | None]:
    """Check a manifest payload's version and signature, returning (ok, reason).

    *previous_keys* are keys retired by a rotation: a manifest signed with any
    of them still verifies, so rotating the key does not turn every earlier
    run into a ``signature_key`` finding. New manifests are never signed with
    them (see pipeline).
    """
    version = payload.get("manifest_version")
    if version not in _SUPPORTED_MANIFEST_VERSIONS:
        return False, "unsupported_version"
    signature = payload.get("signature")
    if not isinstance(signature, str):
        return False, "signature"
    sanitized = {k: v for k, v in payload.items() if k != "signature"}
    for key in (secret_key, *previous_keys):
        if verify_signature(sanitized, secret_key=key, signature=signature):
            return True, None
    return False, "signature_key"


def _broken(run_id: int | None, reason: str, detail: str) -> dict[str, Any]:
    return {"first_broken_run_id": run_id, "reason": reason, "detail": detail}


def _check_sealed_run(
    run: Any,
    previous_manifest_sha256: str | None,
    secret_key: str,
    previous_keys: tuple[str, ...] = (),
):
    """Check one sealed run; return (broken_or_None, this_manifest_sha256)."""
    manifest_path = manifest_path_for_report(run.report_path)
    if manifest_path is None or not manifest_path.exists():
        return _broken(run.id, "manifest_missing", "manifest.json"), None
    # The stored hash first: a manifest whose bytes changed was edited after
    # the run (reason "signature"); a manifest that is byte-identical to what
    # the run stored but fails the HMAC was signed with another key
    # ("signature_key"), which is what a key rotation looks like.
    actual_sha256 = sha256_file(manifest_path)
    if actual_sha256 != run.manifest_sha256:
        return _broken(run.id, "signature", "manifest.json"), None
    try:
        payload = load_manifest_file(manifest_path)
    except (json.JSONDecodeError, OSError, ValueError):
        return _broken(run.id, "signature", "manifest.json"), None
    if payload.get("manifest_version") not in _SUPPORTED_MANIFEST_VERSIONS:
        return _broken(run.id, "unsupported_version", str(payload.get("manifest_version"))), None
    ok, sig_reason = verify_manifest_payload(
        payload, secret_key=secret_key, previous_keys=previous_keys
    )
    if not ok:
        return _broken(run.id, sig_reason or "signature", "manifest.json"), None
    if payload.get("previous_manifest_sha256") != previous_manifest_sha256:
        return _broken(run.id, "chain_link", str(payload.get("previous_manifest_sha256"))), None
    artefacts = payload.get("artefacts")
    if not isinstance(artefacts, dict):
        return _broken(run.id, "artefact_hash", "artefacts"), None
    for name, expected_hash in sorted(artefacts.items()):
        file_path = manifest_path.parent / str(name)
        if not file_path.exists():
            return _broken(run.id, "artefact_missing", str(name)), None
        if sha256_file(file_path) != expected_hash:
            return _broken(run.id, "artefact_hash", str(name)), None
    return None, actual_sha256


async def verify_target_chain(
    *,
    target_id: str,
    secret_key: str,
    session: Any,
    previous_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Verify a target's manifest chain (ADR-007 §4), oldest sealed run first.

    Unsealed runs (no ``manifest_sha256``) are counted, never treated as
    tampering. When retention has purged the oldest runs, the oldest retained
    sealed run links to a manifest whose row no longer exists: the chain is
    verified from that run on and ``anchor_run_id`` /
    ``anchor_previous_manifest_sha256`` say where, so an auditor holding the
    archived manifests can check the earlier part offline.
    """
    from sqlmodel import select  # noqa: PLC0415 — keep this module import-light

    from orchestrator.models import Run  # noqa: PLC0415

    result = await session.exec(
        select(Run).where(Run.target_id == target_id).order_by(Run.started_at.asc(), Run.id.asc())
    )
    runs = result.all()
    retained_hashes = {run.manifest_sha256 for run in runs if run.manifest_sha256}

    checked = 0
    unsealed = 0
    broken: dict[str, Any] | None = None
    previous_manifest_sha256: str | None = None
    anchor_run_id: int | None = None
    anchor_previous: str | None = None

    for run in runs:
        if run.manifest_sha256 is None:
            unsealed += 1
            continue
        if checked == 0:
            # First sealed run still on record: accept a link to a manifest
            # whose run row retention has removed (it cannot be checked here).
            manifest_path = manifest_path_for_report(run.report_path)
            with contextlib.suppress(OSError, ValueError, json.JSONDecodeError):
                if manifest_path is not None and manifest_path.exists():
                    link = load_manifest_file(manifest_path).get("previous_manifest_sha256")
                    if link is not None and link not in retained_hashes:
                        previous_manifest_sha256 = link
                        anchor_run_id = run.id
                        anchor_previous = link
        checked += 1
        broken, this_sha256 = _check_sealed_run(
            run, previous_manifest_sha256, secret_key, previous_keys=previous_keys
        )
        if broken is not None:
            break
        previous_manifest_sha256 = this_sha256

    response: dict[str, Any] = {
        "ok": broken is None,
        "checked": checked,
        "unsealed": unsealed,
        "first_broken_run_id": None,
        "reason": None,
        "detail": None,
        "anchor_run_id": anchor_run_id,
        "anchor_previous_manifest_sha256": anchor_previous,
    }
    if broken is not None:
        response.update(broken)
    return response
