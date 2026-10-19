"""
Edge paths of the evidence manifest and chain check (ADR-007).

``test_evidence_chain.py`` drives real pipeline runs and tampers with their
files. These tests craft manifests directly to reach the checks a pipeline
run cannot produce: a run row pointing nowhere, a stored hash of a file that
is not JSON, a correctly signed manifest whose artefact list is malformed.
Each must report a broken chain with a precise reason, never pass.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from orchestrator.evidence import (
    _check_sealed_run,
    build_manifest,
    load_manifest_file,
    manifest_path_for_report,
    sha256_file,
    sha256_hex,
    sign_payload,
    verify_manifest_payload,
    verify_signature,
    write_manifest_file,
)

_KEY = "test-key"


def _run(report_path: str | None, manifest_sha256: str | None, run_id: int = 1):
    return SimpleNamespace(id=run_id, report_path=report_path, manifest_sha256=manifest_sha256)


def _signed(**fields) -> dict:
    payload = build_manifest(
        run_id=1,
        target_id="t1",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at=None,
        status="success",
        collectors_run=["openosint"],
        artefacts={},
        previous_manifest_sha256=None,
        secret_key=_KEY,
    )
    payload.update(fields)
    payload["signature"] = sign_payload(payload, secret_key=_KEY)
    return payload


def _write(tmp_path: Path, payload: dict) -> tuple[str, str]:
    report = tmp_path / "report.md"
    report.write_text("# r", encoding="utf-8")
    return str(report), write_manifest_file(report_path=report, manifest=payload)


# ── Primitives ────────────────────────────────────────────────────────────────


def test_sha256_helpers_agree() -> None:
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_sha256_file_streams_the_file(tmp_path: Path) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"x" * 200_000)
    assert sha256_file(path) == "sha256:" + hashlib.sha256(b"x" * 200_000).hexdigest()


@pytest.mark.parametrize("signature", [None, "", "sha256:abc", "HMAC-SHA256:abc"])
def test_signature_without_the_hmac_prefix_never_verifies(signature: str | None) -> None:
    assert verify_signature({"a": 1}, secret_key=_KEY, signature=signature) is False


def test_manifest_paths_need_a_report_path(tmp_path: Path) -> None:
    assert manifest_path_for_report(None) is None
    assert manifest_path_for_report("") is None
    assert manifest_path_for_report(str(tmp_path / "r.md")) == tmp_path / "manifest.json"
    with pytest.raises(ValueError, match="report_path is required"):
        write_manifest_file(report_path=None, manifest={})


def test_a_manifest_must_be_a_json_object(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_manifest_file(path)


def test_payload_with_an_unknown_version_or_no_signature_is_rejected() -> None:
    assert verify_manifest_payload(_signed(manifest_version=2), secret_key=_KEY) == (
        False,
        "unsupported_version",
    )
    unsigned = _signed()
    unsigned["signature"] = 123
    assert verify_manifest_payload(unsigned, secret_key=_KEY) == (False, "signature")
    assert verify_manifest_payload(_signed(), secret_key=_KEY) == (True, None)


# ── One sealed run ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("report_path", [None, "missing/report.md"])
def test_a_sealed_run_without_its_manifest_is_broken(report_path: str | None) -> None:
    broken, sha = _check_sealed_run(_run(report_path, "sha256:00"), None, _KEY)
    assert broken == {
        "first_broken_run_id": 1,
        "reason": "manifest_missing",
        "detail": "manifest.json",
    }
    assert sha is None


def test_a_stored_hash_of_a_file_that_is_not_json_is_broken(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    manifest = tmp_path / "manifest.json"
    manifest.write_text("not json", encoding="utf-8")

    broken, _ = _check_sealed_run(_run(str(report), sha256_file(manifest)), None, _KEY)

    assert broken is not None and broken["reason"] == "signature"


def test_a_stored_hash_of_an_unsupported_version_is_reported_as_such(tmp_path: Path) -> None:
    report, sha = _write(tmp_path, _signed(manifest_version=99))

    broken, _ = _check_sealed_run(_run(report, sha), None, _KEY)

    assert broken is not None
    assert (broken["reason"], broken["detail"]) == ("unsupported_version", "99")


def test_a_signed_manifest_with_a_malformed_artefact_list_is_broken(tmp_path: Path) -> None:
    report, sha = _write(tmp_path, _signed(artefacts=["report.md"]))

    broken, _ = _check_sealed_run(_run(report, sha), None, _KEY)

    assert broken is not None
    assert (broken["reason"], broken["detail"]) == ("artefact_hash", "artefacts")


def test_a_wrong_previous_link_is_a_chain_break(tmp_path: Path) -> None:
    report, sha = _write(tmp_path, _signed(previous_manifest_sha256="sha256:aa"))

    broken, _ = _check_sealed_run(_run(report, sha), "sha256:bb", _KEY)

    assert broken is not None
    assert (broken["reason"], broken["detail"]) == ("chain_link", "sha256:aa")


def test_an_intact_run_returns_its_manifest_hash(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# r", encoding="utf-8")
    payload = _signed(artefacts={"report.md": sha256_file(report)})
    sha = write_manifest_file(report_path=report, manifest=payload)

    assert _check_sealed_run(_run(str(report), sha), None, _KEY) == (None, sha)
    assert json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8")) == payload
