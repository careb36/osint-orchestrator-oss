"""Unit tests for orchestrator.targets shared targets.yaml loader."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.targets import load_targets


def _write(path: Path, body: str) -> None:
    path.write_text(body.strip() + "\n", encoding="utf-8")


def test_load_targets_reports_missing_file(tmp_path: Path) -> None:
    targets, errors = load_targets(str(tmp_path / "missing.yaml"))
    assert targets == []
    assert errors == ["<targets-file>"]


def test_load_targets_reports_malformed_yaml(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("targets: [\n", encoding="utf-8")
    targets, errors = load_targets(str(path))
    assert targets == []
    assert errors == ["<targets-file>"]


def test_load_targets_skips_invalid_target_and_keeps_valid_ones(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: valid
            enabled: true
            fqdn: valid.example.com
            authorization: self-owned
            purpose: test
          - id: broken
            enabled: true
            purpose: test
          - id: second-valid
            enabled: true
            fqdn: second.example.com
            authorization: self-owned
            purpose: test
        """,
    )
    targets, errors = load_targets(str(path))
    assert [target.id for target in targets] == ["valid", "second-valid"]
    assert errors == ["broken"]


def test_api_targets_endpoint_skips_malformed_file_instead_of_500(
    monkeypatch, tmp_path: Path
) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("targets: [\n", encoding="utf-8")
    monkeypatch.setattr(settings, "targets_file", str(path))
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/targets")
    assert response.status_code == 200
    assert response.json() == []
