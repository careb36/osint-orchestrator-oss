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


_VALID_BLOCK = """
        targets:
          - id: acme
            fqdn: acme.example.com
            authorization: self-owned
            purpose: test
"""


def test_load_targets_keeps_the_first_block_of_a_duplicate_id(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: acme
            fqdn: first.example.com
            authorization: self-owned
            purpose: test
          - id: acme
            fqdn: second.example.com
            authorization: self-owned
            purpose: test
        """,
    )
    targets, errors = load_targets(str(path))
    assert [(target.id, target.fqdn) for target in targets] == [("acme", "first.example.com")]
    assert errors == ["acme"]


def test_load_targets_rejects_a_misspelt_key_instead_of_using_the_default(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: acme
            enabeld: false
            fqdn: acme.example.com
            authorization: self-owned
            purpose: test
          - id: beta
            fqdn: beta.example.com
            authorization: self-owned
            purpose: test
            schedule:
              corn: "0 9 * * *"
          - id: gamma
            fqdn: gamma.example.com
            authorization: self-owned
            purpose: test
            collectors:
              spiderfoot:
                modlues: [sfp_whois]
        """,
    )
    targets, errors = load_targets(str(path))
    assert targets == []
    assert errors == ["acme", "beta", "gamma"]


def test_load_targets_rejects_a_non_positive_misfire_grace(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: acme
            fqdn: acme.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "0 8 * * *"
              misfire_grace_time_seconds: 0
        """,
    )
    targets, errors = load_targets(str(path))
    assert targets == []
    assert errors == ["acme"]


def test_load_targets_rejects_a_targets_key_that_is_not_a_list(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(path, "targets:\n  id: acme\n")
    targets, errors = load_targets(str(path))
    assert targets == []
    assert errors == ["<targets-file>"]


def test_load_targets_reports_a_non_mapping_entry_by_index(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(path, _VALID_BLOCK + "          - just-a-string\n")
    targets, errors = load_targets(str(path))
    assert [target.id for target in targets] == ["acme"]
    assert errors == ["<index 1>"]
