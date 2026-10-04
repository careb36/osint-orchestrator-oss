from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.scheduler import scheduler


def _write_targets(path: Path, body: str) -> None:
    path.write_text(body.strip() + "\n", encoding="utf-8")


@pytest.fixture
def clean_scheduler_jobs():
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
    yield
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)


def test_scheduler_reload_applies_edits_and_reports_invalid_targets(
    clean_scheduler_jobs, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets_file = tmp_path / "targets.yaml"
    _write_targets(
        targets_file,
        """
        targets:
          - id: alpha
            enabled: true
            fqdn: alpha.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "0 8 * * *"
              misfire_grace_time_seconds: 3600
        """,
    )
    monkeypatch.setattr(settings, "targets_file", str(targets_file))

    with TestClient(app) as client:
        _write_targets(
            targets_file,
            """
            targets:
              - id: alpha
                enabled: true
                fqdn: alpha.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "0 9 * * *"
                  misfire_grace_time_seconds: 3600
              - id: beta
                enabled: true
                fqdn: beta.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "15 10 * * *"
                  misfire_grace_time_seconds: 3600
              - id: gamma
                enabled: false
                fqdn: gamma.example.com
                authorization: self-owned
                purpose: test
              - id: bad-cron
                enabled: true
                fqdn: bad-cron.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "0 25 * * *"
                  misfire_grace_time_seconds: 3600
              - id: broken
                enabled: true
                purpose: test
            """,
        )

        resp = client.post("/scheduler/reload")

        assert resp.status_code == 200
        payload = resp.json()
        assert payload["status"] == "reloaded_with_errors"
        assert payload["added"] == 1
        assert payload["updated"] == 1
        assert payload["removed"] == 0
        assert payload["unchanged"] == 0
        assert payload["active_targets"] == 2
        assert payload["targets_loaded"] == 4
        assert payload["invalid_targets"] == ["bad-cron", "broken"]
        assert {job.id for job in scheduler.get_jobs() if job.id.startswith("target-")} == {
            "target-alpha",
            "target-beta",
        }


def test_scheduler_reload_is_noop_when_file_did_not_change(
    clean_scheduler_jobs, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets_file = tmp_path / "targets.yaml"
    _write_targets(
        targets_file,
        """
        targets:
          - id: alpha
            enabled: true
            fqdn: alpha.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "0 8 * * *"
              misfire_grace_time_seconds: 3600
          - id: beta
            enabled: true
            fqdn: beta.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "15 10 * * *"
              misfire_grace_time_seconds: 3600
        """,
    )
    monkeypatch.setattr(settings, "targets_file", str(targets_file))

    with TestClient(app) as client:
        resp = client.post("/scheduler/reload")

        assert resp.status_code == 200
        payload = resp.json()
        assert payload["status"] == "reloaded"
        assert payload["added"] == 0
        assert payload["updated"] == 0
        assert payload["removed"] == 0
        assert payload["unchanged"] == 2
        assert payload["active_targets"] == 2
        assert payload["targets_loaded"] == 2
        assert payload["invalid_targets"] == []


def test_scheduler_reload_keeps_existing_jobs_when_yaml_is_invalid(
    clean_scheduler_jobs, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets_file = tmp_path / "targets.yaml"
    _write_targets(
        targets_file,
        """
        targets:
          - id: alpha
            enabled: true
            fqdn: alpha.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "0 8 * * *"
              misfire_grace_time_seconds: 3600
        """,
    )
    monkeypatch.setattr(settings, "targets_file", str(targets_file))

    with TestClient(app) as client:
        targets_file.write_text("targets: [\n", encoding="utf-8")
        resp = client.post("/scheduler/reload")

        assert resp.status_code == 200
        payload = resp.json()
        assert payload["status"] == "reloaded_with_errors"
        assert payload["added"] == 0
        assert payload["updated"] == 0
        assert payload["removed"] == 0
        assert payload["unchanged"] == 1
        assert payload["active_targets"] == 1
        assert payload["targets_loaded"] == 0
        assert payload["invalid_targets"] == ["<targets-file>"]
        assert {job.id for job in scheduler.get_jobs() if job.id.startswith("target-")} == {
            "target-alpha"
        }


def test_scheduler_reload_preview_reports_changes_without_mutating_jobs(
    clean_scheduler_jobs, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    targets_file = tmp_path / "targets.yaml"
    _write_targets(
        targets_file,
        """
        targets:
          - id: alpha
            enabled: true
            fqdn: alpha.example.com
            authorization: self-owned
            purpose: test
            schedule:
              cron: "0 8 * * *"
              misfire_grace_time_seconds: 3600
        """,
    )
    monkeypatch.setattr(settings, "targets_file", str(targets_file))

    with TestClient(app) as client:
        # Startup loads alpha@08.
        _write_targets(
            targets_file,
            """
            targets:
              - id: alpha
                enabled: true
                fqdn: alpha.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "0 9 * * *"
                  misfire_grace_time_seconds: 3600
              - id: beta
                enabled: true
                fqdn: beta.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "15 10 * * *"
                  misfire_grace_time_seconds: 3600
              - id: bad-cron
                enabled: true
                fqdn: bad-cron.example.com
                authorization: self-owned
                purpose: test
                schedule:
                  cron: "0 25 * * *"
                  misfire_grace_time_seconds: 3600
            """,
        )
        resp = client.post("/scheduler/reload/preview")

        assert resp.status_code == 200
        payload = resp.json()
        assert payload["status"] == "preview_with_errors"
        assert payload["added"] == 1
        assert payload["updated"] == 1
        assert payload["removed"] == 0
        assert payload["unchanged"] == 0
        assert payload["active_targets"] == 2
        assert payload["targets_loaded"] == 3
        assert payload["invalid_targets"] == ["bad-cron"]

        # Preview must not mutate current scheduler state.
        assert {job.id for job in scheduler.get_jobs() if job.id.startswith("target-")} == {
            "target-alpha"
        }
        alpha_job = scheduler.get_job("target-alpha")
        assert alpha_job is not None
        assert "hour='8'" in str(alpha_job.trigger)
