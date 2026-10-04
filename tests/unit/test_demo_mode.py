"""Tests for demo-mode startup validation, scheduling and sanitization."""

from __future__ import annotations

import pytest

from orchestrator.config import settings
from orchestrator.demo import load_demo_targets, strip_demo_risk_fields, validate_demo_mode


@pytest.fixture
def demo_mode_env(monkeypatch: pytest.MonkeyPatch, tmp_path):
    target_file = tmp_path / "demo-targets.yaml"
    target_file.write_text(
        """
targets:
  - id: demo-one
    enabled: true
    fqdn: demo-one.example.com
    authorization: Public demo allowlist; demonstration only.
    purpose: Demo target
    collectors:
      openosint:
        enabled: true
      spiderfoot:
        enabled: true
    schedule:
      cron: "0 9 * * *"
      misfire_grace_time_seconds: 3600
  - id: demo-two
    enabled: false
    fqdn: demo-two.example.com
    authorization: Public demo allowlist; demonstration only.
    purpose: Demo target
    collectors:
      openosint:
        enabled: false
    schedule:
      cron: "0 10 * * *"
      misfire_grace_time_seconds: 3600
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "demo_targets_file", str(target_file))
    monkeypatch.setattr(settings, "demo_max_runs_per_ip_per_day", 2)
    monkeypatch.setattr(settings, "demo_max_runs_per_day", 5)
    monkeypatch.setattr(settings, "demo_tavily_calls_per_day", 100)
    monkeypatch.setattr(settings, "demo_llm_calls_per_day", 200)
    monkeypatch.setattr(settings, "demo_trusted_proxy_hops", 1)


def test_demo_targets_file_loads_and_filters_valid_entries(demo_mode_env) -> None:
    targets, invalid, failed = load_demo_targets(settings.demo_targets_file)
    assert failed is False
    assert [t.id for t in targets] == ["demo-one", "demo-two"]
    assert invalid == []


def test_demo_mode_validation_rejects_empty_or_invalid_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(settings, "demo_mode", True)
    monkeypatch.setattr(settings, "demo_targets_file", "")
    with pytest.raises(RuntimeError, match="DEMO_TARGETS_FILE"):
        validate_demo_mode()

    target_file = tmp_path / "demo-targets.yaml"
    target_file.write_text("targets: []\n", encoding="utf-8")
    monkeypatch.setattr(settings, "demo_targets_file", str(target_file))
    with pytest.raises(RuntimeError, match="empty"):
        validate_demo_mode()


def test_demo_public_payload_strips_risk_fields() -> None:
    payload = {
        "summary": "ok",
        "risk_level": "high",
        "risk_justification": "Needs review",
        "nested": {"risk_level": "critical", "value": "safe"},
        "items": [{"risk_justification": "strip me", "value": 1}],
    }
    assert strip_demo_risk_fields(payload) == {
        "summary": "ok",
        "nested": {"value": "safe"},
        "items": [{"value": 1}],
    }
