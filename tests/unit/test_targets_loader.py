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


def test_restricted_target_must_use_the_local_model(tmp_path: Path) -> None:
    """A restricted investigation never reaches a cloud provider: the block is
    rejected at load time instead of silently sending its prompts away."""
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: on-premises
            fqdn: onprem.example.com
            authorization: self-owned
            purpose: test
            classification: restricted
            llm: local
          - id: leaky
            fqdn: leaky.example.com
            authorization: self-owned
            purpose: test
            classification: restricted
            llm: nebius
          - id: open
            fqdn: open.example.com
            authorization: self-owned
            purpose: test
            llm: nebius
        """,
    )
    targets, errors = load_targets(str(path))
    assert [target.id for target in targets] == ["on-premises", "open"]
    assert errors == ["leaky"]
    assert targets[0].classification == "restricted"
    assert targets[1].classification == "osint"  # the default: open sources


def _restricted(**overrides):
    from orchestrator.models import Target

    fields = {
        "id": "x",
        "fqdn": "x.example",
        "authorization": "a",
        "purpose": "p",
        "classification": "restricted",
    }
    return Target(**{**fields, **overrides})


def test_restricted_validation_names_the_provider() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=r"requires llm: local, got llm: anthropic"):
        _restricted(llm="anthropic")


def test_restricted_target_cannot_use_socialosint_or_tavily_answers() -> None:
    """Both reach a hosted model by another road than ``llm``: SocialOSINT
    runs its own LLM analysis and Tavily writes ``include_answer`` with its
    own model."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="collectors.socialosint"):
        _restricted(collectors={"socialosint": {"enabled": True}})
    with pytest.raises(ValidationError, match="include_answer"):
        _restricted(collectors={"tavily": {"enabled": True, "include_answer": True}})
    # Plain Tavily searches are collection, not analysis: still allowed.
    assert _restricted(collectors={"tavily": {"enabled": True}}).classification == "restricted"


def test_effective_provider_follows_the_global_switches(monkeypatch) -> None:
    """The report and the console show where the prompts actually go, which
    LLM_PROVIDER can change: ``none`` turns synthesis off and ``nebius``
    remaps ``llm: openai``."""
    from orchestrator.models import Target
    from orchestrator.synthesizer.providers import effective_provider

    def target(llm: str) -> Target:
        return Target(id="t", fqdn="t.example", authorization="a", purpose="p", llm=llm)

    monkeypatch.setattr(settings, "llm_provider", "ollama")
    assert [effective_provider(target(x)) for x in ("local", "openai", "nebius", "anthropic")] == [
        "ollama",
        "openai",
        "nebius",
        "anthropic",
    ]
    monkeypatch.setattr(settings, "llm_provider", "nebius")
    assert effective_provider(target("openai")) == "nebius"
    assert effective_provider(target("local")) == "ollama"
    monkeypatch.setattr(settings, "llm_provider", "none")
    assert effective_provider(target("local")) == "none"
    assert effective_provider(target("nebius")) == "none"


def test_api_target_payload_carries_the_effective_provider(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    _write(
        path,
        """
        targets:
          - id: remapped
            fqdn: remapped.example.com
            authorization: self-owned
            purpose: test
            llm: openai
        """,
    )
    monkeypatch.setattr(settings, "targets_file", str(path))
    monkeypatch.setattr(settings, "llm_provider", "nebius")
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app) as client:
        listed = client.get("/targets").json()
        single = client.get("/targets/remapped").json()
    assert listed[0]["processing"] == single["processing"] == "nebius"
    assert single["llm"] == "openai"
