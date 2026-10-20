"""
The investigation-assistant worker overlay (ADR-011, issue #102).

The worker is a one-shot container built from the producer's own clone that
exports one case and posts its bundle to ``POST /bundles``. These tests pin the
properties a later edit could silently break: where the key comes from, that
the case corpus stays read-only, and that the worker only talks to a healthy
orchestrator over the compose network.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINE_COMPOSE = REPO_ROOT / "docker-compose.engine.yml"
BASE_COMPOSE = REPO_ROOT / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"


def _services(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))["services"]


def _worker() -> dict:
    return _services(ENGINE_COMPOSE)["investigation-engine"]


def test_base_compose_has_no_worker() -> None:
    """Required variables of the overlay must never block a plain `docker compose up`."""
    assert "investigation-engine" not in _services(BASE_COMPOSE)


def test_worker_is_opt_in_and_one_shot() -> None:
    worker = _worker()
    assert worker["profiles"] == ["engine"]
    assert worker["restart"] == "no"


def test_worker_is_built_from_the_producer_clone_with_an_explicit_tag() -> None:
    worker = _worker()
    assert worker["build"]["context"] == "${INVESTIGATION_ASSISTANT_DIR:?}"
    assert worker["build"]["args"] == {"EXTRAS": "stix"}
    name, _, tag = worker["image"].rpartition(":")
    assert name == "investigation-assistant"
    assert tag and tag != "latest"


def test_api_key_comes_from_the_environment_and_is_required() -> None:
    environment = _worker()["environment"]
    assert environment["INVESTIGAR_ORCHESTRATOR_API_KEY"] == "${INVESTIGAR_ORCHESTRATOR_API_KEY:?}"
    command = " ".join(_worker()["command"])
    assert "API_KEY" not in command, "the key must never be on the command line"


def test_case_corpus_is_mounted_read_only_and_worked_on_in_tmpfs() -> None:
    worker = _worker()
    assert worker["volumes"] == ["${INVESTIGATION_ASSISTANT_DIR:?}/cases:/cases:ro"]
    assert worker["tmpfs"] == ["/data/cases:uid=1000,gid=1000,mode=0700"]
    script = worker["command"][0]
    assert 'cp -R "/cases/$$INVESTIGATION_CASE" /data/cases/' in script
    assert "--cases-dir /data/cases" in script


def test_worker_posts_to_a_healthy_orchestrator_on_the_compose_network() -> None:
    worker = _worker()
    assert worker["depends_on"] == {"orchestrator": {"condition": "service_healthy"}}
    assert worker["command"][0].rstrip().endswith("--ingest http://orchestrator:8000")
    orchestrator = _services(BASE_COMPOSE)["orchestrator"]
    assert any(str(port).endswith(":8000") for port in orchestrator["ports"])


def test_case_slug_is_expanded_by_the_container_shell_not_by_compose() -> None:
    """A single `$` would be interpolated from the host when the file is loaded."""
    script = _worker()["command"][0]
    assert re.findall(r"(?<!\$)\$(?!\$)", script) == []
    assert script.count("$$INVESTIGATION_CASE") == 3  # cp, run, export-stix
    assert _worker()["environment"]["INVESTIGATION_CASE"] == "${INVESTIGATION_CASE:-demo_simulado}"


def test_env_example_documents_the_worker_variables() -> None:
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    for line in (
        "INVESTIGATION_ASSISTANT_DIR=",
        "INVESTIGATION_CASE=demo_simulado",
        "INVESTIGAR_ORCHESTRATOR_API_KEY=",
    ):
        assert re.search(rf"^{re.escape(line)}$", env, re.MULTILINE), line
