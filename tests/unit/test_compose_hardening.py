"""The compose stack as a production shape: nothing but the loopback interface,
pinned images, and a container that does not run as root."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = sorted(REPO_ROOT.glob("docker-compose*.yml"))
DOCKERFILE = REPO_ROOT / "Dockerfile"

# A tag with a patch component (8.0.6, 3.13.7-management, 6.8.11,
# RELEASE.2024-05-28T17-19-04Z, v2.4.198) or a digest. A two-component
# "8.0" floats with every patch release and is what this test rejects.
_PINNED = re.compile(
    r"^[^@:]+:(\d+\.\d+\.\d+|RELEASE\.|v\d+\.\d+\.\d+|[0-9a-f]{7,})|^[^@]+@sha256:"
)


def _services(path: Path) -> dict[str, dict]:
    return yaml.safe_load(path.read_text(encoding="utf-8")).get("services", {})


@pytest.mark.parametrize(
    "name",
    [
        "opencti",
        "worker",
        "connector-import-file-stix",
        "connector-opencti",
        "elasticsearch",
        "redis",
        "rabbitmq",
        "minio",
    ],
)
def test_opencti_stack_is_behind_the_opencti_profile(name: str) -> None:
    services = _services(REPO_ROOT / "docker-compose.yml")
    assert "opencti" in services[name].get("profiles", [])


def test_orchestrator_does_not_require_the_opencti_stack() -> None:
    services = _services(REPO_ROOT / "docker-compose.yml")
    dependencies = services["orchestrator"]["depends_on"]
    assert "redis" not in dependencies
    for name, dependency in dependencies.items():
        if "opencti" in services[name].get("profiles", []):
            assert dependency.get("required") is False
    assert dependencies["opencti"] == {"condition": "service_healthy", "required": False}
    assert dependencies["spiderfoot"] == {"condition": "service_healthy"}


@pytest.mark.parametrize("name", ["orchestrator", "spiderfoot"])
def test_core_services_have_no_profile(name: str) -> None:
    services = _services(REPO_ROOT / "docker-compose.yml")
    assert "profiles" not in services[name]


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=[p.name for p in COMPOSE_FILES])
def test_every_published_port_binds_the_loopback_interface(compose: Path) -> None:
    exposed = [
        (name, port)
        for name, service in _services(compose).items()
        for port in service.get("ports", [])
        if not str(port).startswith("127.0.0.1:")
    ]
    assert exposed == [], f"{compose.name}: ports published on every interface: {exposed}"


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=[p.name for p in COMPOSE_FILES])
def test_every_image_is_pinned_to_a_patch_release_or_digest(compose: Path) -> None:
    floating = [
        (name, service["image"])
        for name, service in _services(compose).items()
        if "image" in service and "build" not in service and not _PINNED.match(service["image"])
    ]
    assert floating == [], f"{compose.name}: floating image tags: {floating}"


def test_git_build_contexts_are_pinned_to_a_commit() -> None:
    unpinned = [
        (name, service["build"]["context"])
        for name, service in _services(REPO_ROOT / "docker-compose.yml").items()
        if isinstance(service.get("build"), dict)
        and str(service["build"].get("context", "")).startswith(("http://", "https://"))
        and not re.search(r"#[0-9a-f]{40}$", service["build"]["context"])
    ]
    assert unpinned == []


def test_image_runs_as_uid_1000() -> None:
    lines = [line.strip() for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()]
    user_lines = [line for line in lines if line.startswith("USER ")]
    assert user_lines == ["USER 1000"]
    assert lines.index("USER 1000") < lines.index(
        next(line for line in lines if line.startswith("CMD "))
    )


def test_image_keeps_the_database_in_the_directory_uid_1000_owns() -> None:
    """The application default (./orchestrator.db under /app) is root-owned and
    unwritable for uid 1000: the smoke test failed with "unable to open
    database file" until the image pointed the database at /app/data."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "ORCHESTRATOR_DATABASE_URL=sqlite+aiosqlite:////app/data/orchestrator.db" in text
    assert "chown -R 1000:1000 /app/daily_reports /app/data" in text
