from pathlib import Path

import yaml

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
MISP_ENTRYPOINT = Path(__file__).resolve().parents[2] / "deploy/misp/entrypoint.sh"


def test_misp_uses_its_dedicated_passwordless_redis() -> None:
    services = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))["services"]
    environment = services["misp"]["environment"]

    assert environment["REDIS_HOST"] == "misp-redis"
    assert environment["REDIS_PORT"] == 6379
    assert environment["ENABLE_REDIS_EMPTY_PASSWORD"] == "true"
    assert "REDIS_PASSWORD" not in environment
    assert "REDIS_FQDN" not in environment


def test_misp_uses_the_passwordless_backport_image() -> None:
    services = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))["services"]

    assert services["misp"]["build"]["dockerfile"] == "Dockerfile.misp"
    assert services["misp"]["image"].endswith(":v2.4.198-passwordless")
    assert services["misp-modules"]["image"].endswith(":v2.4.198")


def test_misp_backport_updates_persisted_redis_settings() -> None:
    entrypoint = MISP_ENTRYPOINT.read_text(encoding="utf-8")

    assert "('redis_host' => )" in entrypoint
    assert "('redis_password' => )" in entrypoint
