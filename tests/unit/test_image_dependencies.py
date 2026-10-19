"""
Guard tests for what the Docker image installs.

CI installs only the ``dev`` extra, so a regression in the image (the ``llm``
extra dropped, ``pip install .`` restored, pycti drifting from the platform)
would otherwise go unnoticed until a real run fails. These tests read the
build files; they need no network and no Docker.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import tomllib

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).parents[2]
DOCKERFILE = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _requirement_names(requirements: list[str]) -> set[str]:
    return {re.split(r"[<>=!~ @\[]", req, maxsplit=1)[0].lower() for req in requirements}


def test_llm_extra_declares_the_cloud_provider_sdks() -> None:
    extra = PYPROJECT["project"]["optional-dependencies"]["llm"]
    assert {"openai", "anthropic"} <= _requirement_names(extra)


def test_image_installs_the_llm_extra() -> None:
    # Without it every openai/nebius/anthropic synthesis fails at runtime.
    assert re.search(r'pip install [^\n]*"\.\[llm\]"', DOCKERFILE)


def _pycti_release_for(platform_tag: str) -> str:
    """The pycti release that ships with an ``opencti/platform`` tag.

    Rolling releases share the tag verbatim (``6.8.11``); an LTS tag
    ``7.260811.0-lts.1`` is published on PyPI as ``7.260811.0.1``.
    """
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-lts\.(\d+))?", platform_tag)
    assert match, f"unexpected platform tag {platform_tag!r}"
    base, lts = match.groups()
    return f"{base}.{lts}" if lts else base


def test_pycti_pin_matches_the_opencti_platform_tag() -> None:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    platform_tag = compose["services"]["opencti"]["image"].rsplit(":", 1)[1]
    pins = [req for req in PYPROJECT["project"]["dependencies"] if req.lower().startswith("pycti")]

    assert pins == [f"pycti=={_pycti_release_for(platform_tag)}"]


@pytest.mark.parametrize(
    ("tag", "release"),
    [("6.8.11", "6.8.11"), ("7.260811.0", "7.260811.0"), ("7.260811.0-lts.1", "7.260811.0.1")],
)
def test_pycti_release_mapping(tag: str, release: str) -> None:
    assert _pycti_release_for(tag) == release


@pytest.mark.parametrize("module", ["openai", "anthropic"])
def test_provider_sdk_importable_when_installed(module: str) -> None:
    """Meaningful inside the image (where the extra is installed), skipped elsewhere."""
    if importlib.util.find_spec(module) is None:
        pytest.skip(f"{module} not installed (llm extra absent in this environment)")
    __import__(module)
