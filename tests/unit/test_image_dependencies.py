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
DOCKERFILE_MISP = (REPO_ROOT / "Dockerfile.misp").read_text(encoding="utf-8")
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


# ── Optional images ──────────────────────────────────────────────────────────
#
# Dockerfile.misp and Dockerfile.socialosint belong to the opt-in compose
# profiles, so nothing built them and nothing scanned them: a broken one (or a
# .dockerignore that drops what it copies) stayed invisible until an operator
# tried the profile. The workflow that covers them and the ignore file that
# feeds them are both easy to break silently, hence these guards.

DOCKER_PUBLISH = (REPO_ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(
    encoding="utf-8"
)
DOCKERIGNORE = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")


def _dockerignore_rules() -> list[str]:
    return [
        line.strip()
        for line in DOCKERIGNORE.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@pytest.mark.parametrize("dockerfile", ["Dockerfile.misp", "Dockerfile.socialosint"])
def test_optional_image_is_built_and_scanned_in_ci(dockerfile: str) -> None:
    assert (REPO_ROOT / dockerfile).is_file()
    workflow = yaml.safe_load(DOCKER_PUBLISH)
    job = workflow["jobs"]["optional-images"]
    matrix = job["strategy"]["matrix"]["include"]
    entry = next((e for e in matrix if e["dockerfile"] == dockerfile), None)
    assert entry, (
        f"{dockerfile} is not in the scan matrix; it would be built by nobody, "
        "which is the gap this job closes"
    )
    # Every image states whether a new finding fails the PR. A missing flag
    # silently makes the scan advisory, which is the state this job replaced.
    assert isinstance(entry["blocking"], bool), f"{dockerfile} has no blocking flag"
    scanned = [step for step in job["steps"] if "trivy-action" in (step.get("uses") or "")]
    assert scanned, "optional images are built but never scanned"
    # The exit code must follow the flag, or the flag is decorative.
    assert any("matrix.blocking" in str(step.get("with", {}).get("exit-code")) for step in scanned)


@pytest.mark.parametrize("dockerfile", ["Dockerfile.misp", "Dockerfile.socialosint"])
def test_pr_pipeline_reruns_when_an_optional_dockerfile_changes(dockerfile: str) -> None:
    workflow = yaml.safe_load(DOCKER_PUBLISH)
    paths = workflow[True]["pull_request"]["paths"]  # `on:` parses as the boolean True
    assert dockerfile in paths, (
        f"editing {dockerfile} would not trigger the workflow that builds it"
    )


def test_dockerignore_keeps_what_dockerfile_misp_copies() -> None:
    """The build broke on `entrypoint_fpm.sh: not found` while `deploy` was ignored."""
    copied = re.findall(r"^COPY\s+(\S+)", DOCKERFILE_MISP, re.MULTILINE)
    assert copied, "Dockerfile.misp stopped copying anything; revisit this guard"
    rules = _dockerignore_rules()
    for source in copied:
        parts = source.strip("/").split("/")
        needed = {"/".join(parts[: index + 1]) for index in range(len(parts))}
        assert not needed & set(rules), (
            f"Dockerfile.misp copies {source}, but .dockerignore excludes "
            f"{sorted(needed & set(rules))}; the build fails with 'not found'"
        )


def test_socialosint_pins_the_security_upgrades_it_needs() -> None:
    """The upstream tree resolves to versions with published CVEs.

    Dockerfile.socialosint is the only place they can be moved without forking
    that repository, so the pin must stay in the same RUN as the install (a
    later layer would leave the vulnerable files shipped) and it must carry an
    argument override so a rebuild can move past it without an edit.
    """
    dockerfile = (REPO_ROOT / "Dockerfile.socialosint").read_text(encoding="utf-8")
    assert "ARG PIP_SECURITY_UPGRADES=" in dockerfile
    assert "--upgrade ${PIP_SECURITY_UPGRADES}" in dockerfile
    # setuptools carries the vendored wheel/jaraco.context Trivy reports;
    # installing those two on their own does not remove the vendored copies.
    assert "setuptools==" in dockerfile
    # Never let a dependency check failure ship a broken tree.
    assert "pip check" in dockerfile


def test_every_trivy_acceptance_expires() -> None:
    """An accepted finding must carry a date, or it is permanent by inertia.

    Trivy's ignorefile syntax supports `exp:YYYY-MM-DD`; without it an entry
    silently outlives the reason it was added, which is how a security
    acceptance turns into a blind spot.
    """
    ignorefile = REPO_ROOT / ".trivyignore"
    assert ignorefile.is_file(), "the blocking scan needs an ignorefile to accept known findings"
    entries = [
        line.strip()
        for line in ignorefile.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert entries, "an empty .trivyignore should be deleted, not kept"
    for entry in entries:
        assert " exp:" in entry, (
            f"{entry!r} has no expiry date; add `exp:YYYY-MM-DD` so the "
            "acceptance is re-examined instead of inherited"
        )
    assert any(
        ".trivyignore" in str(step.get("with", {}).get("trivyignores", ""))
        for step in yaml.safe_load(DOCKER_PUBLISH)["jobs"]["optional-images"]["steps"]
    ), ".trivyignore exists but the scan never reads it"


def test_suppressed_findings_stay_visible_in_the_scan_log() -> None:
    """An accepted finding must be printed, not silently dropped.

    `hide-progress: true` makes the action set TRIVY_QUIET, which also silences
    the "Some vulnerabilities have been ignored/suppressed" notice. A reviewer
    then sees a green scan with no trace of what was accepted, which is worse
    than a red one: the exception is invisible. TRIVY_SHOW_SUPPRESSED restores
    the "Suppressed Vulnerabilities" table without changing the exit code.
    """
    steps = yaml.safe_load(DOCKER_PUBLISH)["jobs"]["optional-images"]["steps"]
    scans = [s for s in steps if "trivy-action" in str(s.get("uses", ""))]
    assert scans, "no Trivy step in the optional-images job"
    for step in scans:
        env = step.get("env") or {}
        assert str(env.get("TRIVY_SHOW_SUPPRESSED")).lower() == "true", (
            f"{step.get('name')} hides progress, which suppresses the notice "
            "that findings were accepted; set TRIVY_SHOW_SUPPRESSED: 'true'"
        )


DOCKER_PUBLISH_YAML = yaml.safe_load(DOCKER_PUBLISH)


def test_scan_runs_monthly_so_an_expiry_becomes_a_deadline() -> None:
    """An `exp:` date only means something if something re-runs the scan.

    Without a schedule the optional images are scanned when a pull request
    happens to touch them, so an expiry that passed could go unnoticed for
    months - the entry would still be honoured on every run in between, which
    is the permanence the `exp:` field was added to prevent.
    """
    triggers = DOCKER_PUBLISH_YAML[True]  # YAML 1.1 parses the `on:` key as True
    assert "schedule" in triggers, "no schedule: image scans only run on pull_request"
    crons = [entry["cron"] for entry in triggers["schedule"]]
    assert len(crons) == 1, f"expected one cron, found {crons}"
    minute, hour, dom, month, dow = crons[0].split()
    assert dom.isdigit() and month == "*" and dow == "*", (
        f"{crons[0]!r} is not a monthly run on a fixed day, so the expiry "
        "check would fire on an unpredictable calendar"
    )


def _job_condition(job: str) -> str:
    condition = DOCKER_PUBLISH_YAML["jobs"][job].get("if", "")
    return " ".join(str(condition).split())


def test_the_scheduled_run_scans_but_never_publishes() -> None:
    """A scheduled run must not push an image.

    The image job publishes whenever the event is not a pull request. A
    schedule runs from the default branch, so without this guard every monthly
    run would publish a new :main image with no commit behind it.
    """
    assert "github.event_name != 'schedule'" in _job_condition("image"), (
        "the image job would publish a :main image on every scheduled run"
    )
    push_step_condition = "github.event_name != 'pull_request'"
    assert push_step_condition in DOCKER_PUBLISH, (
        "the publish step no longer keys off the event; recheck that a scheduled run cannot push"
    )


def test_the_scheduled_run_includes_the_optional_image_scan() -> None:
    condition = _job_condition("optional-images")
    assert "github.event_name == 'schedule'" in condition, (
        "the scan is gated to pull_request, so the monthly run would skip the "
        "job that exists to catch an expired acceptance"
    )


def test_a_monthly_run_cannot_pile_up_or_cancel_commit_work() -> None:
    """Scheduled runs need their own concurrency group.

    Falling back to `run_id` gives each monthly run a fresh group, so a queue
    that is stuck accumulates one copy per month; sharing a group with commits
    would let the scan cancel, or be cancelled by, work tied to a revision.
    """
    concurrency = DOCKER_PUBLISH_YAML["concurrency"]
    group = " ".join(str(concurrency["group"]).split())
    assert "scheduled-optional-image-scan" in group, (
        "scheduled runs share the run_id group and can accumulate"
    )
