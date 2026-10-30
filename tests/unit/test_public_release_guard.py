"""The public-release guard scans what could reach the repository.

`gitleaks detect --no-git --source .` reads git-ignored files too, and the
README tells every operator to keep live credentials in `.env`. The guard
therefore failed on a developer's machine for a leak the public repository
cannot see, while CI (a clean checkout without `.env`) passed: two verdicts for
the same commit, and the local one trains people to ignore the check.

The double below stands in for the gitleaks binary — a tool CI downloads and a
developer may not have installed — and records what it was pointed at. The file
selection the guard performs runs for real, against a real repository.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "check_public_release.sh"
TRACKED = "notes.md"
IGNORED = ".env"
# Matches gitleaks' github-pat rule. The canonical AWS example
# (AKIAIOSFODNN7EXAMPLE) is in gitleaks' own allowlist, so a test built on it
# would pass for the wrong reason. Assembled at run time on purpose: the full
# value never appears in a tracked file, so the fixture cannot become the leak
# the guard reports.
CREDENTIAL = "GITHUB_TOKEN=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-c", "user.email=test@example.com", "-c", "user.name=test"]
    subprocess.run([*git, "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(f"{IGNORED}\n", encoding="utf-8")
    (repo / TRACKED).write_text("nothing to see here\n", encoding="utf-8")
    (repo / IGNORED).write_text(CREDENTIAL, encoding="utf-8")
    subprocess.run([*git, "add", ".gitignore", TRACKED], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


def _double(bin_dir: Path, exit_code: int = 0) -> tuple[Path, Path]:
    """A `gitleaks` on PATH that records its arguments and the files it saw."""
    bin_dir.mkdir()
    argv, scanned = bin_dir / "argv.txt", bin_dir / "scanned.txt"
    binary = bin_dir / "gitleaks"
    binary.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" > {argv}\n"
        f"find . -type f | sort > {scanned}\n"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return argv, scanned


def _run(
    repo: Path, bin_dir: Path | None = None, history: bool = False
) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if key != "CHECK_HISTORY"}
    if bin_dir is not None:
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
    if history:
        env["CHECK_HISTORY"] = "1"
    return subprocess.run(
        ["bash", str(GUARD)], cwd=repo, env=env, capture_output=True, text=True, timeout=120
    )


def test_guard_scans_tracked_files_and_skips_ignored_ones(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _, scanned = _double(tmp_path / "bin")

    result = _run(repo, tmp_path / "bin")

    assert result.returncode == 0, result.stdout + result.stderr
    seen = set(scanned.read_text(encoding="utf-8").split())
    assert f"./{TRACKED}" in seen
    assert f"./{IGNORED}" not in seen, "the operator's .env must not be scanned"
    assert "Public-release guard passed" in result.stdout


def test_history_mode_scans_the_repository_itself(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    argv, scanned = _double(tmp_path / "bin")

    result = _run(repo, tmp_path / "bin", history=True)

    assert result.returncode == 0, result.stdout + result.stderr
    arguments = argv.read_text(encoding="utf-8")
    assert "--source ." in arguments
    assert "--no-git" not in arguments, "history mode reads git objects, not a copy"
    assert "./.git/config" in set(scanned.read_text(encoding="utf-8").split())


def test_a_finding_fails_the_guard(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _double(tmp_path / "bin", exit_code=1)

    result = _run(repo, tmp_path / "bin")

    assert result.returncode == 1
    assert "Public-release guard FAILED" in result.stdout


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks is not installed")
def test_real_gitleaks_ignores_the_operator_env_and_catches_a_committed_key(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)

    clean = _run(repo)
    assert clean.returncode == 0, clean.stdout + clean.stderr

    (repo / "leaked.txt").write_text(CREDENTIAL, encoding="utf-8")
    subprocess.run(["git", "add", "leaked.txt"], cwd=repo, check=True, timeout=60)
    caught = _run(repo)
    # The same string, tracked instead of ignored: the guard now reports it.
    # --redact withholds the path from the log, so the exit status is the signal.
    assert caught.returncode == 1
    assert "Public-release guard FAILED" in caught.stdout
