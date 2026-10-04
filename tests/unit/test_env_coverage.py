"""
Guard test: every field declared in orchestrator.config.Settings must have a
corresponding entry in .env.example.

This prevents the two documents from drifting apart silently.  When you add a
new setting to Settings, you must also add it (or a commented-out version) to
.env.example.  The test converts field names to the env-var form (upper-case,
with the pydantic-settings default: underscores preserved) and then checks that
the string appears somewhere in .env.example.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).parents[2]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
README_FILES = (REPO_ROOT / "README.md", REPO_ROOT / "README.es.md")


def _env_var_name(field_name: str) -> str:
    """Return the expected env-variable name for a Settings field."""
    return field_name.upper()


def _env_example_text() -> str:
    return ENV_EXAMPLE.read_text(encoding="utf-8")


def _settings_fields() -> list[str]:
    # Import lazily so the test file itself doesn't break on import if
    # pydantic-settings is not installed yet.
    from orchestrator.config import Settings  # noqa: PLC0415

    return list(Settings.model_fields.keys())


def _readme_table_keys() -> set[str]:
    keys: set[str] = set()
    for path in README_FILES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.lstrip().startswith("|"):
                continue
            for match in re.finditer(r"`([A-Z][A-Z0-9_]+)`", line):
                keys.add(match.group(1))
    return keys


@pytest.mark.parametrize("field_name", _settings_fields())
def test_settings_field_in_env_example(field_name: str) -> None:
    """Each Settings field must be mentioned in .env.example."""
    env_var = _env_var_name(field_name)
    text = _env_example_text()
    # Accept the variable anywhere: as KEY=value, # KEY= (commented), or in a
    # comment line that names it explicitly.
    pattern = re.compile(r"(?m)^[# ]*" + re.escape(env_var) + r"\b")
    assert pattern.search(text), (
        f"Settings field '{field_name}' (env var '{env_var}') is missing from "
        f".env.example.  Add a documented entry or a commented placeholder."
    )


def test_env_example_has_no_inline_comment_on_blank_value() -> None:
    """``KEY=   # comment`` must not appear in .env.example.

    Docker Compose's env_file parser treats the comment as the value when the
    value is blank, so a copied template would set e.g. TAVILY_INCLUDE_DOMAINS
    to "# Optional comma-separated allowlist ...". Put the comment on its own
    line above the key instead. Commented-out placeholders (``# KEY=   # ...``)
    are checked too: uncommenting one would bring the bug back.
    """
    offenders = re.findall(r"(?m)^#?[ \t]*[A-Z][A-Z0-9_]*=[ \t]+#.*$", _env_example_text())
    assert not offenders, "Blank values with an inline comment:\n" + "\n".join(offenders)


@pytest.mark.parametrize("field_name", _settings_fields())
def test_settings_field_in_readme_environment_tables(field_name: str) -> None:
    """Each Settings field must be listed in a README environment table row."""
    env_var = _env_var_name(field_name)
    assert env_var in _readme_table_keys(), (
        f"Settings field '{field_name}' (env var '{env_var}') is missing from "
        "README.md / README.es.md environment tables."
    )
