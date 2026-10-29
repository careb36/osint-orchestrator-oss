"""Whether a test session may keep the environment it was started with.

Two requirements pull in opposite directions:

* Unit tests must not inherit a developer's exported settings. A shell that had
  sourced `.env` leaked `OPENCTI_ENABLED` into the suite and
  `test_issue8_sink_failure_reraises_on_second_run` failed because the sink was
  already on before pytest started. Only a clean shell ever passed.
* `tests/integration/test_e2e.py` reads the real stack's endpoint and API key
  from the environment at import time, so scrubbing it would point the suite at
  localhost defaults and drop the key for authenticated calls.

`Settings` is instantiated at import time, so both cannot hold in one process.
When a run can reach the integration tests, integration wins and the environment
is kept; CI is hermetic either way because it selects `-m "not integration"`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# The env prefix of every settings group, taken from the field names of
# orchestrator.config.Settings. They cannot be derived at that point: the
# module instantiates itself at import time from whatever is still in the
# environment, which is the very thing being scrubbed.
# tests/unit/test_env_coverage.py fails if Settings grows a group missing here.
SETTINGS_PREFIXES = (
    "ORCHESTRATOR",
    "OPENCTI",
    "ALERT",
    "AMASS",
    "SOCIALOSINT",
    "SPIDERFOOT",
    "TAVILY",
    "LLM",
    "OPENAI",
    "ANTHROPIC",
    "NEBIUS",
    "OLLAMA",
    "SYNTHESIS",
    "TARGETS",
)

# Options whose next argument is a value rather than a path.
_VALUE_OPTIONS = frozenset(
    {"-m", "--markexpr", "-k", "--keyword", "-p", "--rootdir", "-c", "--config-file", "-o"}
)


def _filter_expressions(argv: list[str]) -> list[str]:
    """The `-m` / `-k` expressions in an argv, whichever spelling was used."""
    found = []
    for index, arg in enumerate(argv):
        if arg in _VALUE_OPTIONS and index + 1 < len(argv):
            if arg in ("-m", "--markexpr", "-k", "--keyword"):
                found.append(argv[index + 1])
        elif arg.startswith(("--markexpr=", "--keyword=")):
            found.append(arg.split("=", 1)[1])
    return found


def _selected_paths(argv: list[str]) -> list[str]:
    """The positional arguments of an argv: the files or directories selected."""
    paths, skip_next = [], False
    for arg in argv:
        if skip_next:
            skip_next = False
        elif arg in _VALUE_OPTIONS:
            skip_next = True
        elif not arg.startswith("-"):
            paths.append(arg)
    return paths


def keeps_environment(argv: list[str], repo_root: Path) -> bool:
    """True when the session can run the integration tests, which need the env."""
    expressions = " ".join(_filter_expressions(argv))
    if re.search(r"\bintegration\b", expressions):
        # `-m "not integration"` is the hermetic selection, not an integration run.
        return not re.search(r"\bnot\b[^,;]*\bintegration\b", expressions)

    integration_dir = (repo_root / "tests" / "integration").resolve()
    for raw in _selected_paths(argv) or [str(repo_root)]:
        path = Path(raw)
        path = (path if path.is_absolute() else repo_root / path).resolve()
        if path == integration_dir or path.is_relative_to(integration_dir):
            return True
        if integration_dir.is_relative_to(path):
            return True
    return False


def scrub(environ: os._Environ | dict[str, str] = os.environ) -> list[str]:
    """Delete every settings variable and return the names removed."""
    # Every setting is <PREFIX>_<FIELD>, so a variable without the underscore
    # (a bare "OPENCTI") belongs to something else and stays.
    removed = [
        name for name in list(environ) if "_" in name and name.split("_", 1)[0] in SETTINGS_PREFIXES
    ]
    for name in removed:
        del environ[name]
    return removed
