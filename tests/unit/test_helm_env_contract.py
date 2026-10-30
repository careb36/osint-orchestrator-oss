"""Every environment variable the Helm chart renders is one the app reads.

`orchestrator/config.py` declares `Settings` with `extra="ignore"`, so a
misnamed variable is not an error anywhere: pydantic drops it, the process
starts, and the operator's value never takes effect. Nothing in `helm lint
--strict` or `helm template` notices either — I checked both against a chart
whose mapping read `.Values.config.openctiUrll`. Helm rendered
`OPENCTI_URL: "<nil>"`, a literal string the app would happily treat as a URL,
and both commands passed.

That is the failure this guards: the chart is the only documented way to deploy
on Kubernetes (`docs/operations.md`, `deploy/helm/osint-orchestrator/README.md`),
and a value it
silently discards looks exactly like one that was applied.

The chart is read, not rendered. Rendering would need `helm` on PATH, which the
`Lint & Unit Tests` CI job does not install — the chart has its own job — and a
test that skips itself where the tool is missing is not a guard.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from orchestrator.config import Settings

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "osint-orchestrator"
VALUES = CHART / "values.yaml"
ENV_TEMPLATE = CHART / "templates" / "configmap-env.yaml"
SECRET_TEMPLATE = CHART / "templates" / "secret.yaml"
DEPLOYMENT = CHART / "templates" / "deployment.yaml"

# `"NAME" .Values.some.path` and `"NAME" "literal value"` inside the $env dict.
_MAPPING_ENTRY = re.compile(r'(?m)^\s*"([A-Z][A-Z0-9_]*)"\s+(\.Values\.[A-Za-z0-9_.]+|"[^"]*")\s*$')
# The app's own variable naming: the Settings field name, uppercased.
_SETTING_NAMES = frozenset(name.upper() for name in Settings.model_fields)


def _values() -> dict[str, Any]:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


def _config_env_entries() -> dict[str, str]:
    """Env var -> the values path or literal it is rendered from."""
    text = ENV_TEMPLATE.read_text(encoding="utf-8")
    start = text.index("$env := dict")
    block = text[start : text.index("}}", start)]
    entries = dict((name, source) for name, source in _MAPPING_ENTRY.findall(block))
    # A rewrite of the template could make the pattern match nothing, and every
    # check below would then pass over an empty set.
    assert len(entries) >= 25, (
        f"parsed only {len(entries)} env vars from {ENV_TEMPLATE.name}; the $env "
        "dict changed shape and this guard is no longer reading it"
    )
    return entries


def _secret_keys() -> list[str]:
    keys = list(_values().get("secrets", {}).get("values") or {})
    assert keys, "no keys parsed from secrets.values in values.yaml"
    return keys


def _resolved(values: dict[str, Any], path: str) -> Any:
    node: Any = values
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return KeyError(path)
        node = node[part]
    return node


@pytest.mark.parametrize("env_var", sorted(_config_env_entries()) + _secret_keys())
def test_the_app_reads_the_variable_the_chart_renders(env_var: str) -> None:
    """Settings ignores unknown keys, so a typo here is a value silently dropped."""
    assert env_var in _SETTING_NAMES, (
        f"the chart renders {env_var}, which is not a Settings field. Pydantic "
        'drops it (extra="ignore"), so the value never reaches the app and '
        "nothing fails: not helm lint, not the pod start. Field names are the "
        "env var names, uppercased."
    )


def test_every_values_path_the_mapping_reads_exists() -> None:
    """A broken path renders the literal '<nil>' and passes `helm lint --strict`."""
    values = _values()
    missing = {
        name: source
        for name, source in _config_env_entries().items()
        if source.startswith(".Values.")
        and isinstance(_resolved(values, source.removeprefix(".Values.")), KeyError)
    }
    assert missing == {}, (
        "the chart reads values paths that values.yaml does not define: "
        f"{missing}. Helm renders such a lookup as the literal string '<nil>', "
        "which the app accepts, and both helm lint --strict and helm template "
        "still pass."
    )


def test_no_variable_is_declared_twice_in_the_configmap() -> None:
    """A duplicate key in the Go template's dict literal is won by the last one, silently."""
    text = ENV_TEMPLATE.read_text(encoding="utf-8")
    start = text.index("$env := dict")
    block = text[start : text.index("}}", start)]
    names = [name for name, _ in _MAPPING_ENTRY.findall(block)]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    assert duplicated == [], (
        f"{duplicated} are mapped twice in configmap-env.yaml. The template dict "
        "keeps only the last entry, so one of the two values is unreachable and "
        "no render shows it."
    )


def test_no_variable_is_in_both_the_configmap_and_the_secret() -> None:
    """envFrom applies the Secret after the ConfigMap, so a shared key flips silently."""
    shared = sorted(set(_config_env_entries()) & set(_secret_keys()))
    assert shared == [], (
        f"{shared} are rendered into both the ConfigMap and the Secret. "
        "deployment.yaml lists the Secret second in envFrom, so Kubernetes lets "
        "it win — the ConfigMap value is dead and nothing says so."
    )


def test_the_rendered_variables_reach_the_container() -> None:
    """A key in the ConfigMap is dead if nothing mounts the ConfigMap."""
    text = DEPLOYMENT.read_text(encoding="utf-8")
    mounted = re.findall(r"(?m)^\s*-\s*(configMapRef|secretRef):\s*\n\s*name:\s*(\S.*)$", text)
    kinds = [kind for kind, _ in mounted]
    assert "configMapRef" in kinds, (
        "deployment.yaml does not mount a ConfigMap as envFrom, so none of the "
        "config.* values reaches the container"
    )
    assert "secretRef" in kinds, (
        "deployment.yaml does not mount the Secret as envFrom, so "
        "secrets.values never reaches the container"
    )
    configmap_name = next(name for kind, name in mounted if kind == "configMapRef")
    assert "-env" in configmap_name, (
        f"the ConfigMap mounted as envFrom is {configmap_name!r}, not the chart's "
        "-env ConfigMap that configmap-env.yaml renders"
    )
    # envFrom lets a later source win, so the order is what makes a shared key
    # a silent override rather than a startup error.
    assert kinds.index("configMapRef") < kinds.index("secretRef"), (
        "the Secret must be mounted after the ConfigMap: envFrom applies later "
        "sources last, and the assertions above assume that order"
    )
    # The Secret is rendered only when one is not supplied from outside.
    assert "existingSecret" in SECRET_TEMPLATE.read_text(encoding="utf-8"), (
        "secret.yaml must keep the existingSecret branch, or a chart that "
        "supplies its own Secret renders a duplicate one"
    )


def test_extra_env_wins_over_a_named_entry() -> None:
    """The chart README promises extraEnv overrides a named config.* value.

    Sprig's `mergeOverwrite` lets its *later* arguments win, so the direction of
    the two arguments is the whole promise. Swapping them would leave every
    values file written before a key had its own `config.*` entry silently
    ignored, which is the case the README says the escape hatch covers.
    """
    text = ENV_TEMPLATE.read_text(encoding="utf-8")
    match = re.search(r"mergeOverwrite\s+(\S+)\s+\(\s*(\.Values\.config\.extraEnv)", text)
    assert match, (
        "configmap-env.yaml no longer merges config.extraEnv with mergeOverwrite; "
        "deploy/helm/osint-orchestrator/README.md documents that an entry there "
        "overrides a named config.* value"
    )
    assert match.group(1) == "$env", (
        f"mergeOverwrite receives {match.group(1)!r} as its destination, so "
        "config.extraEnv no longer wins over a named value"
    )
