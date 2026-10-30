"""The metrics table in `docs/operations.md` describes the metrics that exist.

`AGENTS.md` requires a new metric to be declared in `orchestrator/metrics.py`
*and* given a row in the table "with exactly the labels declared in code", and
`CONTRIBUTING.md` lists the two matching as something a reviewer checks by eye.
Neither was enforced.

An operator reads this table to write an alert, so a wrong label is not a
cosmetic error: `sum by (target_id)` over a metric that has no `target_id`, or a
dashboard querying a metric name that was renamed, returns nothing and looks
like a quiet system. Both are the failure mode this file exists to prevent.

Names are compared as Prometheus exposes them — the code declares
`osint_orchestrator_runs_total` and the table writes `runs_total` under a stated
prefix — and a counter or an info-metric whose name the client library suffixes
is normalised before comparing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from prometheus_client import Counter, Gauge, Histogram, Info

from orchestrator import metrics

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = ROOT / "docs" / "operations.md"
PREFIX = "osint_orchestrator_"
_HEADER = "| Metric | Labels | Meaning |"
# Label names are backticked; the parenthesised group after a label lists the
# values it takes, so it is stripped before the names are read.
_ROW = re.compile(r"\|\s*`([a-z0-9_]+)`\s*\|\s*(.*?)\s*\|")
_PARENTHESISED = re.compile(r"\([^)]*\)")
_BACKTICKED = re.compile(r"`([a-z0-9_]+)`")


def _documented() -> dict[str, set[str]]:
    page = OPERATIONS.read_text(encoding="utf-8")
    if _HEADER not in page:
        pytest.fail(f"the metrics table header {_HEADER!r} is gone from docs/operations.md")
    table = page[page.index(_HEADER) :]
    table = table[: table.index("\n\n")]
    rows = {}
    for line in table.splitlines():
        match = _ROW.match(line)
        if match:
            labels = match.group(2).replace("(", "(")
            rows[match.group(1)] = set(_BACKTICKED.findall(_PARENTHESISED.sub("", labels)))
    assert rows, "the metrics table parsed as empty — did its Markdown change shape?"
    return rows


def _exposed() -> dict[str, set[str] | None]:
    """Every metric declared in the module, under the name /metrics exposes.

    `prometheus_client` stores the bare name and adds the suffix at exposition
    time: a `Counter` declared as `..._runs_total` exposes `..._runs_total` and
    keeps `..._runs` in `_name`, and an `Info` exposes its name plus `_info`.
    The suffix rule is checked against a real exposition payload in
    `test_the_suffix_rule_matches_the_exposition`.

    An `Info` carries no fixed label names — its labels are the keys of the
    payload published at runtime — so its entry is `None` and the labels are
    read from the exposition instead.
    """
    declared = {}
    for attribute in dir(metrics):
        metric = getattr(metrics, attribute)
        if not isinstance(metric, (Counter, Gauge, Histogram, Info)):
            continue
        name = metric._name.removeprefix(PREFIX)
        if isinstance(metric, Counter):
            name += "_total"
        elif isinstance(metric, Info):
            name += "_info"
        declared[name] = None if isinstance(metric, Info) else set(metric._labelnames)
    assert declared, "no metrics found in orchestrator.metrics"
    return declared


def _published_info_labels(name: str) -> set[str]:
    """The label names an info-metric actually exposes, from a real payload."""
    metrics.set_build_info("label-guard")
    body = metrics.render()[0].decode()
    for line in body.splitlines():
        if line.startswith(f"{PREFIX}{name}{{"):
            return set(re.findall(r"([a-z_]+)=", line[: line.index("}")]))
    return set()


@pytest.fixture(scope="module")
def documented() -> dict[str, set[str]]:
    return _documented()


@pytest.fixture(scope="module")
def declared() -> dict[str, set[str]]:
    return _exposed()


def test_every_declared_metric_has_a_row(
    documented: dict[str, set[str]], declared: dict[str, set[str]]
) -> None:
    missing = sorted(set(declared) - set(documented))
    assert missing == [], (
        f"metrics declared in orchestrator/metrics.py with no row in the "
        f"docs/operations.md table: {missing}. An operator cannot alert on a "
        "metric the reference does not describe."
    )


def test_every_row_describes_a_declared_metric(
    documented: dict[str, set[str]], declared: dict[str, set[str]]
) -> None:
    removed = sorted(set(documented) - set(declared))
    assert removed == [], (
        f"rows in the docs/operations.md tables for metrics that no longer "
        f"exist: {removed}. A dashboard built on them returns nothing and the "
        "silence reads as a healthy system."
    )


def test_row_labels_match_the_declared_labels(
    documented: dict[str, set[str]], declared: dict[str, set[str] | None]
) -> None:
    wrong = {}
    for name in sorted(set(declared) & set(documented)):
        actual = declared[name]
        if actual is None:
            actual = _published_info_labels(name)
        if documented[name] != actual:
            wrong[name] = {"the table": sorted(documented[name]), "the code": sorted(actual)}
    assert wrong == {}, f"label lists that disagree between the table and the code: {wrong}"


def test_the_suffix_rule_matches_the_exposition() -> None:
    """The name mapping above is a claim about the client library, so pin it.

    Counters are stored without `_total` and get it back on exposition, and
    `Info` gains `_info`. If a library upgrade changed either, the three checks
    above would compare against names that no exposition ever contains and
    could pass while every query an operator writes returns nothing.
    """
    metrics.runs_total.labels("suffix-rule", "success").inc()
    metrics.set_build_info("suffix-rule")
    body = metrics.render()[0].decode()
    exposed = {line.split("{")[0].split(" ")[0] for line in body.splitlines() if line}
    assert f"{PREFIX}runs_total" in exposed
    assert f"{PREFIX}build_info" in exposed
