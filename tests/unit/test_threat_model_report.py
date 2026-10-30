"""The generated threat model must stay consistent with itself.

`docs/threat-model.md` is produced by `scripts/threat_model.py`, which needs
OWASP pytm in a throwaway virtualenv and is deliberately not a runtime
dependency, so CI cannot run the generator. Nothing else checked the report:
it could drift from the model it describes, or from the ledger that pins which
(threat, element) pairs exist, and the number a reader trusts — "1414 findings
across 89 distinct threats" — would quietly stop being true.

These checks need no pytm. They hold the report to the numbers it states and to
`scripts/threat_model_findings.txt`, so a hand edit, a dropped section or a
ledger that no longer matches fails the suite. When one of them fails, do not
edit the report by hand: regenerate it (see the module docstring of
`scripts/threat_model.py`).
"""

from __future__ import annotations

import collections
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "docs" / "threat-model.md"
LEDGER = ROOT / "scripts" / "threat_model_findings.txt"

# Threat ids carry a two- or three-letter prefix (AC01, INP05), never one.
_FINDING = re.compile(r"^#### F-(\d+) — .*  `([A-Z]{2,3}\d{2,3})`$")
_ELEMENT = re.compile(r"^- \*\*Element:\*\* (.+) \(([a-z]+)\)$")
_RESPONSE = re.compile(r"^- \*\*Response:\*\* ([a-z]+) — ")
_HEADLINE = re.compile(r"^## Findings: (\d+) across (\d+) distinct threats$")
_TRIAGE_TOTAL = re.compile(r"^- \*\*(accepted|mitigated|transferred)\*\*: (\d+) finding\(s\)$")
_SEVERITY = re.compile(r"^### Severity: (.+) \((\d+)\)$")
_DOCUMENTED_CLASS = re.compile(r"^- \*\*([a-z]+)\*\*: ")


def _parse() -> dict:
    lines = REPORT.read_text(encoding="utf-8").splitlines()
    findings: list[dict] = []
    headline = None
    triage: dict[str, int] = {}
    severity: dict[str, int] = {}
    classes: set[str] = set()
    current = None
    in_classes = False
    for line in lines:
        if line.startswith("## Element classes"):
            in_classes = True
            continue
        if line.startswith("## "):
            in_classes = False
        if in_classes:
            documented = _DOCUMENTED_CLASS.match(line)
            if documented:
                classes.add(documented.group(1))
        if match := _HEADLINE.match(line):
            headline = (int(match.group(1)), int(match.group(2)))
        elif match := _TRIAGE_TOTAL.match(line):
            triage[match.group(1)] = int(match.group(2))
        elif match := _SEVERITY.match(line):
            severity[match.group(1)] = int(match.group(2))
        elif match := _FINDING.match(line):
            current = {"id": int(match.group(1)), "threat": match.group(2)}
            findings.append(current)
        elif current is not None and (match := _ELEMENT.match(line)):
            current["element"], current["class"] = match.group(1), match.group(2)
        elif current is not None and (match := _RESPONSE.match(line)):
            current["response"] = match.group(1)
    return {
        "headings": sum(1 for line in lines if line.startswith("#### F-")),
        "findings": findings,
        "headline": headline,
        "triage": triage,
        "severity": severity,
        "classes": classes,
    }


@pytest.fixture(scope="module")
def report() -> dict:
    return _parse()


def test_every_heading_is_a_finding_with_an_element_and_a_response(report: dict) -> None:
    findings = report["findings"]
    assert report["headings"] == len(findings), (
        f"{report['headings']} finding headings, {len(findings)} parsed: the heading format "
        "changed. Regenerate the report instead of editing it."
    )
    incomplete = [f["id"] for f in findings if not f.get("element") or not f.get("response")]
    assert not incomplete, f"findings with no element or no response: {incomplete[:10]}"
    duplicated = [
        fid for fid, count in collections.Counter(f["id"] for f in findings).items() if count > 1
    ]
    assert not duplicated, f"finding ids rendered twice: {duplicated[:10]}"


def test_headline_matches_the_findings_it_lists(report: dict) -> None:
    total, distinct = report["headline"]
    findings = report["findings"]
    assert total == len(findings)
    assert distinct == len({f["threat"] for f in findings})


def test_severity_sections_add_up_to_the_headline(report: dict) -> None:
    total = report["headline"][0]
    severity = report["severity"]
    assert severity, "no severity sections: the report lost its structure"
    assert sum(severity.values()) == total, (
        f"sections report {severity} = {sum(severity.values())}, headline says {total}"
    )


def test_triage_summary_matches_the_responses_and_the_headline(report: dict) -> None:
    findings = report["findings"]
    counted = collections.Counter(f["response"] for f in findings)
    assert set(counted) <= {"accepted", "mitigated", "transferred"}, sorted(counted)
    assert dict(counted) == report["triage"], (
        f"summary says {report['triage']}, the findings say {dict(counted)}"
    )
    assert sum(counted.values()) == report["headline"][0]


def test_every_element_class_is_documented(report: dict) -> None:
    used = {f["class"] for f in report["findings"]}
    assert used <= report["classes"], (
        f"classes used but not documented: {sorted(used - report['classes'])}"
    )
    assert report["classes"] == {"orchestrator", "sidecar", "vendor", "store", "flow"}


def test_ledger_lists_exactly_the_findings(report: dict) -> None:
    pairs = [
        tuple(line.split("\t"))
        for line in LEDGER.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert all(len(pair) == 3 for pair in pairs), "the ledger lines are not threat/class/element"
    assert len(pairs) == len(set(pairs)), "the ledger repeats a (threat, class, element) pair"
    assert pairs == sorted(pairs), "the ledger is not sorted: a diff would hide the change"
    rendered = {(f["threat"], f["class"], f["element"]) for f in report["findings"]}
    assert rendered == set(pairs), (
        "the ledger and the report disagree; only the report or only the ledger was regenerated. "
        f"In the report only: {sorted(rendered - set(pairs))[:5]}. "
        f"In the ledger only: {sorted(set(pairs) - rendered)[:5]}."
    )
