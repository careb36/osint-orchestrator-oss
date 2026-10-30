"""The API reference describes the routes the server actually serves.

`CONTRIBUTING.md` requires an API change to reach "the endpoint table in
`docs/operations.md`" and lists the table as something a reviewer checks by eye.
Nothing enforced it, and the table had already drifted: `/health` and `/ready`
each appeared twice, with different descriptions, because an edit landed on one
copy and not the other.

The table is what a caller reads before writing an integration, so a wrong entry
is worse than a missing one — it promises a path that answers 404 and the reader
trusts the table over the server.

Three checks, each answering a question the table has to get right:

1. no duplicate rows — two entries for one route hide an edit to a stale copy;
2. every documented endpoint is served — the code is the source of truth;
3. every routed area appears somewhere under `docs/` — so a new area cannot ship
   with no documentation at all.

Check 3 works on the first path segment, not the whole path: this project
documents the dossier routes in prose relative to `/cases/{id}`
(`docs/compliance-workflow.md`), and demanding an exact full-path string would
force a second copy of the reference into the operations table.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from orchestrator.api import app

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = ROOT / "docs" / "operations.md"
DOCS = ROOT / "docs"
_HEADER = "| Method | Path | Description |"
_ROW = re.compile(r"\|\s*`([A-Z]+)`\s*\|\s*`([^`]+)`\s*\|")
_PARAMETER = re.compile(r"\{[^}]*\}")
# FastAPI serves these itself. The page introduces them in prose ("Interactive
# reference: /docs (OpenAPI at /openapi.json)") rather than with a table row.
_FRAMEWORK = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")


def _normalise(path: str) -> str:
    """Collapse parameter names: `/runs/{id}` and `/runs/{run_id}` are one path."""
    return _PARAMETER.sub("{}", path)


def _documented() -> list[tuple[str, str]]:
    page = OPERATIONS.read_text(encoding="utf-8")
    if _HEADER not in page:
        pytest.fail(f"the endpoint table header {_HEADER!r} is gone from docs/operations.md")
    table = page[page.index(_HEADER) :]
    table = table[: table.index("\n\n")]
    rows = [(method, _normalise(path)) for method, path in _ROW.findall(table)]
    assert rows, "the endpoint table parsed as empty — did its Markdown change shape?"
    return rows


def _served() -> set[tuple[str, str]]:
    """Every route the app publishes, from two sources that each miss some.

    `app.openapi()` flattens the routers that are included lazily, but omits the
    routes declared with `include_in_schema=False` (`/`, `/metrics`, `/console`).
    `app.routes` sees those and misses the lazy ones. The union is the real
    surface; the four pages FastAPI owns are removed because the reference
    introduces them in prose.
    """
    served = {
        (method.upper(), _normalise(route.path))
        for route in app.routes
        if getattr(route, "methods", None) and getattr(route, "path", None)
        for method in route.methods
    }
    served |= {
        (method.upper(), _normalise(path))
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    served -= {("GET", path) for path in _FRAMEWORK}
    served -= {(method, path) for method, path in served if method in {"HEAD", "OPTIONS"}}
    assert served, "no routes found on the app"
    return served


@pytest.fixture(scope="module")
def documented() -> list[tuple[str, str]]:
    return _documented()


@pytest.fixture(scope="module")
def served() -> set[tuple[str, str]]:
    return _served()


def test_the_table_has_no_duplicate_rows(documented: list[tuple[str, str]]) -> None:
    duplicated = sorted({row for row in documented if documented.count(row) > 1})
    assert duplicated == [], (
        f"endpoint rows that appear more than once: {duplicated}. One route, two "
        "entries is how an edit lands on a stale copy and reads as documented."
    )


def test_every_documented_endpoint_is_served(
    documented: list[tuple[str, str]], served: set[tuple[str, str]]
) -> None:
    invented = sorted(set(documented) - served)
    assert invented == [], (
        f"endpoints in the docs/operations.md table that the app does not serve: "
        f"{invented}. A caller builds an integration on a path that answers 404."
    )


def test_every_routed_area_appears_in_the_documentation() -> None:
    """A whole new area — `/reports`, say — cannot go unmentioned.

    Matching stops at the first path segment on purpose: the dossier routes are
    documented as suffixes of `/cases/{id}` in `docs/compliance-workflow.md`, and
    requiring the full path here would duplicate that reference.
    """
    corpus = "\n".join(path.read_text(encoding="utf-8") for path in sorted(DOCS.glob("*.md")))
    areas = {path.split("/")[1] for path in app.openapi()["paths"] if path.count("/") > 1}
    unmentioned = sorted(area for area in areas if f"/{area}" not in corpus)
    assert unmentioned == [], (
        f"route areas that no page under docs/ ever names: {unmentioned}. A caller "
        "cannot discover them, and a reviewer cannot see them missing."
    )
