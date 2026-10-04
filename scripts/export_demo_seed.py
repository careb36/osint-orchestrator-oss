#!/usr/bin/env python3
"""Export one run as a demo seed file (see demo/seed/README.md).

    python scripts/export_demo_seed.py --database ./orchestrator.db --run-id 12 \
        [--report-root .] > demo/seed/<name>.json

Reads the SQLite database directly (read-only) and the run's directory. The
seed never contains risk fields, signatures, keys or raw model responses.
`--report-root` is the directory that the run's `report_path` is relative to
(or a replacement for its `/app` prefix when exporting from a container volume).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.demo import export_seed  # noqa: E402


def _rows(conn: sqlite3.Connection, query: str, *params: object) -> list[dict]:
    conn.row_factory = sqlite3.Row
    return [dict(row) for row in conn.execute(query, params)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database", required=True, help="path to orchestrator.db")
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--report-root", default=".", help="where report_path is rooted")
    args = parser.parse_args()

    conn = sqlite3.connect(f"file:{args.database}?mode=ro", uri=True)
    runs = _rows(conn, "SELECT * FROM runs WHERE id = ?", args.run_id)
    if not runs:
        print(f"run {args.run_id} not found", file=sys.stderr)
        return 1
    run = runs[0]
    run["status"] = str(run["status"]).lower()
    if not run.get("report_path"):
        print(f"run {args.run_id} has no report", file=sys.stderr)
        return 1
    report_path = Path(run["report_path"])
    if report_path.is_absolute() and not report_path.exists():
        # e.g. /app/daily_reports/... exported from a container volume
        report_path = Path(args.report_root) / Path(*report_path.parts[2:])
    elif not report_path.is_absolute():
        report_path = Path(args.report_root) / report_path
    if not report_path.is_file():
        print(f"report not found at {report_path}", file=sys.stderr)
        return 1

    findings = _rows(conn, "SELECT * FROM findings WHERE run_id = ?", args.run_id)
    finding = findings[0] if findings else None
    if finding:
        for key in ("new_since_last_run", "suggested_pivots"):
            finding[key] = json.loads(finding.get(key) or "[]")
    evidence = _rows(
        conn, "SELECT * FROM evidence_qualifications WHERE run_id = ? ORDER BY url, id", args.run_id
    )
    print(export_seed(run=run, finding=finding, evidence=evidence, run_dir=report_path.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
