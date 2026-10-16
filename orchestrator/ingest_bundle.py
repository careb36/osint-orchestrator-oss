"""Import an external STIX 2.1 bundle into OpenCTI.

The normalizer is the only *producer* of STIX inside the orchestrator
(ADR-002): collectors hand over a ``CollectorResult`` and
``orchestrator/normalizer/stix.py`` builds the objects. ADR-011 admits
*external producers* — tooling that already emits STIX 2.1, such as the
``investigation-assistant`` engine — as an **intake path only**: the bundle is
parsed and handed to ``OpenCTISink``, which owns retries, per-object rejection
reporting and the outbox. Nothing here builds or rewrites STIX.

    python -m orchestrator.ingest_bundle bundle.stix.json \\
        [--work-name investigation-assistant:conexion_ganadera] [--dry-run]

``pycti`` is imported **before** ``stix2.parse`` on purpose: pycti registers
the OpenCTI SCOs (``bank-account``, ``text``, …) that the stix2 catalogue does
not know, so a bundle carrying them cannot be parsed without it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import pycti  # noqa: F401  (side effect: registers the OpenCTI SCOs)
import stix2

from orchestrator.config import settings
from orchestrator.logging_config import configure_logging
from orchestrator.sinks import OpenCTIIngestError, OpenCTISink

logger = logging.getLogger(__name__)

DEFAULT_WORK_NAME = "external-stix"


def load_bundle(path: Path) -> stix2.Bundle:
    """Parse a STIX 2.1 bundle from disk. Call it after importing pycti."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read the file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise ValueError(f"{path}: not a STIX 2.1 bundle")
    try:
        return stix2.parse(data, allow_custom=True)
    except stix2.ParseError as exc:
        raise ValueError(f"{path}: cannot parse the bundle: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m orchestrator.ingest_bundle``."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path, help="path to the STIX 2.1 bundle")
    parser.add_argument(
        "--work-name",
        default=DEFAULT_WORK_NAME,
        help="label recorded with the ingest (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="parse and count only; do not contact OpenCTI",
    )
    args = parser.parse_args(argv)
    configure_logging()

    try:
        bundle = load_bundle(args.bundle)
    except ValueError as exc:
        logger.error("ingest_bundle: %s", exc)
        return 2

    total = len(bundle.objects)
    if args.dry_run:
        print(f"{total} objects parsed from {args.bundle} (dry run; nothing ingested)")
        return 0

    sink = OpenCTISink()
    try:
        sink.ingest(bundle, args.work_name)
    except OpenCTIIngestError as exc:
        logger.error("ingest_bundle failed: %s", exc)
        return 1
    print(f"{total} objects ingested into {settings.opencti_url} as work_name={args.work_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
