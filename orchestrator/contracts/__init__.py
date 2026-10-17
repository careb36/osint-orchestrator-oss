"""Contract for STIX 2.1 bundles from external producers (JSON Schema).

A pinned copy of the schema published by the ``investigation-assistant``
producer (its ``stix_export/schema/`` and its ``IA-ADR-005``). The ``$id`` and
``x-contract-version`` are the producer's: this repository is the **consumer**
and keeps an identical copy to validate the intake without coupling the code of
the two projects. The schema's own title and description stay in the
producer's language because the file must stay byte-identical to theirs.

When the producer changes the format it bumps the contract version; this copy
and ``SCHEMA_VERSION`` are then updated together (the contract test enforces it).
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

SCHEMA_VERSION = "1.0.0"
SCHEMA_FILE = "stix-bundle.schema.json"


def load_schema() -> dict[str, Any]:
    """Load the contract's JSON Schema (installed package or source tree)."""
    return json.loads(files(__package__).joinpath(SCHEMA_FILE).read_text(encoding="utf-8"))
