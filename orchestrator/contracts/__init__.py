"""Contrato del bundle STIX 2.1 de productores externos (JSON Schema).

Copia fijada del esquema que publica el productor ``investigation-assistant``
(ver su ``stix_export/schema/`` y su ``IA-ADR-005``). El ``$id`` y el
``x-contract-version`` son los del productor; este repo es el **consumidor** y
fija una copia idéntica para validar la ingesta sin acoplar el código de ambos.

Si el productor cambia el formato, sube la versión del contrato; entonces se
actualiza esta copia y ``SCHEMA_VERSION`` (el test de contrato lo exige).
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

SCHEMA_VERSION = "1.0.0"
SCHEMA_FILE = "stix-bundle.schema.json"


def load_schema() -> dict[str, Any]:
    """Carga el JSON Schema del contrato (paquete instalado o árbol fuente)."""
    return json.loads(
        files(__package__).joinpath(SCHEMA_FILE).read_text(encoding="utf-8"))
