"""Shared targets.yaml loader used by API, scheduler, and retention."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from orchestrator.models import Target

logger = logging.getLogger(__name__)

_LOAD_ERROR = "<targets-file>"


def load_targets(path: str) -> tuple[list[Target], list[str]]:
    """
    Load and validate targets from *path*.

    Returns (valid_targets, errors), where errors contains either target ids (or
    ``<index N>``) for invalid target entries, or ``<targets-file>`` for a
    file-level load failure (missing file, malformed YAML, wrong top-level
    shape).
    """
    targets_path = Path(path)
    if not targets_path.exists():
        logger.warning("targets file not found: %s", path)
        return [], [_LOAD_ERROR]

    try:
        data = yaml.safe_load(targets_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Invalid targets file %s: %s", path, exc)
        return [], [_LOAD_ERROR]

    if not isinstance(data, dict):
        logger.error("Invalid targets file %s: top level must be a mapping", path)
        return [], [_LOAD_ERROR]

    raw_targets = data.get("targets", [])
    if not isinstance(raw_targets, list):
        logger.error("Invalid targets file %s: 'targets' must be a list", path)
        return [], [_LOAD_ERROR]

    loaded_targets: list[Target] = []
    invalid_targets: list[str] = []
    for idx, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            invalid_targets.append(f"<index {idx}>")
            continue
        try:
            loaded_targets.append(Target(**raw))
        except Exception as exc:  # noqa: BLE001
            target_id = str(raw.get("id", f"<index {idx}>"))
            logger.warning("Skipping invalid target %s from %s: %s", target_id, path, exc)
            invalid_targets.append(target_id)
    return loaded_targets, sorted(set(invalid_targets))
