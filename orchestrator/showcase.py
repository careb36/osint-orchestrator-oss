"""Replay a recorded sample run through the real pipeline, without API keys.

The showcase is how a reader sees the product before configuring a collector
or an LLM provider. ``python -m orchestrator.showcase`` loads the recorded
runs in ``orchestrator/showcase_data/`` and hands each one to ``run_target_pipeline`` with
a collector that returns the recorded ``CollectorResult`` and an LLM client
that answers the qualification and synthesis prompts with the recorded rows.
The pipeline does everything else exactly as for a scheduled run: STIX
normalisation (ADR-002), the delta against the previous run, the report and
``qualified_evidence.json``, the manifest signed with the deployment key and
chained to the previous run (ADR-007), and the alert case. Nothing leaves the
host.

The recording is honest about what it is: the sample entity is fictitious
and uses reserved names (``.example``, TEST-NET addresses), the texts are
written, not model output, and every persisted row says provider
``showcase`` and model ``recorded-sample``, so the console never credits a
model that did not run. The target that receives the runs is ``enabled:
false`` in ``targets.example.yaml``: the scheduler never runs it and
"Start run" refuses it, so the sample never costs an API call.

Exit codes: 0 replayed; 1 a precondition failed (OpenCTI ingest on, the
target missing from targets.yaml, a run of the target still pending) or a
recording is invalid.

    python -m orchestrator.showcase [--seed-dir <directory of run-*.json>]
    docker compose exec orchestrator python -m orchestrator.showcase
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.resources
import json
import logging
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from orchestrator.collectors.base import BaseCollector
from orchestrator.config import settings
from orchestrator.database import create_db_and_tables
from orchestrator.i18n import resolve_language
from orchestrator.logging_config import configure_logging
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    EvidenceCategory,
    EvidenceItem,
    EvidenceRelevance,
    Observable,
    Relationship,
    Target,
)
from orchestrator.pipeline import run_target_pipeline
from orchestrator.run_control import create_pending_run
from orchestrator.targets import load_targets

logger = logging.getLogger(__name__)

SHOWCASE_VERSION = 1
# The recordings travel inside the package (also in the image and in a wheel).
DEFAULT_SEED_DIR = Path(str(importlib.resources.files("orchestrator.showcase_data")))
# What the persisted rows say about the "model" that answered: the recorded
# texts, replayed. The names are deliberately not a provider's.
PROVIDER = "showcase"
MODEL = "recorded-sample"


# ─── Recording format ────────────────────────────────────────────────────────


class RecordedCollector(BaseModel):
    """One collector's output in a recording: the fields of ``CollectorResult``."""

    model_config = ConfigDict(extra="forbid")

    collector: CollectorName
    observables: list[Observable] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)


class RecordedQualification(BaseModel):
    """The fast route's verdict on one evidence item, rationale per language."""

    model_config = ConfigDict(extra="forbid")

    url: str
    category: EvidenceCategory
    relevance: EvidenceRelevance
    confidence: float = Field(ge=0, le=1)
    rationale: dict[str, str] = Field(min_length=1)


class RecordedFinding(BaseModel):
    """The reasoning route's answer, in the shape the synthesizer validates."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1)
    new_since_last_run: list[str] = Field(default_factory=list)
    risk_level: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    risk_justification: str = ""
    suggested_pivots: list[str] = Field(default_factory=list)


class Recording(BaseModel):
    """One recorded run: ``demo/showcase/run-<n>.json``."""

    model_config = ConfigDict(extra="forbid")

    showcase_version: Literal[1]
    target_id: str
    collectors: list[RecordedCollector] = Field(min_length=1)
    qualifications: list[RecordedQualification] = Field(default_factory=list)
    finding: dict[str, RecordedFinding] = Field(min_length=1)


def load_recording(path: Path) -> Recording:
    """Parse and validate one recording; raises ValueError with the file named."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read the file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON: {exc}") from exc
    try:
        return Recording.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"{path}: not a showcase recording: {exc}") from exc


def _text_for(texts: dict[str, Any], language: str) -> Any:
    """The entry for *language*, else English, else whatever the recording has."""
    for candidate in (language, "en"):
        if candidate in texts:
            return texts[candidate]
    return next(iter(texts.values()))


# ─── Stand-ins for the collectors and the LLM ────────────────────────────────


class ShowcaseCollector(BaseCollector):
    """Returns one recorded ``CollectorResult`` instead of collecting."""

    def __init__(self, target: Target, recorded: RecordedCollector) -> None:
        super().__init__(target)
        self._recorded = recorded

    @property
    def name(self) -> CollectorName:
        return self._recorded.collector

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self._recorded.collector,
            target_fqdn=self.target.fqdn,
            observables=list(self._recorded.observables),
            relationships=list(self._recorded.relationships),
            notes=list(self._recorded.notes),
            evidence=list(self._recorded.evidence),
        )


class ShowcaseLLMClient:
    """Answers the qualification and synthesis prompts from the recording.

    The fast route's prompt lists the batch as ``- index: N`` blocks with an
    ``  url:`` line each (``synthesizer/qualify.py``); the reply maps every
    recorded URL in the batch to its verdict by index. The reasoning route
    gets the recorded finding for the target's language.
    """

    provider = PROVIDER

    def __init__(self, recording: Recording, *, language: str) -> None:
        self._language = language
        self._qualifications = {row.url: row for row in recording.qualifications}
        self._finding: RecordedFinding = _text_for(recording.finding, language)

    def model_for_route(self, route: Literal["reasoning", "fast"]) -> str:
        return MODEL

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        if model_route == "fast":
            return json.dumps({"items": self._qualify(user)}, ensure_ascii=False)
        return self._finding.model_dump_json()

    def _qualify(self, user_prompt: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        index: int | None = None
        for line in user_prompt.splitlines():
            if line.startswith("- index: "):
                index = int(line.removeprefix("- index: ").strip())
                continue
            if index is None or not line.startswith("  url: "):
                continue
            row = self._qualifications.get(line.removeprefix("  url: ").strip())
            if row is None:
                continue
            items.append(
                {
                    "index": index,
                    "category": row.category.value,
                    "relevance": row.relevance.value,
                    "confidence": row.confidence,
                    "rationale": _text_for(row.rationale, self._language),
                }
            )
        return items


# ─── Replay ──────────────────────────────────────────────────────────────────


def recordings_in(seed_dir: Path) -> list[Path]:
    """The recordings of *seed_dir* in replay order (``run-1.json``, ``run-2.json``, …)."""
    return sorted(seed_dir.glob("run-*.json"), key=lambda path: path.name)


async def replay(recording: Recording, target: Target) -> int | None:
    """Run one recording through the pipeline; returns the run id, None if not admitted."""
    run_id = await create_pending_run(target.id)
    if run_id is None:
        return None
    language = resolve_language(target.language)
    await run_target_pipeline(
        target,
        run_id,
        collectors=[ShowcaseCollector(target, block) for block in recording.collectors],
        llm_client=ShowcaseLLMClient(recording, language=language),
    )
    return run_id


async def replay_all(seed_dir: Path, *, targets_file: str) -> int:
    """Replay every recording of *seed_dir*; returns the process exit code."""
    if settings.opencti_enabled:
        logger.error(
            "Showcase not replayed: OPENCTI_ENABLED=true would ingest the sample into OpenCTI; "
            "set it to false for the showcase"
        )
        return 1
    paths = recordings_in(seed_dir)
    if not paths:
        logger.error("Showcase not replayed: no run-*.json in %s", seed_dir)
        return 1
    try:
        recordings = [load_recording(path) for path in paths]
    except ValueError as exc:
        logger.error("Showcase not replayed: %s", exc)
        return 1

    targets, _errors = load_targets(targets_file)
    by_id = {target.id: target for target in targets}
    missing = sorted({rec.target_id for rec in recordings} - by_id.keys())
    if missing:
        logger.error(
            "Showcase not replayed: target %s is not in %s; copy its block from "
            "targets.example.yaml",
            ", ".join(missing),
            targets_file,
        )
        return 1

    await create_db_and_tables()
    for path, recording in zip(paths, recordings, strict=True):
        target = by_id[recording.target_id]
        run_id = await replay(recording, target)
        if run_id is None:
            logger.error(
                "Showcase stopped at %s: a run of target %s is still pending or running",
                path.name,
                target.id,
                extra={"target_id": target.id},
            )
            return 1
        logger.info(
            "Showcase run replayed file=%s target=%s run_id=%d",
            path.name,
            target.id,
            run_id,
            extra={"target_id": target.id, "run_id": run_id},
        )
    logger.info(
        "Showcase ready: %d run(s) of target %s; open the console at /console",
        len(paths),
        ", ".join(sorted({rec.target_id for rec in recordings})),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m orchestrator.showcase",
        description="Replay the recorded showcase runs through the pipeline (no API keys).",
    )
    parser.add_argument(
        "--seed-dir",
        type=Path,
        default=DEFAULT_SEED_DIR,
        help=f"directory with run-*.json recordings (default: {DEFAULT_SEED_DIR})",
    )
    args = parser.parse_args(argv)
    configure_logging()
    return asyncio.run(replay_all(args.seed_dir, targets_file=settings.targets_file))


if __name__ == "__main__":
    sys.exit(main())
