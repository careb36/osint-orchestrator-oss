"""
OpenOSINT collector.

Calls OpenOSINT in-process through its public Python API
(`openosint.investigate.investigate`), which returns an
`openosint.correlation.EntityGraph`, and maps that graph onto the
orchestrator's `CollectorResult` contract (ADR-002).

WHY in-process and not a subprocess
-----------------------------------
Shelling out to the `openosint` CLI couples us to an interactive command
surface that carries no compatibility guarantee: flags and subcommand names
change between releases, output is formatted for humans, and a wrong
invocation is indistinguishable from "the target has no findings" — it exits
non-zero and we record a successful run with nothing in it. `investigate()`
is the entry point OpenOSINT documents for downstream consumers to pin
against, returns typed objects, and surfaces argument errors as ValueError.

WHY we map to CollectorResult instead of using OpenOSINT's STIX exporter
-----------------------------------------------------------------------
OpenOSINT ships `openosint.graph.export.stix`, but using it would make the
orchestrator a two-producer system: bundles built there and bundles built by
`orchestrator.normalizer.stix` would carry different Identity objects,
confidence scales and label conventions into the same OpenCTI. ADR-002 puts
a single normalizer on the boundary, so every collector — OpenOSINT included
— hands over a CollectorResult and STIX is produced in exactly one place.
As a side effect this keeps the dependency surface narrow: `investigate()`
pulls in only pivot/correlation/extractors, not the `graph` package and its
followthemoney/PyICU chain.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime

from orchestrator.collectors import BaseCollector
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Relationship,
)

logger = logging.getLogger(__name__)


# OpenOSINT EntityType.value → STIX 2.1 observable type used by the normalizer.
# `ip` is refined to ipv4-addr / ipv6-addr per value; person and org become
# Identity SDOs, distinguished by the identity_class carried in Observable.extra.
_ENTITY_TYPE_TO_STIX: dict[str, str] = {
    "email": "email-addr",
    "username": "user-account",
    "domain": "domain-name",
    "ip": "ipv4-addr",
    "phone": "phone-number",
    "hash": "file",
    "url": "url",
    "person": "identity",
    "org": "identity",
    "asn": "autonomous-system",
}

_IDENTITY_CLASS: dict[str, str] = {"person": "individual", "org": "organization"}

# targets.yaml investigation_type → openosint EntityKind value.
_INVESTIGATION_TYPE_TO_KIND: dict[str, str] = {
    "domain": "domain",
    "email": "email",
    "username": "username",
    "ip": "ip",
    "phone": "phone",
    "url": "url",
    "hash": "hash",
    "person": "person",
    "auto": "auto",
}


def _ip_stix_type(value: str) -> str:
    """Return ipv4-addr or ipv6-addr for *value*, defaulting to ipv4-addr."""
    try:
        return f"ipv{ipaddress.ip_address(value.strip()).version}-addr"
    except ValueError:
        return "ipv4-addr"


def _stix_type_for(entity_type_value: str, value: str) -> str | None:
    """Map an OpenOSINT EntityType value to a STIX observable type."""
    stix_type = _ENTITY_TYPE_TO_STIX.get(entity_type_value)
    if stix_type == "ipv4-addr":
        return _ip_stix_type(value)
    return stix_type


class OpenOSINTCollector(BaseCollector):
    """In-process OpenOSINT collector: pivots from the target seed via ``investigate()``.

    The search is bounded by the target's budget keys (``max_depth``,
    ``max_entities``, ``max_tool_calls``, ``tool_timeout_seconds``). Entities
    without a STIX mapping are dropped with a warning rather than guessed at.
    """

    name = CollectorName.OPENOSINT

    async def collect(self) -> CollectorResult:
        """Run a budgeted investigation and map the entity graph to a CollectorResult.

        Never raises: import errors, invalid budgets/types and investigation
        failures all return ``success=False`` with an explanatory error.
        """
        fqdn = self.target.fqdn
        cfg = self.target.collectors.openosint

        try:
            investigate, budget = self._load_api(cfg)
        except ImportError as exc:
            logger.error("OpenOSINT is not importable: %s", exc)
            return self._failure(fqdn, f"openosint not installed: {exc}")
        except ValueError as exc:
            # InvestigationBudget validates its bounds on construction.
            logger.error("Invalid OpenOSINT budget for %s: %s", fqdn, exc)
            return self._failure(fqdn, f"invalid investigation budget: {exc}")

        kind = _INVESTIGATION_TYPE_TO_KIND.get(cfg.investigation_type.lower())
        if kind is None:
            valid = sorted(_INVESTIGATION_TYPE_TO_KIND)
            return self._failure(
                fqdn,
                f"unknown investigation_type {cfg.investigation_type!r}; valid: {valid}",
            )

        logger.info("OpenOSINT: investigating %s as %s", fqdn, kind)
        try:
            graph = await investigate(fqdn, kind=kind, budget=budget, run_id=self.target.id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("OpenOSINT failed for %s", fqdn)
            return self._failure(fqdn, str(exc))

        try:
            return self._from_graph(graph, fqdn)
        except Exception as exc:  # noqa: BLE001
            # A malformed entity or relationship is the tool's bug, not the
            # run's: report it as a failed collector like any other error.
            logger.exception("OpenOSINT graph mapping failed for %s", fqdn)
            return self._failure(fqdn, f"graph mapping: {exc}")

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _load_api(cfg):
        """Import the OpenOSINT API and build a budget from the collector config."""
        from openosint.investigate import InvestigationBudget, investigate

        budget = InvestigationBudget(
            max_depth=cfg.max_depth,
            max_entities=cfg.max_entities,
            max_tool_calls=cfg.max_tool_calls,
            timeout_seconds=cfg.tool_timeout_seconds,
        )
        return investigate, budget

    def _failure(self, fqdn: str, error: str) -> CollectorResult:
        """Build a failed CollectorResult carrying *error*."""
        return CollectorResult(collector=self.name, target_fqdn=fqdn, success=False, error=error)

    def _from_graph(self, graph, fqdn: str) -> CollectorResult:
        """
        Map an EntityGraph onto CollectorResult.

        Entities whose type has no STIX equivalent are dropped with a warning
        rather than guessed at — a wrong observable type is worse in OpenCTI
        than a missing one.
        """
        observables: list[Observable] = []
        relationships: list[Relationship] = []
        notes: list[str] = []
        # (entity type value, normalized) → STIX type, so relationship
        # endpoints resolve to the same type the observable was emitted with.
        stix_type_of: dict[tuple[str, str], str] = {}

        for entity in graph._sorted_entities():
            entity_type = entity.type.value
            stix_type = _stix_type_for(entity_type, entity.value)
            if stix_type is None:
                logger.warning(
                    "OpenOSINT entity type %r has no STIX mapping; dropping %r",
                    entity_type,
                    entity.value,
                )
                continue
            stix_type_of[(entity_type, entity.normalized)] = stix_type

            extra: dict = {"source_tools": sorted(entity.source_tools)}
            identity_class = _IDENTITY_CLASS.get(entity_type)
            if identity_class:
                extra["identity_class"] = identity_class
            observables.append(Observable(type=stix_type, value=entity.value, extra=extra))

        for rel in graph._sorted_relationships():
            src_type = stix_type_of.get((rel.source.type.value, rel.source.normalized))
            tgt_type = stix_type_of.get((rel.target.type.value, rel.target.normalized))
            if src_type is None or tgt_type is None:
                continue
            relationships.append(
                Relationship(
                    source_value=rel.source.value,
                    source_type=src_type,
                    target_value=rel.target.value,
                    target_type=tgt_type,
                    relationship_type=rel.kind.strip().lower().replace(" ", "-") or "related-to",
                )
            )

        if not observables:
            notes.append("openosint: investigation returned no entities")

        logger.info(
            "OpenOSINT: %s → %d observables, %d relationships",
            fqdn,
            len(observables),
            len(relationships),
        )
        return CollectorResult(
            collector=self.name,
            target_fqdn=fqdn,
            collected_at=datetime.now(UTC),
            observables=observables,
            relationships=relationships,
            notes=notes,
            success=True,
        )
