"""
Normalizer: CollectorResult → stix2.Bundle

This module is the ONLY producer of STIX in the orchestrator (ADR-002).
Every collector — whatever its native output — hands over a CollectorResult
and gets STIX built here, so Identity, confidence, labels and object ids
follow one set of rules across all tools.

Rules:
  - Every collector has a named Identity object (created_by_ref).
  - All objects carry confidence, x_opencti_score, and labels=[target_fqdn, tool].
  - Values are canonicalised before use, and every id is derived from the
    value that is actually emitted (see _canonical_value).
  - Object ids are deterministic, so re-ingesting an unchanged finding is a
    no-op in OpenCTI:
      * SCOs get the STIX 2.1 spec-mandated uuid5 (OASIS namespace, computed
        by the stix2 library) — this is what makes our observables collide
        with the same observable produced by MISP or an official OpenCTI
        connector, which is the whole point of ADR-003.
      * SDOs (Identity, Relationship, Note, and the Indicator fallback) have
        no spec-mandated id, so we derive a uuid5 from their content over a
        fixed orchestrator namespace.
  - Notes become stix2.Note objects referencing the tool Identity.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import stix2

from orchestrator.models import CollectorName, CollectorResult, EvidenceQualification, Observable

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _det_uuid(seed: str) -> str:
    """Deterministic UUID5 derived from seed (namespace = DNS)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"osint-orchestrator.{seed}"))


# Observable types whose canonical form is lowercase. Domains, e-mail
# addresses and account logins are case-insensitive identities, and hex
# digests have no meaningful case; emitting mixed case would produce a
# second STIX object for the same real-world thing on the next run.
_LOWERCASE_TYPES = frozenset({"domain-name", "email-addr", "user-account", "ipv6-addr", "file"})


def _canonical_value(obs_type: str, value: str) -> str:
    """
    Return the form of *value* that is both emitted and used to derive the id.

    URLs are deliberately left byte-exact apart from surrounding whitespace:
    the path and query of a URL are case-sensitive, and the scheme is part of
    the STIX `url` SCO value, so lowercasing or stripping it would emit a
    value that no longer identifies the same resource.
    """
    v = value.strip()
    if obs_type in _LOWERCASE_TYPES:
        return v.lower()
    if obs_type == "phone-number":
        return _canonical_phone(v)
    return v


_HASH_ALGO_BY_LEN: dict[int, str] = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_HEX_RE = re.compile(r"^[0-9a-f]+$")

# Formatting characters in a phone number carry no information: "+1 (555)
# 123-4567" and "+15551234567" are the same subscriber, and emitting both
# would create two observables for one phone. They are stripped only when what
# remains is a bare (optionally +-prefixed) number, so a value carrying an
# extension or other semantics is left untouched rather than mangled.
_PHONE_FORMATTING_RE = re.compile(r"[\s().-]")
_PHONE_CANONICAL_RE = re.compile(r"^\+?\d+$")


def _canonical_phone(value: str) -> str:
    """Strip formatting from phone numbers so STIX ids stay deterministic.

    " +598 99 123 456" and "+59899123456" must produce the same
    deterministic id; values that are not phone-shaped are returned as-is.
    """
    stripped = _PHONE_FORMATTING_RE.sub("", value)
    return stripped if _PHONE_CANONICAL_RE.match(stripped) else value


# ── Per-tool Identity objects (module-level singletons) ───────────────────────

_COLLECTOR_CREATED = datetime(2026, 9, 4, tzinfo=UTC)

_IDENTITIES: dict[CollectorName, stix2.Identity] = {
    CollectorName.OPENOSINT: stix2.Identity(
        id=f"identity--{_det_uuid('openosint')}",
        name="OpenOSINT",
        identity_class="system",
        description="OSINT Orchestrator — OpenOSINT collector",
        created=_COLLECTOR_CREATED,
        modified=_COLLECTOR_CREATED,
    ),
    CollectorName.SPIDERFOOT: stix2.Identity(
        id=f"identity--{_det_uuid('spiderfoot')}",
        name="SpiderFoot",
        identity_class="system",
        description="OSINT Orchestrator — SpiderFoot collector",
        created=_COLLECTOR_CREATED,
        modified=_COLLECTOR_CREATED,
    ),
    CollectorName.SOCIALOSINT: stix2.Identity(
        id=f"identity--{_det_uuid('socialosint')}",
        name="OWASP SocialOSINT",
        identity_class="system",
        description="OSINT Orchestrator — SocialOSINT collector",
        created=_COLLECTOR_CREATED,
        modified=_COLLECTOR_CREATED,
    ),
    CollectorName.AMASS: stix2.Identity(
        id=f"identity--{_det_uuid('amass')}",
        name="OWASP Amass",
        identity_class="system",
        description="OSINT Orchestrator — Amass collector",
        created=_COLLECTOR_CREATED,
        modified=_COLLECTOR_CREATED,
    ),
    CollectorName.TAVILY: stix2.Identity(
        id=f"identity--{_det_uuid('tavily')}",
        name="Tavily",
        identity_class="system",
        description="OSINT Orchestrator — Tavily collector",
        created=_COLLECTOR_CREATED,
        modified=_COLLECTOR_CREATED,
    ),
}

# STIX 2.1 SCO types supported by the stix2 library
_STIX_SCO_MAP: dict[str, type] = {
    "domain-name": stix2.DomainName,
    "ipv4-addr": stix2.IPv4Address,
    "ipv6-addr": stix2.IPv6Address,
    "url": stix2.URL,
    "email-addr": stix2.EmailAddress,
    "autonomous-system": stix2.AutonomousSystem,
    "x509-certificate": stix2.X509Certificate,
    "user-account": stix2.UserAccount,
    "file": stix2.File,
}

# Simple value-carrying SCOs: stix2 derives the spec id from `value` alone.
_SIMPLE_VALUE_SCOS = (
    stix2.DomainName,
    stix2.IPv4Address,
    stix2.IPv6Address,
    stix2.URL,
    stix2.EmailAddress,
)

# Confidence heuristic per tool (0–100)
_TOOL_CONFIDENCE: dict[CollectorName, int] = {
    CollectorName.OPENOSINT: 70,
    CollectorName.SPIDERFOOT: 65,
    CollectorName.SOCIALOSINT: 55,
    # DNS-resolved names straight from the asset database: high-confidence facts.
    CollectorName.AMASS: 70,
    CollectorName.TAVILY: 60,
}
_TAVILY_URL_IN_NOTE = re.compile(r"\|\s*url=([^|]+)")
# "AS15169", "as15169", "ASN 15169" or a bare "15169". Anything else is not an
# autonomous-system number and is dropped: emitting number=0 for every
# unparseable value made unrelated ASNs share one STIX id.
_ASN = re.compile(r"^(?:AS|ASN)?\s*(\d+)$", re.IGNORECASE)


# ── Observable → STIX SCO ─────────────────────────────────────────────────────


def _build_sco(
    obs: Observable,
    identity_id: str,
    labels: list[str],
    score: int,
    collected_at: datetime,
) -> Any | None:
    """
    Convert an Observable to a stix2 SCO or SDO object. Returns None on failure.

    STIX 2.1 SCOs (Cyber Observables) do NOT support `created_by_ref` or `labels`
    as top-level properties. We store them as custom properties with `x_` prefix
    so OpenCTI can read them via the custom_properties mechanism.

    The id of every object returned here is derived from `value` — the
    canonical value that the object itself carries — so a consumer that
    recomputes the id from the emitted value arrives at the same id.
    """
    custom: dict[str, Any] = {
        "x_opencti_score": score,
        "x_opencti_created_by_ref": identity_id,
        "x_labels": labels,
    }
    value = _canonical_value(obs.type, obs.value)
    if not value:
        return None

    cls = _STIX_SCO_MAP.get(obs.type)
    try:
        if cls in _SIMPLE_VALUE_SCOS:
            return cls(value=value, custom_properties=custom)

        if cls == stix2.AutonomousSystem:
            match = _ASN.match(value)
            if match is None:
                logger.warning("Dropping autonomous-system observable with no number: %r", value)
                return None
            return cls(number=int(match.group(1)), name=value, custom_properties=custom)

        if cls == stix2.UserAccount:
            # account_type, user_id and account_login are all ID contributing
            # properties for UserAccount, so a producer that sets account_login
            # and one that does not derive DIFFERENT ids for the same account.
            # We deliberately set only account_type + user_id: account_login
            # would be a copy of user_id here (it carries no extra information)
            # and omitting it is what lets our observable collide with the same
            # account emitted by OpenOSINT's own exporter.
            #
            # account_type is ALSO an ID contributing property, so it stays
            # "generic" for every producer: a collector that set it to the
            # platform name would give `twitter:alice` a different id from the
            # same account emitted elsewhere as generic — two OpenCTI objects
            # for one account. The platform is useful context, so it travels
            # as a custom property, which does not enter the id.
            extra_custom: dict[str, Any] = {}
            if obs.extra.get("platform"):
                extra_custom["x_platform"] = str(obs.extra["platform"])
            return cls(
                account_type="generic",
                user_id=value,
                custom_properties={**custom, **extra_custom},
            )

        if cls == stix2.File:
            algo = _HASH_ALGO_BY_LEN.get(len(value))
            if algo and _HEX_RE.match(value):
                return cls(hashes={algo: value}, custom_properties=custom)
            # Not a recognised digest — an unnamed File has no ID contributing
            # property and would get a random id, so fall through to Indicator.
            return _fallback_indicator(obs.type, value, identity_id, labels, score, collected_at)

        if cls == stix2.X509Certificate:
            # `subject` is NOT an ID contributing property for X509Certificate
            # (only hashes and serial_number are), so stix2 would assign a
            # random uuid4 and re-create the certificate on every run.
            # Pin an explicit content-derived id instead.
            return cls(
                id=f"x509-certificate--{_det_uuid(f'x509-certificate|{value}')}",
                subject=value,
                custom_properties=custom,
            )

        if obs.type == "phone-number":
            return _phone_number_sco(value, custom)

        if obs.type == "identity":
            # People and organisations are SDOs, not observables. Identity has
            # no spec-mandated deterministic id, so derive one from the name
            # and class to keep re-ingestion idempotent.
            identity_class = obs.extra.get("identity_class", "unknown")
            return stix2.Identity(
                id=f"identity--{_det_uuid(f'entity|{identity_class}|{value}')}",
                name=value,
                identity_class=identity_class,
                created_by_ref=identity_id,
                confidence=score,
                labels=labels,
                custom_properties={"x_opencti_score": score},
            )

        # Fallback: unknown type → Indicator (SDO — supports created_by_ref)
        return _fallback_indicator(obs.type, value, identity_id, labels, score, collected_at)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not build STIX object for %s=%r: %s", obs.type, obs.value, exc)
    return None


def _phone_number_sco(value: str, custom: dict[str, Any]) -> dict[str, Any]:
    """
    Build OpenCTI's native `phone-number` observable.

    STIX 2.1 has no phone SCO, so this is a custom type whichever way we go —
    but it is the one OpenCTI understands natively (pycti maps `phone-number`
    onto its Phone-Number observable), which makes it strictly better than the
    alternatives rather than a trade-off: a bespoke `x-openosint-phone-number`
    correlates with nothing at all, and an Indicator wrapping
    `[phone-number:value = ...]` references that very same non-standard type
    inside its pattern while also being semantically wrong — an Indicator is a
    detection rule, not an observation.

    Returned as a plain dict rather than a registered stix2 CustomObservable on
    purpose: pycti registers `phone-number` when imported, and registering the
    same type twice raises DuplicateRegistrationError. Since the OpenCTI sink
    imports pycti, registering our own would make import order decide whether
    the process starts. stix2.Bundle(allow_custom=True) accepts dicts and
    serialises them unchanged.

    Custom SCOs have no spec-mandated id, so it is derived from the canonical
    value to keep re-ingestion idempotent.
    """
    return {
        "type": "phone-number",
        "spec_version": "2.1",
        "id": f"phone-number--{_det_uuid(f'phone-number|{value}')}",
        "value": value,
        **custom,
    }


def _fallback_indicator(
    obs_type: str,
    value: str,
    identity_id: str,
    labels: list[str],
    score: int,
    collected_at: datetime,
) -> Any:
    """
    Represent an observable type we have no SCO for as an Indicator.

    Indicator is an SDO, so stix2 assigns a random uuid4 unless we pin one.
    We derive it from (type, value) so the same finding keeps its id across
    runs — `valid_from` alone does NOT make an SDO id deterministic.
    """
    # STIX pattern string literals escape backslash and single quote. The
    # backslash must be doubled FIRST, otherwise the escapes we add for quotes
    # get re-escaped and the pattern no longer parses — and an unparseable
    # pattern makes stix2 reject the Indicator, silently dropping the finding.
    safe_val = value.replace("\\", "\\\\").replace("'", "\\'")
    valid_from = collected_at.replace(tzinfo=UTC) if collected_at.tzinfo is None else collected_at
    return stix2.Indicator(
        id=f"indicator--{_det_uuid(f'{obs_type}|{value}')}",
        name=value,
        pattern=f"[{obs_type}:value = '{safe_val}']",
        pattern_type="stix",
        valid_from=valid_from,
        created_by_ref=identity_id,
        labels=labels or ["unknown"],
        confidence=score,
        custom_properties={"x_opencti_score": score},
    )


# ── Main entry point ──────────────────────────────────────────────────────────


def _qualified_note_extras(
    result: CollectorResult,
    note_text: str,
    qualification_by_url: dict[str, EvidenceQualification],
) -> tuple[list[str], dict[str, Any]]:
    labels = [result.target_fqdn, result.collector.value]
    custom: dict[str, Any] = {}
    if result.collector != CollectorName.TAVILY:
        return labels, custom
    match = _TAVILY_URL_IN_NOTE.search(note_text)
    if not match:
        return labels, custom
    url = match.group(1).strip()
    row = qualification_by_url.get(url)
    if row is None:
        return labels, custom
    labels.extend([f"category:{row.category}", f"relevance:{row.relevance}"])
    custom["x_orchestrator_confidence"] = row.confidence
    return labels, custom


def normalize(
    result: CollectorResult,
    *,
    qualification_by_url: dict[str, EvidenceQualification] | None = None,
) -> stix2.Bundle:
    """
    Convert a CollectorResult to a stix2.Bundle.

    Bundle contents:
      - The tool's Identity SDO
      - All valid observables as STIX SCOs (or Indicators for unknown types)
      - Relationships between observables
      - Notes (free-form collector output)
    """
    identity = _IDENTITIES.get(result.collector, _IDENTITIES[CollectorName.OPENOSINT])
    identity_id: str = identity.id
    confidence = _TOOL_CONFIDENCE.get(result.collector, 60)
    labels = [result.target_fqdn, result.collector.value]
    qualification_by_url = qualification_by_url or {}

    objects: list[Any] = [identity]
    # Keyed by (type, canonical value): two observables of different types may
    # legitimately carry the same string.
    value_to_stix_id: dict[tuple[str, str], str] = {}

    # ── Observables ───────────────────────────────────────────────────────────
    for obs in result.observables:
        sco = _build_sco(obs, identity_id, labels, confidence, result.collected_at)
        if sco is not None:
            key = (obs.type, _canonical_value(obs.type, obs.value))
            if key in value_to_stix_id:
                continue
            objects.append(sco)
            value_to_stix_id[key] = sco["id"]

    # ── Relationships ─────────────────────────────────────────────────────────
    for rel in result.relationships:
        src_id = value_to_stix_id.get(
            (rel.source_type, _canonical_value(rel.source_type, rel.source_value))
        )
        tgt_id = value_to_stix_id.get(
            (rel.target_type, _canonical_value(rel.target_type, rel.target_value))
        )
        if not src_id or not tgt_id:
            continue
        try:
            stix_rel = stix2.Relationship(
                # Content-derived id: the same edge re-observed on a later run
                # must not create a second Relationship object in OpenCTI.
                id=f"relationship--{_det_uuid(f'{src_id}|{rel.relationship_type}|{tgt_id}')}",
                source_ref=src_id,
                target_ref=tgt_id,
                relationship_type=rel.relationship_type,
                created_by_ref=identity_id,
                confidence=confidence,
                labels=labels,
                custom_properties={"x_opencti_score": confidence},
            )
            objects.append(stix_rel)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build STIX Relationship: %s", exc)

    # ── Notes ─────────────────────────────────────────────────────────────────
    for note_text in result.notes:
        if not note_text or not note_text.strip():
            continue
        try:
            note_labels, note_custom = _qualified_note_extras(
                result, note_text, qualification_by_url
            )
            # The identity is one per collector, so the target goes into the
            # id: two targets with the same note text ("no public results…")
            # must not share a Note that OpenCTI would then merge.
            note = stix2.Note(
                id=f"note--{_det_uuid(f'{identity_id}|{result.target_fqdn}|{note_text}')}",
                abstract=note_text[:128],
                content=note_text,
                created_by_ref=identity_id,
                object_refs=[identity_id],
                labels=note_labels,
                custom_properties={"x_opencti_score": confidence, **note_custom},
            )
            objects.append(note)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build STIX Note: %s", exc)

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    logger.debug(
        "normalize: collector=%s target=%s objects=%d",
        result.collector.value,
        result.target_fqdn,
        len(objects),
    )
    return bundle
