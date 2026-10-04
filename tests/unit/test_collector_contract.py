"""Compatibility guardrails for the collector output contract."""

from __future__ import annotations

from orchestrator.models import (
    COLLECTOR_RESULT_CONTRACT_VERSION,
    CollectorName,
    CollectorResult,
)


def test_collector_result_exposes_contract_version_by_default() -> None:
    result = CollectorResult(
        collector=CollectorName.OPENOSINT,
        target_fqdn="example.com",
    )
    assert result.contract_version == COLLECTOR_RESULT_CONTRACT_VERSION


def test_collector_result_has_no_new_required_fields() -> None:
    schema = CollectorResult.model_json_schema()
    required_fields = set(schema.get("required", []))
    # Backward compatibility gate: adding a new required field is a breaking
    # change for every collector implementation and downstream normalizer code.
    assert required_fields == {"collector", "target_fqdn"}
