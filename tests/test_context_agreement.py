"""Every view of business context agrees with the resolver.

Evidence review, evidence quality, Evidence Closure gaps, context review,
policy facts and decision requirements must report the same unresolved
fields for the same asset (design/context-resolution.md, section 11).
"""

from __future__ import annotations

import itertools

import pytest

from qstriage.assessment import assess_inventory
from qstriage.closure import build_gap_manifest
from qstriage.context import ContextEffect, normalize_asset_context
from qstriage.decision import VerificationRequirement
from qstriage.evidence import EvidenceCategory
from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    Inventory,
    InventoryEvidenceMetadata,
    RiskLevel,
)
from qstriage.review import review_decision_context


DATA_CLASS_VALUES = ["customer_pii", "public", "unknown", "redacted", "Confidential"]
EXPOSURE_VALUES = ["internal", "unknown", "redacted", "corporate-ish"]
RETENTION_VALUES = [0, 10]
ORIGINS = ["service", "cbom_cryptographic_asset"]
ASSERTED = [False, True]

QUALITY_KEYS = {
    "data_class": "data_class",
    "retention_years": "retention_years",
    "exposure": "exposure_boundary",
    "criticality": "business_criticality_context",
    "local_blast_radius": "blast_radius_context",
    "migration_effort": "migration_effort_context",
}

CASES = list(
    itertools.product(DATA_CLASS_VALUES, EXPOSURE_VALUES, RETENTION_VALUES, ORIGINS, ASSERTED)
)


def _assertion() -> FieldEvidenceAssertion:
    return FieldEvidenceAssertion(
        state=EvidenceAssertionState.declared,
        provenance=EvidenceAssertionProvenance.user_declared,
        source_reference="owner-confirmation",
    )


def _inventory(
    data_class: str, exposure: str, retention: int, asset_type: str, asserted: bool
) -> Inventory:
    asset = CryptographicAsset(
        id="asset-1",
        name="Asset 1",
        environment="production",
        asset_type=asset_type,
        protocol="tls",
        algorithm="RSA-2048",
        key_size_bits=2048,
        data_class=data_class,
        retention_years=retention,
        exposure=exposure,
        criticality=RiskLevel.medium,
        local_blast_radius=RiskLevel.medium,
        migration_effort=RiskLevel.medium,
    )
    evidence = None
    if asserted:
        evidence = InventoryEvidenceMetadata(
            version="0.1",
            source_inventory_hash="sha256:" + "0" * 64,
            assets={
                "asset-1": AssetEvidenceAssertions(
                    retention_years=_assertion(),
                    criticality=_assertion(),
                    local_blast_radius=_assertion(),
                    migration_effort=_assertion(),
                )
            },
        )
    return Inventory(assets=[asset], evidence=evidence)


@pytest.mark.parametrize(("data_class", "exposure", "retention", "asset_type", "asserted"), CASES)
def test_all_views_report_the_same_unresolved_fields(
    data_class: str, exposure: str, retention: int, asset_type: str, asserted: bool
) -> None:
    inventory = _inventory(data_class, exposure, retention, asset_type, asserted)
    asset = inventory.assets[0]
    asset_evidence = inventory.evidence.assets["asset-1"] if inventory.evidence else None

    context = normalize_asset_context(asset, asset_evidence)
    expected = {field.field for field in context.unresolved_fields}

    assessment = assess_inventory(inventory)[0]
    gaps = {gap.field for gap in build_gap_manifest(inventory).gaps}
    gaps.discard("relationship_completeness")
    review = {issue.field for issue in review_decision_context(inventory).asset_reviews[0].issues}
    evidence = {
        finding.field_path.rsplit(".", 1)[1]
        for finding in assessment.evidence_review.findings
        if finding.category
        in {EvidenceCategory.business_context, EvidenceCategory.supply_chain_context}
        and finding.field_path
    }
    quality = {
        field for field, key in QUALITY_KEYS.items()
        if key in assessment.evidence_quality.missing_evidence
    }
    assessed = {field.field for field in assessment.normalized_context.unresolved_fields}

    assert gaps == expected
    assert review == expected
    assert evidence == expected
    assert quality == expected
    assert assessed == expected

    blocking = {
        field.field for field in context.unresolved_fields if field.effect is ContextEffect.block
    }
    policy_missing = blocking & {"data_class", "retention_years", "exposure"}
    blocked_by_policy = (
        "missing_business_context_requires_human_review"
        in assessment.policy_evaluation.applied_rule_ids
    )
    assert blocked_by_policy == bool(policy_missing)

    requirements = set(assessment.decision.verification_requirements)
    if expected & {"data_class", "retention_years", "exposure", "criticality"}:
        assert VerificationRequirement.business_context in requirements

    if not expected and asset_type == "service":
        # CBOM imports also need relationship completeness, which is dependency
        # context and is outside this test.
        assert assessment.evidence_review.decision_grade.value == "decision_grade"
        assert review_decision_context(inventory).asset_reviews[0].status == "complete"


@pytest.mark.parametrize(("data_class", "exposure", "retention", "asset_type", "asserted"), CASES)
def test_no_message_calls_a_present_value_unknown(
    data_class: str, exposure: str, retention: int, asset_type: str, asserted: bool
) -> None:
    inventory = _inventory(data_class, exposure, retention, asset_type, asserted)
    asset = inventory.assets[0]

    for resolved in normalize_asset_context(asset).unresolved_fields:
        assert resolved.message is not None
        assert resolved.field_path in resolved.message
        if resolved.raw_value not in {"unknown"}:
            assert " is unknown" not in resolved.message


def test_pdr_for_the_enriched_demo_agrees_with_the_closure_comparison() -> None:
    from pathlib import Path

    from qstriage.closure import build_inventory_comparison
    from qstriage.models import load_inventory
    from qstriage.pdr import generate_pdr_document

    demo = Path(__file__).resolve().parents[1] / "examples" / "evidence-closure"
    before = load_inventory(demo / "imported.yaml")
    after = load_inventory(demo / "expected" / "enriched.yaml")

    comparison = build_inventory_comparison(before, after).assets[0]
    record = generate_pdr_document(after).records[0]

    assert [finding.code for finding in record.evidence_review.findings] == (
        comparison.remaining_finding_codes
    )
    assert record.decision.execution_state.value == comparison.execution_state_after
    assert record.decision.action_type.value == comparison.action_after
    assert record.decision.verification_priority.value == (
        comparison.verification_priority_after
    )
