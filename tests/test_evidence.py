from pydantic import ValidationError
import pytest

from qstriage.evidence import (
    DecisionGrade,
    EvidenceCategory,
    EvidenceEffect,
    EvidenceFinding,
    EvidenceProvenance,
    EvidenceSeverity,
    EvidenceState,
    HumanAction,
    RelationshipCompleteness,
    build_evidence_review,
)


def test_finding_marks_decision_grade_block_and_human_review() -> None:
    finding = EvidenceFinding(
        code="missing_data_class",
        category=EvidenceCategory.business_context,
        severity=EvidenceSeverity.high,
        message="Data class is missing.",
        effects=[
            EvidenceEffect.confidence_capped,
            EvidenceEffect.decision_grade_blocked,
            EvidenceEffect.human_review_required,
        ],
        asset_id="public-api-gateway",
        field_path="assets[public-api-gateway].data_class",
        evidence_state=EvidenceState.no_assertion,
        provenance=EvidenceProvenance.qstriage_default,
        human_action=HumanAction(
            description="Add business data classification to the asset.",
            field_path="assets[public-api-gateway].data_class",
            expected_value_type="non-empty data class such as customer_pii or public",
            effect_if_unresolved="PDR remains not decision-grade.",
        ),
    )

    assert finding.blocks_decision_grade is True
    assert finding.requires_human_review is True


def test_review_blocks_decision_grade_for_missing_business_context() -> None:
    finding = EvidenceFinding(
        code="missing_data_class",
        category=EvidenceCategory.business_context,
        severity=EvidenceSeverity.high,
        message="Data class is unknown; migration priority may be unreliable.",
        effects=[
            EvidenceEffect.confidence_capped,
            EvidenceEffect.decision_grade_blocked,
            EvidenceEffect.human_review_required,
        ],
        evidence_state=EvidenceState.no_assertion,
        provenance=EvidenceProvenance.qstriage_default,
        human_action=HumanAction(
            description="Set data_class for the affected asset.",
            field_path="assets[asset-id].data_class",
            expected_value_type="non-empty business data classification",
            effect_if_unresolved="Decision grade remains blocked.",
        ),
    )

    review = build_evidence_review([finding], asset_id="asset-id")

    assert review.asset_id == "asset-id"
    assert review.decision_grade == DecisionGrade.not_decision_grade
    assert review.human_review_required is True
    assert review.confidence_cap <= 0.5
    assert review.evidence_score < 1.0
    assert review.blocking_finding_codes == ["missing_data_class"]
    assert review.recommended_next_actions == ["Set data_class for the affected asset."]


def test_defaulted_qstriage_value_lowers_confidence_cap() -> None:
    finding = EvidenceFinding(
        code="defaulted_criticality",
        category=EvidenceCategory.supply_chain_context,
        severity=EvidenceSeverity.medium,
        message="Criticality was defaulted because imported CBOM evidence has no business context.",
        effects=[EvidenceEffect.confidence_capped],
        evidence_state=EvidenceState.defaulted,
        provenance=EvidenceProvenance.qstriage_default,
    )

    review = build_evidence_review([finding], asset_id="crypto-rsa-2048")

    assert review.confidence_cap <= 0.75
    assert review.findings[0].evidence_state == EvidenceState.defaulted
    assert review.findings[0].provenance == EvidenceProvenance.qstriage_default


def test_relationship_completeness_distinguishes_unknown_from_none() -> None:
    unknown_finding = EvidenceFinding(
        code="unknown_dependency_completeness",
        category=EvidenceCategory.dependency_context,
        severity=EvidenceSeverity.high,
        message="Dependency completeness is unknown.",
        effects=[EvidenceEffect.confidence_capped],
        evidence_state=EvidenceState.unknown,
        relationship_completeness=RelationshipCompleteness.unknown,
    )

    none_finding = EvidenceFinding(
        code="no_upstream_dependencies_declared",
        category=EvidenceCategory.dependency_context,
        severity=EvidenceSeverity.info,
        message="No upstream dependencies were declared.",
        effects=[],
        evidence_state=EvidenceState.declared,
        relationship_completeness=RelationshipCompleteness.none,
    )

    assert unknown_finding.relationship_completeness == RelationshipCompleteness.unknown
    assert none_finding.relationship_completeness == RelationshipCompleteness.none


def test_review_with_no_findings_is_decision_grade() -> None:
    review = build_evidence_review([], asset_id="asset-id")

    assert review.evidence_score == 1.0
    assert review.confidence_cap == 1.0
    assert review.decision_grade == DecisionGrade.decision_grade
    assert review.human_review_required is False
    assert review.findings == []


def test_evidence_models_reject_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        EvidenceFinding.model_validate(
            {
                "code": "bad",
                "category": "business_context",
                "severity": "low",
                "message": "Unexpected field should be rejected.",
                "unexpected": True,
            }
        )


from qstriage.cbom import import_cbom_inventory
from qstriage.evidence import review_asset_evidence, review_inventory_evidence
from qstriage.models import CryptographicAsset, Dependency, Inventory


def _complete_asset() -> CryptographicAsset:
    return CryptographicAsset(
        id="asset-1",
        name="Asset 1",
        environment="prod",
        asset_type="service",
        protocol="tls",
        algorithm="RSA-2048",
        key_size_bits=2048,
        data_class="customer_pii",
        retention_years=7,
        exposure="internet",
        criticality="high",
        local_blast_radius="high",
        migration_effort="medium",
    )


def test_complete_user_declared_asset_is_decision_grade() -> None:
    review = review_asset_evidence(_complete_asset())

    assert review.decision_grade == DecisionGrade.decision_grade
    assert review.human_review_required is False
    assert review.evidence_score == 1.0
    assert review.confidence_cap == 1.0
    assert review.findings == []


def test_unknown_algorithm_blocks_decision_grade() -> None:
    asset = _complete_asset().model_copy(update={"algorithm": "unknown", "key_size_bits": None})

    review = review_asset_evidence(asset)

    assert review.decision_grade == DecisionGrade.not_decision_grade
    assert "unknown_algorithm" in review.blocking_finding_codes
    assert any(finding.code == "unknown_algorithm" for finding in review.findings)


def test_unverified_pqc_parameters_create_distinct_critical_blocking_finding() -> None:
    asset = _complete_asset().model_copy(
        update={"algorithm": "ML-KEM-9999", "key_size_bits": None}
    )

    review = review_asset_evidence(asset)
    finding = next(
        finding
        for finding in review.findings
        if finding.code == "unverified_algorithm_parameters"
    )

    assert review.decision_grade == DecisionGrade.not_decision_grade
    assert review.human_review_required is True
    assert review.confidence_cap <= 0.4
    assert finding.category == EvidenceCategory.cryptographic_context
    assert finding.severity == EvidenceSeverity.critical
    assert finding.effects == [
        EvidenceEffect.confidence_capped,
        EvidenceEffect.decision_grade_blocked,
        EvidenceEffect.human_review_required,
    ]
    assert finding.human_action is not None
    assert finding.human_action.description == (
        "Verify the exact algorithm version and parameter set for the affected asset."
    )
    assert "unknown_algorithm" not in review.blocking_finding_codes


def test_cbom_imported_assets_are_not_decision_grade_without_business_context() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")

    reviews = review_inventory_evidence(inventory, source_type="cyclonedx_cbom")
    review_by_asset = {review.asset_id: review for review in reviews}
    rsa_review = review_by_asset["crypto-rsa-2048"]
    finding_codes = {finding.code for finding in rsa_review.findings}

    assert rsa_review.decision_grade == DecisionGrade.not_decision_grade
    assert rsa_review.human_review_required is True
    assert "missing_data_class" in finding_codes
    assert "defaulted_retention_years" in finding_codes
    assert "missing_exposure" in finding_codes
    assert "defaulted_criticality" in finding_codes
    assert "unknown_dependency_completeness" in finding_codes


def test_cbom_dependency_context_is_known_unknown() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")

    review = review_inventory_evidence(inventory, source_type="cyclonedx_cbom")[0]
    dependency_findings = [
        finding
        for finding in review.findings
        if finding.code == "unknown_dependency_completeness"
    ]

    assert len(dependency_findings) == 1
    assert dependency_findings[0].relationship_completeness == RelationshipCompleteness.unknown
    assert dependency_findings[0].evidence_state == EvidenceState.unknown


def test_declared_qstriage_dependencies_are_recorded_as_known_context() -> None:
    asset_1 = _complete_asset()
    asset_2 = _complete_asset().model_copy(
        update={
            "id": "asset-2",
            "name": "Asset 2",
            "algorithm": "ML-KEM-768",
            "key_size_bits": None,
        }
    )
    inventory = Inventory(
        assets=[asset_1, asset_2],
        dependencies=[
            Dependency(
                id="dep-1",
                source="asset-1",
                target="asset-2",
                direction="outbound",
                dependency_type="api_call",
                protocol="https",
                weight=0.8,
                criticality="high",
                carries_crypto_context=True,
            )
        ],
    )

    reviews = review_inventory_evidence(inventory)
    review_by_asset = {review.asset_id: review for review in reviews}

    assert any(
        finding.code == "declared_qstriage_dependency_context"
        for finding in review_by_asset["asset-1"].findings
    )
    assert any(
        finding.relationship_completeness == RelationshipCompleteness.known
        for finding in review_by_asset["asset-1"].findings
    )


def test_informational_findings_do_not_degrade_evidence_confidence() -> None:
    finding = EvidenceFinding(
        code="declared_qstriage_dependency_context",
        category=EvidenceCategory.dependency_context,
        severity=EvidenceSeverity.info,
        message="QSTriage dependency context is declared.",
        effects=[],
        evidence_state=EvidenceState.declared,
        relationship_completeness=RelationshipCompleteness.known,
    )

    review = build_evidence_review([finding], asset_id="asset-id")

    assert review.evidence_score == 1.0
    assert review.confidence_cap == 1.0
    assert review.decision_grade == DecisionGrade.decision_grade
    assert review.human_review_required is False
