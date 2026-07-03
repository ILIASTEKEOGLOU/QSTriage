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
