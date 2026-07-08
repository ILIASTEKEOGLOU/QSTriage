from qstriage.decision import (
    ActionType,
    DecisionContext,
    DecisionThresholds,
    ExecutionState,
    VerificationPriority,
    VerificationRequirement,
    reconcile_decision,
)
from qstriage.evidence import (
    EvidenceCategory,
    EvidenceEffect,
    EvidenceFinding,
    EvidenceSeverity,
    EvidenceState,
    build_evidence_review,
)
from qstriage.models import RiskLevel
from qstriage.policy import (
    PolicyEvaluationResult,
    PolicyFinding,
    PolicyRuleEffect,
    PolicySeverity,
)
from qstriage.scoring import ScoreBreakdown, ScoreResult
from qstriage.standards import classify_algorithm


def _score(*, value: float, band: str, legacy_action: str) -> ScoreResult:
    return ScoreResult(
        asset_id="asset-1",
        asset_name="Asset 1",
        priority_score=value,
        priority_band=band,
        recommended_action=legacy_action,
        confidence="high",
        breakdown=ScoreBreakdown(
            cryptographic_risk=0.0,
            shelf_life_risk=0.0,
            exposure_risk=0.0,
            criticality_score=0.0,
            graph_blast_radius=0.0,
            deadline_pressure=0.0,
            effort_penalty=0.0,
            total=value,
        ),
        explanation=[],
    )


def _policy_result(*findings: PolicyFinding) -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        policy_pack_id="nist-pqc-basic",
        policy_pack_version="0.2",
        policy_pack_hash="test-policy-hash",
        applied_rule_ids=[finding.rule_id for finding in findings],
        findings=list(findings),
    )


def _policy_finding(
    rule_id: str,
    *effects: PolicyRuleEffect,
    severity: PolicySeverity = PolicySeverity.high,
) -> PolicyFinding:
    return PolicyFinding(
        rule_id=rule_id,
        severity=severity,
        message=rule_id,
        effects=list(effects),
        asset_id="asset-1",
    )


def _evidence_finding(
    code: str,
    category: EvidenceCategory,
    *effects: EvidenceEffect,
    severity: EvidenceSeverity = EvidenceSeverity.high,
    state: EvidenceState = EvidenceState.unknown,
) -> EvidenceFinding:
    return EvidenceFinding(
        code=code,
        category=category,
        severity=severity,
        message=code,
        effects=list(effects),
        asset_id="asset-1",
        evidence_state=state,
    )


def test_known_vulnerable_public_key_keeps_risk_attention_and_migration_action() -> None:
    policy = _policy_result(
        _policy_finding(
            "quantum_vulnerable_public_key_requires_pqc_migration_review",
            PolicyRuleEffect.raises_priority,
            PolicyRuleEffect.requires_human_review,
        )
    )

    decision = reconcile_decision(
        classification=classify_algorithm("RSA-2048"),
        score=_score(
            value=82.0,
            band="high",
            legacy_action="review soon and include in near-term migration backlog",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=policy,
        decision_confidence=0.9,
        migration_effort=RiskLevel.medium,
    )

    assert decision.risk_attention_score == 82.0
    assert decision.risk_attention_band == "high"
    assert decision.execution_state is ExecutionState.justified
    assert decision.action_type is ActionType.migration_planning
    assert decision.verification_priority is VerificationPriority.none
    assert decision.verification_requirements == ()
    assert decision.human_review_required is True


def test_standardized_pqc_is_retained_even_when_legacy_score_action_says_migrate() -> None:
    policy = _policy_result(
        _policy_finding(
            "standardized_pqc_can_be_retained_with_operational_review",
            PolicyRuleEffect.adds_policy_context,
            PolicyRuleEffect.recommends_target_state,
            severity=PolicySeverity.info,
        )
    )

    decision = reconcile_decision(
        classification=classify_algorithm("ML-KEM-768"),
        score=_score(
            value=78.0,
            band="high",
            legacy_action="review soon and include in near-term migration backlog",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=policy,
        decision_confidence=0.95,
        migration_effort=RiskLevel.low,
    )

    assert decision.execution_state is ExecutionState.justified
    assert decision.action_type is ActionType.retain_monitor
    assert decision.verification_priority is VerificationPriority.none
    assert decision.verification_requirements == ()
    assert decision.reason_codes == (
        "classification:standardized_pqc",
        "policy:standardized_pqc_can_be_retained_with_operational_review",
        "risk:high_attention",
    )


def test_unknown_algorithm_with_incomplete_evidence_is_verification_first() -> None:
    evidence = build_evidence_review(
        [
            _evidence_finding(
                "unknown_algorithm",
                EvidenceCategory.cryptographic_context,
                EvidenceEffect.confidence_capped,
                EvidenceEffect.decision_grade_blocked,
                EvidenceEffect.human_review_required,
            ),
            _evidence_finding(
                "missing_data_class",
                EvidenceCategory.business_context,
                EvidenceEffect.confidence_capped,
                EvidenceEffect.decision_grade_blocked,
                EvidenceEffect.human_review_required,
            ),
        ],
        asset_id="asset-1",
    )
    policy = _policy_result(
        _policy_finding(
            "unknown_algorithm_requires_manual_crypto_review",
            PolicyRuleEffect.caps_confidence,
            PolicyRuleEffect.blocks_decision_grade,
            PolicyRuleEffect.requires_human_review,
            severity=PolicySeverity.critical,
        )
    )

    decision = reconcile_decision(
        classification=classify_algorithm("MysteryCrypto-1"),
        score=_score(
            value=28.0,
            band="low",
            legacy_action="defer; keep inventory evidence current",
        ),
        evidence_review=evidence,
        policy_evaluation=policy,
        decision_confidence=0.4,
        migration_effort=RiskLevel.low,
    )

    assert decision.execution_state is ExecutionState.verification_first
    assert decision.action_type is ActionType.manual_crypto_verification
    assert decision.verification_priority is VerificationPriority.high
    assert decision.verification_requirements == (
        VerificationRequirement.cryptographic_identity,
        VerificationRequirement.business_context,
        VerificationRequirement.policy_resolution,
    )
    assert decision.reason_codes == (
        "classification:unknown",
        "evidence:missing_data_class",
        "evidence:unknown_algorithm",
        "policy:unknown_algorithm_requires_manual_crypto_review",
        "confidence:below_decision_grade_threshold",
        "verification:cryptographic_identity",
        "verification:business_context",
        "verification:policy_resolution",
    )


def test_high_risk_with_low_confidence_stays_high_risk_but_is_gated() -> None:
    decision = reconcile_decision(
        classification=classify_algorithm("RSA-2048"),
        score=_score(
            value=91.0,
            band="critical",
            legacy_action="prioritize for early PQC migration planning",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=_policy_result(),
        decision_confidence=0.6,
        migration_effort=RiskLevel.medium,
        thresholds=DecisionThresholds(minimum_decision_grade_confidence=0.75),
    )

    assert decision.risk_attention_score == 91.0
    assert decision.risk_attention_band == "critical"
    assert decision.execution_state is ExecutionState.gated
    assert decision.action_type is ActionType.migration_planning
    assert decision.verification_priority is VerificationPriority.high
    assert decision.verification_requirements == (
        VerificationRequirement.evidence_quality,
    )
    assert decision.human_review_required is True


def test_low_risk_blocking_uncertainty_is_not_suppressed_by_attention_score() -> None:
    evidence = build_evidence_review(
        [
            _evidence_finding(
                "unknown_dependency_completeness",
                EvidenceCategory.dependency_context,
                EvidenceEffect.confidence_capped,
                EvidenceEffect.decision_grade_blocked,
                EvidenceEffect.human_review_required,
            )
        ],
        asset_id="asset-1",
    )

    decision = reconcile_decision(
        classification=classify_algorithm("ML-DSA-65"),
        score=_score(
            value=24.0,
            band="low",
            legacy_action="defer; keep inventory evidence current",
        ),
        evidence_review=evidence,
        policy_evaluation=_policy_result(),
        decision_confidence=0.5,
        migration_effort=RiskLevel.low,
    )

    assert decision.risk_attention_band == "low"
    assert decision.execution_state is ExecutionState.gated
    assert decision.action_type is ActionType.retain_monitor
    assert decision.verification_priority is VerificationPriority.medium
    assert decision.verification_requirements == (
        VerificationRequirement.dependency_context,
    )


def test_known_vulnerable_algorithm_preserves_migration_action_when_context_is_missing() -> None:
    decision = reconcile_decision(
        classification=classify_algorithm("ECDSA P-256"),
        score=_score(
            value=63.0,
            band="medium",
            legacy_action="monitor and reassess after higher-risk assets",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=_policy_result(),
        decision_confidence=0.9,
        migration_effort=RiskLevel.medium,
        context=DecisionContext(
            missing_requirements=(VerificationRequirement.business_context,)
        ),
    )

    assert decision.execution_state is ExecutionState.justified
    assert decision.action_type is ActionType.migration_planning
    assert decision.verification_priority is VerificationPriority.medium
    assert decision.verification_requirements == (
        VerificationRequirement.business_context,
    )
    assert decision.reason_codes == (
        "classification:quantum_vulnerable",
        "verification:business_context",
    )


def test_blocking_policy_overrides_contradictory_legacy_action() -> None:
    policy = _policy_result(
        _policy_finding(
            "manual_policy_resolution_required",
            PolicyRuleEffect.blocks_decision_grade,
            PolicyRuleEffect.requires_human_review,
        )
    )

    decision = reconcile_decision(
        classification=classify_algorithm("RSA-2048"),
        score=_score(
            value=36.0,
            band="low",
            legacy_action="defer; keep inventory evidence current",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=policy,
        decision_confidence=0.9,
        migration_effort=RiskLevel.low,
    )

    assert decision.risk_attention_band == "low"
    assert decision.execution_state is ExecutionState.gated
    assert decision.action_type is ActionType.migration_planning
    assert decision.verification_priority is VerificationPriority.high
    assert decision.verification_requirements == (
        VerificationRequirement.policy_resolution,
    )
    assert "policy:manual_policy_resolution_required" in decision.reason_codes


def test_no_conflict_high_effort_migration_preserves_simulation_semantics() -> None:
    decision = reconcile_decision(
        classification=classify_algorithm("RSA-3072"),
        score=_score(
            value=88.0,
            band="critical",
            legacy_action="simulate before migration; prepare staged remediation plan",
        ),
        evidence_review=build_evidence_review([], asset_id="asset-1"),
        policy_evaluation=_policy_result(),
        decision_confidence=0.9,
        migration_effort=RiskLevel.high,
    )

    assert decision.execution_state is ExecutionState.justified
    assert decision.action_type is ActionType.simulate_before_migration
    assert decision.verification_priority is VerificationPriority.none
    assert decision.human_review_required is True
    assert decision.reason_codes == (
        "classification:quantum_vulnerable",
        "risk:critical_attention",
        "migration:simulation_required",
    )
