from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from qstriage.evidence import DecisionGrade, EvidenceCategory, EvidenceReview
from qstriage.models import RiskLevel
from qstriage.policy import PolicyEvaluationResult
from qstriage.scoring import ScoreResult
from qstriage.standards import AlgorithmClassification


class ExecutionState(str, Enum):
    justified = "justified"
    gated = "gated"
    verification_first = "verification_first"


class VerificationPriority(str, Enum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"


class ActionType(str, Enum):
    migration_planning = "migration_planning"
    simulate_before_migration = "simulate_before_migration"
    retain_monitor = "retain_monitor"
    key_strength_review = "key_strength_review"
    primitive_review = "primitive_review"
    manual_crypto_verification = "manual_crypto_verification"


class VerificationRequirement(str, Enum):
    cryptographic_identity = "cryptographic_identity"
    cryptographic_parameters = "cryptographic_parameters"
    business_context = "business_context"
    dependency_context = "dependency_context"
    supply_chain_context = "supply_chain_context"
    evidence_quality = "evidence_quality"
    policy_resolution = "policy_resolution"


@dataclass(frozen=True)
class DecisionContext:
    missing_requirements: tuple[VerificationRequirement, ...] = ()


@dataclass(frozen=True)
class DecisionThresholds:
    minimum_decision_grade_confidence: float = 0.75
    high_priority_human_review: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_decision_grade_confidence <= 1.0:
            raise ValueError(
                "minimum_decision_grade_confidence must be between 0 and 1"
            )


@dataclass(frozen=True)
class CanonicalDecision:
    risk_attention_score: float
    risk_attention_band: str
    execution_state: ExecutionState
    action_type: ActionType
    verification_priority: VerificationPriority
    verification_requirements: tuple[VerificationRequirement, ...]
    decision_confidence: float
    human_review_required: bool
    reason_codes: tuple[str, ...]


_REQUIREMENT_ORDER = {
    VerificationRequirement.cryptographic_identity: 0,
    VerificationRequirement.cryptographic_parameters: 1,
    VerificationRequirement.business_context: 2,
    VerificationRequirement.dependency_context: 3,
    VerificationRequirement.supply_chain_context: 4,
    VerificationRequirement.evidence_quality: 5,
    VerificationRequirement.policy_resolution: 6,
}

_PRIORITY_ORDER = {
    VerificationPriority.none: 0,
    VerificationPriority.low: 1,
    VerificationPriority.medium: 2,
    VerificationPriority.high: 3,
}

_REVIEW_ACTIONS = {
    ActionType.key_strength_review,
    ActionType.primitive_review,
    ActionType.manual_crypto_verification,
}


def reconcile_decision(
    *,
    classification: AlgorithmClassification,
    score: ScoreResult,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    migration_effort: RiskLevel,
    context: DecisionContext | None = None,
    thresholds: DecisionThresholds | None = None,
) -> CanonicalDecision:
    """Reconcile existing signals into one deterministic decision contract.

    Risk score and band pass through unchanged as attention signals. The legacy
    score-derived action is intentionally ignored: classification chooses the
    action family, while evidence, policy, confidence, and context control
    execution and verification.
    """

    if not 0.0 <= decision_confidence <= 1.0:
        raise ValueError("decision_confidence must be between 0 and 1")

    context = context or DecisionContext()
    thresholds = thresholds or DecisionThresholds()

    action_type = _action_type(classification, migration_effort)
    requirements = _verification_requirements(
        classification=classification,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        context=context,
        thresholds=thresholds,
    )
    execution_state = _execution_state(
        classification=classification,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        thresholds=thresholds,
    )
    verification_priority = _verification_priority(
        classification=classification,
        score=score,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        requirements=requirements,
        execution_state=execution_state,
        thresholds=thresholds,
    )
    human_review_required = _human_review_required(
        action_type=action_type,
        score=score,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        requirements=requirements,
        execution_state=execution_state,
        thresholds=thresholds,
    )
    reason_codes = _reason_codes(
        classification=classification,
        score=score,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        requirements=requirements,
        action_type=action_type,
        thresholds=thresholds,
    )

    return CanonicalDecision(
        risk_attention_score=score.priority_score,
        risk_attention_band=score.priority_band,
        execution_state=execution_state,
        action_type=action_type,
        verification_priority=verification_priority,
        verification_requirements=requirements,
        decision_confidence=decision_confidence,
        human_review_required=human_review_required,
        reason_codes=reason_codes,
    )


def _action_type(
    classification: AlgorithmClassification,
    migration_effort: RiskLevel,
) -> ActionType:
    if classification.standard_status == "unknown":
        return ActionType.manual_crypto_verification

    if classification.standard_status == "classical_public_key":
        if migration_effort in {RiskLevel.high, RiskLevel.critical}:
            return ActionType.simulate_before_migration
        return ActionType.migration_planning

    if classification.standard_status == "standardized_pqc":
        return ActionType.retain_monitor

    if classification.standard_status == "standardized_symmetric":
        return ActionType.key_strength_review

    if classification.standard_status == "standardized_hash":
        return ActionType.primitive_review

    return ActionType.manual_crypto_verification


def _verification_requirements(
    *,
    classification: AlgorithmClassification,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    context: DecisionContext,
    thresholds: DecisionThresholds,
) -> tuple[VerificationRequirement, ...]:
    requirements = set(context.missing_requirements)

    if classification.standard_status == "unknown":
        requirements.add(VerificationRequirement.cryptographic_identity)

    for finding in evidence_review.findings:
        if not finding.effects and not finding.requires_human_review:
            continue

        if finding.category == EvidenceCategory.business_context:
            requirements.add(VerificationRequirement.business_context)
        elif finding.category == EvidenceCategory.dependency_context:
            requirements.add(VerificationRequirement.dependency_context)
        elif finding.category == EvidenceCategory.supply_chain_context:
            requirements.add(VerificationRequirement.supply_chain_context)
        elif finding.category == EvidenceCategory.integrity_context:
            requirements.add(VerificationRequirement.evidence_quality)
        elif finding.category == EvidenceCategory.cryptographic_context:
            requirement = (
                VerificationRequirement.cryptographic_identity
                if finding.code == "unknown_algorithm"
                else VerificationRequirement.cryptographic_parameters
            )
            requirements.add(requirement)

    if policy_evaluation.blocking_rule_ids:
        requirements.add(VerificationRequirement.policy_resolution)

    evidence_is_blocking = (
        evidence_review.decision_grade == DecisionGrade.not_decision_grade
    )
    confidence_is_blocking = (
        decision_confidence < thresholds.minimum_decision_grade_confidence
    )
    if (evidence_is_blocking or confidence_is_blocking) and not requirements:
        requirements.add(VerificationRequirement.evidence_quality)

    return tuple(sorted(requirements, key=_REQUIREMENT_ORDER.__getitem__))


def _execution_state(
    *,
    classification: AlgorithmClassification,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    thresholds: DecisionThresholds,
) -> ExecutionState:
    if classification.standard_status == "unknown":
        return ExecutionState.verification_first

    if (
        evidence_review.decision_grade == DecisionGrade.not_decision_grade
        or policy_evaluation.blocking_rule_ids
        or decision_confidence < thresholds.minimum_decision_grade_confidence
    ):
        return ExecutionState.gated

    return ExecutionState.justified


def _verification_priority(
    *,
    classification: AlgorithmClassification,
    score: ScoreResult,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    requirements: tuple[VerificationRequirement, ...],
    execution_state: ExecutionState,
    thresholds: DecisionThresholds,
) -> VerificationPriority:
    candidates = [VerificationPriority.none]

    if execution_state == ExecutionState.verification_first:
        candidates.append(VerificationPriority.high)

    evidence_is_blocking = (
        evidence_review.decision_grade == DecisionGrade.not_decision_grade
    )
    policy_is_blocking = bool(policy_evaluation.blocking_rule_ids)
    has_cryptographic_uncertainty = any(
        requirement
        in {
            VerificationRequirement.cryptographic_identity,
            VerificationRequirement.cryptographic_parameters,
        }
        for requirement in requirements
    )
    known_crypto_pressure = (
        classification.quantum_status == "quantum_vulnerable"
        or score.priority_band in {"critical", "high"}
    )

    if evidence_is_blocking or policy_is_blocking:
        if has_cryptographic_uncertainty or known_crypto_pressure:
            candidates.append(VerificationPriority.high)
        else:
            candidates.append(VerificationPriority.medium)

    if decision_confidence < thresholds.minimum_decision_grade_confidence:
        candidates.append(_confidence_priority(score.priority_band))

    context_requirements = {
        VerificationRequirement.business_context,
        VerificationRequirement.dependency_context,
        VerificationRequirement.supply_chain_context,
    }
    if any(requirement in context_requirements for requirement in requirements):
        candidates.append(
            VerificationPriority.medium
            if known_crypto_pressure
            else VerificationPriority.low
        )

    if VerificationRequirement.evidence_quality in requirements:
        candidates.append(_confidence_priority(score.priority_band))

    return max(candidates, key=_PRIORITY_ORDER.__getitem__)


def _confidence_priority(risk_attention_band: str) -> VerificationPriority:
    if risk_attention_band in {"critical", "high"}:
        return VerificationPriority.high
    if risk_attention_band == "medium":
        return VerificationPriority.medium
    return VerificationPriority.low


def _human_review_required(
    *,
    action_type: ActionType,
    score: ScoreResult,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    requirements: tuple[VerificationRequirement, ...],
    execution_state: ExecutionState,
    thresholds: DecisionThresholds,
) -> bool:
    return (
        execution_state != ExecutionState.justified
        or bool(requirements)
        or evidence_review.human_review_required
        or policy_evaluation.human_review_required
        or decision_confidence < thresholds.minimum_decision_grade_confidence
        or (
            thresholds.high_priority_human_review
            and score.priority_band in {"critical", "high"}
        )
        or action_type in _REVIEW_ACTIONS
    )


def _reason_codes(
    *,
    classification: AlgorithmClassification,
    score: ScoreResult,
    evidence_review: EvidenceReview,
    policy_evaluation: PolicyEvaluationResult,
    decision_confidence: float,
    requirements: tuple[VerificationRequirement, ...],
    action_type: ActionType,
    thresholds: DecisionThresholds,
) -> tuple[str, ...]:
    reason_codes = [_classification_reason(classification)]

    relevant_evidence_codes = sorted(
        finding.code
        for finding in evidence_review.findings
        if finding.effects or finding.requires_human_review
    )
    reason_codes.extend(f"evidence:{code}" for code in relevant_evidence_codes)

    reason_codes.extend(
        f"policy:{rule_id}"
        for rule_id in sorted(
            finding.rule_id for finding in policy_evaluation.findings
        )
    )

    if decision_confidence < thresholds.minimum_decision_grade_confidence:
        reason_codes.append("confidence:below_decision_grade_threshold")

    reason_codes.extend(
        f"verification:{requirement.value}" for requirement in requirements
    )

    if score.priority_band in {"critical", "high"}:
        reason_codes.append(f"risk:{score.priority_band}_attention")

    if action_type == ActionType.simulate_before_migration:
        reason_codes.append("migration:simulation_required")

    return tuple(reason_codes)


def _classification_reason(classification: AlgorithmClassification) -> str:
    if classification.standard_status == "unknown":
        return "classification:unknown"
    if classification.quantum_status == "quantum_vulnerable":
        return "classification:quantum_vulnerable"
    if classification.standard_status == "standardized_pqc":
        return "classification:standardized_pqc"
    if classification.standard_status == "standardized_symmetric":
        return "classification:standardized_symmetric"
    if classification.standard_status == "standardized_hash":
        return "classification:standardized_hash"
    return f"classification:{classification.standard_status}"
