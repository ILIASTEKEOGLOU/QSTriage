from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


EVIDENCE_REVIEW_VERSION = "0.1"


class EvidenceSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EvidenceCategory(str, Enum):
    business_context = "business_context"
    cryptographic_context = "cryptographic_context"
    dependency_context = "dependency_context"
    supply_chain_context = "supply_chain_context"
    integrity_context = "integrity_context"


class EvidenceEffect(str, Enum):
    confidence_degraded = "confidence_degraded"
    confidence_capped = "confidence_capped"
    decision_grade_blocked = "decision_grade_blocked"
    human_review_required = "human_review_required"


class EvidenceState(str, Enum):
    verified = "verified"
    declared = "declared"
    defaulted = "defaulted"
    no_assertion = "no_assertion"
    no_value = "no_value"
    redacted = "redacted"
    unknown = "unknown"


class EvidenceMaturity(str, Enum):
    minimum_expected = "minimum_expected"
    recommended_practice = "recommended_practice"
    aspirational_goal = "aspirational_goal"


class EvidenceProvenance(str, Enum):
    supplier_authoritative = "supplier_authoritative"
    third_party_asserted = "third_party_asserted"
    tool_generated = "tool_generated"
    qstriage_default = "qstriage_default"
    user_declared = "user_declared"


class RelationshipCompleteness(str, Enum):
    unknown = "unknown"
    none = "none"
    partial = "partial"
    known = "known"


class DecisionGrade(str, Enum):
    decision_grade = "decision_grade"
    not_decision_grade = "not_decision_grade"


class HumanAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1)
    field_path: str | None = None
    expected_value_type: str | None = None
    effect_if_unresolved: str | None = None


class EvidenceFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    category: EvidenceCategory
    severity: EvidenceSeverity
    message: str = Field(min_length=1)
    effects: list[EvidenceEffect] = Field(default_factory=list)
    asset_id: str | None = None
    field_path: str | None = None
    evidence_state: EvidenceState = EvidenceState.unknown
    maturity: EvidenceMaturity = EvidenceMaturity.minimum_expected
    provenance: EvidenceProvenance = EvidenceProvenance.tool_generated
    relationship_completeness: RelationshipCompleteness | None = None
    human_action: HumanAction | None = None

    @property
    def blocks_decision_grade(self) -> bool:
        return EvidenceEffect.decision_grade_blocked in self.effects

    @property
    def requires_human_review(self) -> bool:
        return (
            EvidenceEffect.human_review_required in self.effects
            or self.human_action is not None
            or self.blocks_decision_grade
        )


class EvidenceReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_version: str = EVIDENCE_REVIEW_VERSION
    asset_id: str | None = None
    evidence_score: float = Field(ge=0.0, le=1.0)
    confidence_cap: float = Field(ge=0.0, le=1.0)
    decision_grade: DecisionGrade
    human_review_required: bool
    findings: list[EvidenceFinding]
    blocking_finding_codes: list[str]
    recommended_next_actions: list[str]


_SEVERITY_SCORE_PENALTY: dict[EvidenceSeverity, float] = {
    EvidenceSeverity.info: 0.0,
    EvidenceSeverity.low: 0.05,
    EvidenceSeverity.medium: 0.12,
    EvidenceSeverity.high: 0.25,
    EvidenceSeverity.critical: 0.4,
}

_STATE_SCORE_PENALTY: dict[EvidenceState, float] = {
    EvidenceState.verified: 0.0,
    EvidenceState.declared: 0.02,
    EvidenceState.defaulted: 0.1,
    EvidenceState.no_assertion: 0.18,
    EvidenceState.no_value: 0.03,
    EvidenceState.redacted: 0.22,
    EvidenceState.unknown: 0.15,
}

_SEVERITY_CONFIDENCE_CAP: dict[EvidenceSeverity, float] = {
    EvidenceSeverity.info: 1.0,
    EvidenceSeverity.low: 0.9,
    EvidenceSeverity.medium: 0.8,
    EvidenceSeverity.high: 0.65,
    EvidenceSeverity.critical: 0.4,
}

_STATE_CONFIDENCE_CAP: dict[EvidenceState, float] = {
    EvidenceState.verified: 1.0,
    EvidenceState.declared: 0.95,
    EvidenceState.defaulted: 0.75,
    EvidenceState.no_assertion: 0.65,
    EvidenceState.no_value: 0.9,
    EvidenceState.redacted: 0.6,
    EvidenceState.unknown: 0.7,
}

_EFFECT_CONFIDENCE_CAP: dict[EvidenceEffect, float] = {
    EvidenceEffect.confidence_degraded: 0.85,
    EvidenceEffect.confidence_capped: 0.7,
    EvidenceEffect.decision_grade_blocked: 0.5,
    EvidenceEffect.human_review_required: 0.9,
}


def build_evidence_review(
    findings: Iterable[EvidenceFinding],
    *,
    asset_id: str | None = None,
    decision_grade_threshold: float = 0.75,
) -> EvidenceReview:
    collected_findings = list(findings)
    evidence_score = _calculate_evidence_score(collected_findings)
    confidence_cap = _calculate_confidence_cap(collected_findings)

    blocking_codes = [
        finding.code
        for finding in collected_findings
        if finding.blocks_decision_grade
    ]

    decision_grade = (
        DecisionGrade.not_decision_grade
        if blocking_codes or confidence_cap < decision_grade_threshold
        else DecisionGrade.decision_grade
    )

    recommended_next_actions = _recommended_next_actions(collected_findings)

    return EvidenceReview(
        asset_id=asset_id,
        evidence_score=evidence_score,
        confidence_cap=confidence_cap,
        decision_grade=decision_grade,
        human_review_required=(
            decision_grade == DecisionGrade.not_decision_grade
            or any(finding.requires_human_review for finding in collected_findings)
        ),
        findings=collected_findings,
        blocking_finding_codes=blocking_codes,
        recommended_next_actions=recommended_next_actions,
    )


def _calculate_evidence_score(findings: list[EvidenceFinding]) -> float:
    penalty = 0.0

    for finding in findings:
        penalty += max(
            _SEVERITY_SCORE_PENALTY[finding.severity],
            _STATE_SCORE_PENALTY[finding.evidence_state],
        )

    return round(max(0.0, 1.0 - penalty), 4)


def _calculate_confidence_cap(findings: list[EvidenceFinding]) -> float:
    cap = 1.0

    for finding in findings:
        cap = min(
            cap,
            _SEVERITY_CONFIDENCE_CAP[finding.severity],
            _STATE_CONFIDENCE_CAP[finding.evidence_state],
        )

        for effect in finding.effects:
            cap = min(cap, _EFFECT_CONFIDENCE_CAP[effect])

    return round(cap, 4)


def _recommended_next_actions(findings: list[EvidenceFinding]) -> list[str]:
    actions: list[str] = []

    for finding in findings:
        if finding.human_action is None:
            continue
        if finding.human_action.description not in actions:
            actions.append(finding.human_action.description)

    return actions
