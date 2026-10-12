from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from qstriage.context import (
    ContextEffect,
    ContextValueState,
    NormalizedAssetContext,
    is_cbom_imported_asset,
    normalize_asset_context,
)
from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    Dependency,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    Inventory,
    RelationshipEvidenceCompleteness,
)
from qstriage.standards import (
    KeySizeRequirement,
    classify_algorithm,
    key_size_requirement,
    requires_parameter_verification,
)


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
        if finding.severity == EvidenceSeverity.info and not finding.effects:
            continue

        penalty += max(
            _SEVERITY_SCORE_PENALTY[finding.severity],
            _STATE_SCORE_PENALTY[finding.evidence_state],
        )

    return round(max(0.0, 1.0 - penalty), 4)


def _calculate_confidence_cap(findings: list[EvidenceFinding]) -> float:
    cap = 1.0

    for finding in findings:
        if finding.severity == EvidenceSeverity.info and not finding.effects:
            continue

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






def review_inventory_evidence(
    inventory: Inventory,
    *,
    source_type: str = "qstriage_inventory",
) -> list[EvidenceReview]:
    dependency_count_by_asset = _dependency_count_by_asset(inventory.dependencies)
    evidence_by_asset = (
        inventory.evidence.assets if inventory.evidence is not None else {}
    )

    return [
        review_asset_evidence(
            asset,
            source_type=source_type,
            dependency_count=dependency_count_by_asset.get(asset.id, 0),
            asset_evidence=evidence_by_asset.get(asset.id),
        )
        for asset in inventory.assets
    ]


def review_asset_evidence(
    asset: CryptographicAsset,
    *,
    source_type: str = "qstriage_inventory",
    dependency_count: int = 0,
    asset_evidence: AssetEvidenceAssertions | None = None,
) -> EvidenceReview:
    findings: list[EvidenceFinding] = []
    is_cbom_imported = is_cbom_imported_asset(asset, source_type)
    context = normalize_asset_context(asset, asset_evidence, source_type=source_type)

    findings.extend(_context_findings(asset, context, ("data_class", "retention_years", "exposure")))
    findings.extend(_cryptographic_context_findings(asset))
    findings.extend(
        _context_findings(
            asset, context, ("criticality", "local_blast_radius", "migration_effort")
        )
    )
    findings.extend(
        _dependency_context_findings(
            asset,
            is_cbom_imported=is_cbom_imported,
            dependency_count=dependency_count,
            asset_evidence=asset_evidence,
        )
    )

    return build_evidence_review(findings, asset_id=asset.id)


_CONTEXT_CATEGORY = {
    "data_class": EvidenceCategory.business_context,
    "retention_years": EvidenceCategory.business_context,
    "exposure": EvidenceCategory.business_context,
    "criticality": EvidenceCategory.supply_chain_context,
    "local_blast_radius": EvidenceCategory.supply_chain_context,
    "migration_effort": EvidenceCategory.supply_chain_context,
}

_CONTEXT_EXPECTED_VALUE = {
    "retention_years": "integer number of years, 0 only when explicitly justified",
    "criticality": "low, medium, high, or critical based on business context",
    "local_blast_radius": "low, medium, high, or critical based on business context",
    "migration_effort": "low, medium, high, or critical based on business context",
}

_CONTEXT_UNRESOLVED_EFFECT = {
    "data_class": "PDR remains not decision-grade.",
    "retention_years": "Long-lived confidentiality risk cannot be decision-grade.",
    "exposure": "Exposure-driven migration priority remains unreliable.",
    "criticality": "Confidence remains capped by defaulted CBOM-derived context.",
    "local_blast_radius": "Confidence remains capped by defaulted CBOM-derived context.",
    "migration_effort": "Confidence remains capped by defaulted CBOM-derived context.",
}

_CONTEXT_EVIDENCE_STATE = {
    ContextValueState.missing: EvidenceState.no_assertion,
    ContextValueState.redacted: EvidenceState.redacted,
    ContextValueState.unmapped: EvidenceState.unknown,
    ContextValueState.defaulted: EvidenceState.defaulted,
}


def _context_findings(
    asset: CryptographicAsset,
    context: NormalizedAssetContext,
    field_names: tuple[str, ...],
) -> list[EvidenceFinding]:
    """Evidence findings for unresolved business context, from the resolver."""

    findings: list[EvidenceFinding] = []
    for resolved in context.fields:
        if resolved.field not in field_names or not resolved.requires_verification:
            continue

        blocking = resolved.effect is ContextEffect.block
        effects = (
            [
                EvidenceEffect.confidence_capped,
                EvidenceEffect.decision_grade_blocked,
                EvidenceEffect.human_review_required,
            ]
            if blocking
            else [EvidenceEffect.confidence_capped, EvidenceEffect.human_review_required]
        )
        evidence_state = _CONTEXT_EVIDENCE_STATE[resolved.state]
        if resolved.state is ContextValueState.missing and resolved.source_reference is not None:
            evidence_state = EvidenceState.unknown
        expected = _CONTEXT_EXPECTED_VALUE.get(
            resolved.field, "one of: " + ", ".join(resolved.accepted_values)
        )
        verb = "Set" if blocking else "Confirm or replace"

        findings.append(
            EvidenceFinding(
                code=resolved.reason_code or f"unresolved_{resolved.field}",
                category=_CONTEXT_CATEGORY[resolved.field],
                severity=EvidenceSeverity(resolved.severity or "medium"),
                message=resolved.message or f"{resolved.field_path} is unresolved.",
                effects=effects,
                asset_id=asset.id,
                field_path=resolved.field_path,
                evidence_state=evidence_state,
                provenance=EvidenceProvenance(resolved.provenance),
                human_action=HumanAction(
                    description=f"{verb} {resolved.field} for asset '{asset.id}'.",
                    field_path=resolved.field_path,
                    expected_value_type=expected,
                    effect_if_unresolved=_CONTEXT_UNRESOLVED_EFFECT[resolved.field],
                ),
            )
        )

    return findings



def _cryptographic_context_findings(asset: CryptographicAsset) -> list[EvidenceFinding]:
    findings: list[EvidenceFinding] = []
    classification = classify_algorithm(asset.algorithm)

    if requires_parameter_verification(classification):
        findings.append(
            EvidenceFinding(
                code="unverified_algorithm_parameters",
                category=EvidenceCategory.cryptographic_context,
                severity=EvidenceSeverity.critical,
                message=(
                    "The cryptographic family is recognized, but the exact algorithm "
                    "version or parameter set is missing or unsupported."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].algorithm",
                evidence_state=EvidenceState.unknown,
                provenance=EvidenceProvenance.user_declared,
                human_action=HumanAction(
                    description=(
                        "Verify the exact algorithm version and parameter set for "
                        "the affected asset."
                    ),
                    field_path=f"assets[{asset.id}].algorithm",
                    expected_value_type=(
                        "exact supported cryptographic algorithm identifier and "
                        "parameter set"
                    ),
                    effect_if_unresolved=(
                        "PQC classification cannot be decision-grade."
                    ),
                ),
            )
        )
    elif (
        _is_unknown_text(asset.algorithm)
        or classification.algorithm_family == "unknown"
    ):
        findings.append(
            EvidenceFinding(
                code="unknown_algorithm",
                category=EvidenceCategory.cryptographic_context,
                severity=EvidenceSeverity.critical,
                message=(
                    "Cryptographic algorithm is unknown or unsupported by the "
                    "current classifier."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].algorithm",
                evidence_state=EvidenceState.unknown,
                provenance=EvidenceProvenance.user_declared,
                human_action=HumanAction(
                    description=f"Set a recognized algorithm for asset '{asset.id}'.",
                    field_path=f"assets[{asset.id}].algorithm",
                    expected_value_type="recognized cryptographic algorithm identifier",
                    effect_if_unresolved="PQC classification cannot be decision-grade.",
                ),
            )
        )

    if (
        asset.key_size_bits is None
        and key_size_requirement(classification) == KeySizeRequirement.required
    ):
        findings.append(
            EvidenceFinding(
                code="missing_key_size_bits",
                category=EvidenceCategory.cryptographic_context,
                severity=EvidenceSeverity.medium,
                message=(
                    "Key size is missing for an algorithm where key length "
                    "materially affects cryptographic risk."
                ),
                effects=[
                    EvidenceEffect.confidence_degraded,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].key_size_bits",
                evidence_state=EvidenceState.no_assertion,
                provenance=EvidenceProvenance.user_declared,
                human_action=HumanAction(
                    description=f"Set key_size_bits for asset '{asset.id}'.",
                    field_path=f"assets[{asset.id}].key_size_bits",
                    expected_value_type="integer key length in bits",
                    effect_if_unresolved="Confidence remains degraded.",
                ),
            )
        )

    return findings


def _dependency_context_findings(
    asset: CryptographicAsset,
    *,
    is_cbom_imported: bool,
    dependency_count: int,
    asset_evidence: AssetEvidenceAssertions | None,
) -> list[EvidenceFinding]:
    if is_cbom_imported:
        relationship_assertion = (
            asset_evidence.relationship_completeness if asset_evidence else None
        )
        if relationship_assertion is not None and relationship_assertion.value in {
            RelationshipEvidenceCompleteness.none,
            RelationshipEvidenceCompleteness.known,
        }:
            return []

        relationship_completeness = RelationshipCompleteness.unknown
        evidence_state = EvidenceState.unknown
        provenance = EvidenceProvenance.tool_generated
        if relationship_assertion is not None:
            relationship_completeness = RelationshipCompleteness(
                relationship_assertion.value.value
            )
            evidence_state = _assertion_state(
                relationship_assertion, default=EvidenceState.unknown
            )
            provenance = _assertion_provenance(
                relationship_assertion, default=EvidenceProvenance.tool_generated
            )

        return [
            EvidenceFinding(
                code="unknown_dependency_completeness",
                category=EvidenceCategory.dependency_context,
                severity=EvidenceSeverity.high,
                message=(
                    "CBOM dependency relationships were not imported as QSTriage "
                    "blast-radius dependencies; relationship completeness is unknown."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                evidence_state=evidence_state,
                provenance=provenance,
                relationship_completeness=relationship_completeness,
                human_action=HumanAction(
                    description=(
                        f"Add QSTriage dependency context or relationship completeness "
                        f"for asset '{asset.id}'."
                    ),
                    field_path="dependencies",
                    expected_value_type="QSTriage dependencies or explicit relationship completeness",
                    effect_if_unresolved="Blast-radius reasoning remains not decision-grade.",
                ),
            )
        ]

    if dependency_count == 0:
        return []

    return [
        EvidenceFinding(
            code="declared_qstriage_dependency_context",
            category=EvidenceCategory.dependency_context,
            severity=EvidenceSeverity.info,
            message="QSTriage dependency context is declared for this asset.",
            effects=[],
            asset_id=asset.id,
            evidence_state=EvidenceState.declared,
            provenance=EvidenceProvenance.user_declared,
            relationship_completeness=RelationshipCompleteness.known,
        )
    ]


def _dependency_count_by_asset(dependencies: list[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}

    for dependency in dependencies:
        counts[dependency.source] = counts.get(dependency.source, 0) + 1
        counts[dependency.target] = counts.get(dependency.target, 0) + 1

    return counts


def _is_unknown_text(value: str | None) -> bool:
    return value is None or value.strip().lower() in {"", "unknown", "no assertion"}


def _assertion_state(
    assertion: FieldEvidenceAssertion | None,
    *,
    default: EvidenceState,
) -> EvidenceState:
    if assertion is None:
        return default
    return {
        EvidenceAssertionState.declared: EvidenceState.declared,
        EvidenceAssertionState.verified: EvidenceState.verified,
    }[assertion.state]


def _assertion_provenance(
    assertion: FieldEvidenceAssertion | None,
    *,
    default: EvidenceProvenance,
) -> EvidenceProvenance:
    if assertion is None:
        return default
    return {
        EvidenceAssertionProvenance.user_declared: EvidenceProvenance.user_declared,
        EvidenceAssertionProvenance.supplier_authoritative: (
            EvidenceProvenance.supplier_authoritative
        ),
        EvidenceAssertionProvenance.third_party_asserted: (
            EvidenceProvenance.third_party_asserted
        ),
        EvidenceAssertionProvenance.tool_generated: EvidenceProvenance.tool_generated,
    }[assertion.provenance]


