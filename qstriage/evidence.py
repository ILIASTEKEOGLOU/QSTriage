from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    Dependency,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    Inventory,
    RelationshipEvidenceCompleteness,
    RiskLevel,
)
from qstriage.standards import classify_algorithm


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




CBOM_IMPORT_NOTE_MARKER = "Imported from CycloneDX CBOM"


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
    is_cbom_imported = _is_cbom_imported_asset(asset, source_type)

    findings.extend(
        _business_context_findings(
            asset,
            is_cbom_imported,
            asset_evidence=asset_evidence,
        )
    )
    findings.extend(_cryptographic_context_findings(asset))
    findings.extend(
        _supply_chain_context_findings(
            asset,
            is_cbom_imported=is_cbom_imported,
            asset_evidence=asset_evidence,
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


def _business_context_findings(
    asset: CryptographicAsset,
    is_cbom_imported: bool,
    *,
    asset_evidence: AssetEvidenceAssertions | None,
) -> list[EvidenceFinding]:
    findings: list[EvidenceFinding] = []
    provenance = (
        EvidenceProvenance.qstriage_default
        if is_cbom_imported
        else EvidenceProvenance.user_declared
    )

    if _is_unknown_text(asset.data_class):
        data_class_assertion = asset_evidence.data_class if asset_evidence else None
        findings.append(
            EvidenceFinding(
                code="missing_data_class",
                category=EvidenceCategory.business_context,
                severity=EvidenceSeverity.high,
                message=(
                    "Data class is unknown; the migration priority may change "
                    "materially once business data classification is supplied."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].data_class",
                evidence_state=_assertion_state(
                    data_class_assertion, default=EvidenceState.no_assertion
                ),
                provenance=_assertion_provenance(
                    data_class_assertion, default=provenance
                ),
                human_action=HumanAction(
                    description=f"Set data_class for asset '{asset.id}'.",
                    field_path=f"assets[{asset.id}].data_class",
                    expected_value_type=(
                        "non-empty business data classification, for example "
                        "customer_pii, identity_tokens, payment_metadata, telemetry, or public"
                    ),
                    effect_if_unresolved="PDR remains not decision-grade.",
                ),
            )
        )

    retention_assertion = asset_evidence.retention_years if asset_evidence else None
    if (
        asset.retention_years == 0
        and is_cbom_imported
        and retention_assertion is None
    ):
        findings.append(
            EvidenceFinding(
                code="defaulted_retention_years",
                category=EvidenceCategory.business_context,
                severity=EvidenceSeverity.high,
                message=(
                    "Retention period is defaulted to 0 because imported CBOM "
                    "evidence does not carry QSTriage business retention context."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].retention_years",
                evidence_state=EvidenceState.defaulted,
                provenance=EvidenceProvenance.qstriage_default,
                human_action=HumanAction(
                    description=f"Set retention_years for asset '{asset.id}'.",
                    field_path=f"assets[{asset.id}].retention_years",
                    expected_value_type="integer number of years, 0 only when explicitly justified",
                    effect_if_unresolved="Long-lived confidentiality risk cannot be decision-grade.",
                ),
            )
        )

    if _is_unknown_text(asset.exposure):
        exposure_assertion = asset_evidence.exposure if asset_evidence else None
        findings.append(
            EvidenceFinding(
                code="missing_exposure",
                category=EvidenceCategory.business_context,
                severity=EvidenceSeverity.high,
                message=(
                    "Exposure is unknown; the system cannot determine whether "
                    "the asset is internet-facing, internal, partner-facing, or isolated."
                ),
                effects=[
                    EvidenceEffect.confidence_capped,
                    EvidenceEffect.decision_grade_blocked,
                    EvidenceEffect.human_review_required,
                ],
                asset_id=asset.id,
                field_path=f"assets[{asset.id}].exposure",
                evidence_state=_assertion_state(
                    exposure_assertion, default=EvidenceState.no_assertion
                ),
                provenance=_assertion_provenance(
                    exposure_assertion, default=provenance
                ),
                human_action=HumanAction(
                    description=f"Set exposure for asset '{asset.id}'.",
                    field_path=f"assets[{asset.id}].exposure",
                    expected_value_type="internet, partner, internal, isolated, or similar exposure class",
                    effect_if_unresolved="Exposure-driven migration priority remains unreliable.",
                ),
            )
        )

    return findings


def _cryptographic_context_findings(asset: CryptographicAsset) -> list[EvidenceFinding]:
    findings: list[EvidenceFinding] = []
    classification = classify_algorithm(asset.algorithm)

    if _is_unknown_text(asset.algorithm) or classification.algorithm_family == "unknown":
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

    if _requires_key_size(asset.algorithm) and asset.key_size_bits is None:
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


def _supply_chain_context_findings(
    asset: CryptographicAsset,
    *,
    is_cbom_imported: bool,
    asset_evidence: AssetEvidenceAssertions | None,
) -> list[EvidenceFinding]:
    if not is_cbom_imported:
        return []

    findings = [
        _defaulted_risk_finding(
            asset,
            field_name="criticality",
            value=asset.criticality,
            assertion=asset_evidence.criticality if asset_evidence else None,
            message=(
                "Criticality is defaulted to medium because imported CBOM "
                "evidence does not carry QSTriage business criticality context."
            ),
        ),
        _defaulted_risk_finding(
            asset,
            field_name="local_blast_radius",
            value=asset.local_blast_radius,
            assertion=asset_evidence.local_blast_radius if asset_evidence else None,
            message=(
                "Local blast radius is defaulted to medium because imported CBOM "
                "evidence does not carry QSTriage dependency impact context."
            ),
        ),
        _defaulted_risk_finding(
            asset,
            field_name="migration_effort",
            value=asset.migration_effort,
            assertion=asset_evidence.migration_effort if asset_evidence else None,
            message=(
                "Migration effort is defaulted to medium because imported CBOM "
                "evidence does not carry QSTriage implementation effort context."
            ),
        ),
    ]

    return [finding for finding in findings if finding is not None]


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


def _defaulted_risk_finding(
    asset: CryptographicAsset,
    *,
    field_name: str,
    value: RiskLevel,
    assertion: FieldEvidenceAssertion | None,
    message: str,
) -> EvidenceFinding | None:
    if value != RiskLevel.medium or assertion is not None:
        return None

    return EvidenceFinding(
        code=f"defaulted_{field_name}",
        category=EvidenceCategory.supply_chain_context,
        severity=EvidenceSeverity.medium,
        message=message,
        effects=[
            EvidenceEffect.confidence_capped,
            EvidenceEffect.human_review_required,
        ],
        asset_id=asset.id,
        field_path=f"assets[{asset.id}].{field_name}",
        evidence_state=EvidenceState.defaulted,
        provenance=EvidenceProvenance.qstriage_default,
        human_action=HumanAction(
            description=f"Confirm or replace {field_name} for asset '{asset.id}'.",
            field_path=f"assets[{asset.id}].{field_name}",
            expected_value_type="low, medium, high, or critical based on business context",
            effect_if_unresolved="Confidence remains capped by defaulted CBOM-derived context.",
        ),
    )


def _dependency_count_by_asset(dependencies: list[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}

    for dependency in dependencies:
        counts[dependency.source] = counts.get(dependency.source, 0) + 1
        counts[dependency.target] = counts.get(dependency.target, 0) + 1

    return counts


def _is_cbom_imported_asset(asset: CryptographicAsset, source_type: str) -> bool:
    return (
        source_type == "cyclonedx_cbom"
        or asset.asset_type == "cbom_cryptographic_asset"
        or CBOM_IMPORT_NOTE_MARKER in asset.notes
    )


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


def _requires_key_size(algorithm: str) -> bool:
    normalized = algorithm.upper().replace("_", "-")
    return normalized.startswith(("RSA", "AES", "DH", "ECDH", "ECDSA"))
