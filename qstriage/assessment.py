from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from qstriage.context import (
    NormalizedAssetContext,
    is_cbom_imported_asset,
    normalize_asset_context,
)
from qstriage.decision import CanonicalDecision, DecisionContext, reconcile_decision
from qstriage.evidence import EvidenceReview, review_asset_evidence
from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    Inventory,
    RelationshipEvidenceCompleteness,
)
from qstriage.policy import (
    PolicyEvaluationResult,
    PolicyEvaluator,
    PolicyPack,
    get_policy_pack,
)
from qstriage.scoring import ScoreResult, score_inventory
from qstriage.standards import (
    AlgorithmClassification,
    KeySizeRequirement,
    classify_algorithm,
    key_size_requirement,
)


class EvidenceQuality(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    missing_evidence: list[str]
    limitations: list[str]


class DecisionConfidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    reason: str


@dataclass(frozen=True)
class AssetAssessment:
    asset: CryptographicAsset
    classification: AlgorithmClassification
    score: ScoreResult
    normalized_context: NormalizedAssetContext
    evidence_quality: EvidenceQuality
    evidence_review: EvidenceReview
    policy_evaluation: PolicyEvaluationResult
    decision_confidence: DecisionConfidence
    decision: CanonicalDecision


def assess_asset(
    asset: CryptographicAsset,
    *,
    score: ScoreResult,
    policy_pack: PolicyPack,
    source_type: str = "qstriage_inventory",
    asset_evidence: AssetEvidenceAssertions | None = None,
) -> AssetAssessment:
    """Build one deterministic assessment for all decision-bearing outputs."""

    if score.asset_id != asset.id:
        raise ValueError(
            f"ScoreResult asset_id '{score.asset_id}' does not match asset '{asset.id}'"
        )

    classification = classify_algorithm(asset.algorithm)
    normalized_context = normalize_asset_context(
        asset, asset_evidence, source_type=source_type
    )
    evidence_review = review_asset_evidence(
        asset, source_type=source_type, asset_evidence=asset_evidence
    )
    policy_evaluation = PolicyEvaluator.evaluate_asset(
        asset,
        policy_pack,
        classification,
        source_type=source_type,
        evidence_review=evidence_review,
        asset_evidence=asset_evidence,
    )
    evidence_quality = evaluate_evidence_quality(
        asset,
        classification,
        context=normalized_context,
        relationship_unresolved=_relationship_unresolved(
            asset, asset_evidence, source_type=source_type
        ),
    )
    decision_confidence = calculate_decision_confidence(
        asset,
        score,
        evidence_quality,
        evidence_review,
    )
    decision = reconcile_decision(
        classification=classification,
        score=score,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence.score,
        migration_effort=asset.migration_effort,
        context=DecisionContext(normalized_context=normalized_context),
    )

    return AssetAssessment(
        asset=asset,
        classification=classification,
        score=score,
        normalized_context=normalized_context,
        evidence_quality=evidence_quality,
        evidence_review=evidence_review,
        policy_evaluation=policy_evaluation,
        decision_confidence=decision_confidence,
        decision=decision,
    )



def assess_inventory(
    inventory: Inventory,
    *,
    policy_pack: PolicyPack | None = None,
    source_type: str = "qstriage_inventory",
) -> list[AssetAssessment]:
    """Build canonical assessments in deterministic risk-attention order."""

    resolved_policy_pack = policy_pack or get_policy_pack()
    asset_by_id = inventory.asset_by_id()
    evidence_by_asset = (
        inventory.evidence.assets if inventory.evidence is not None else {}
    )

    return [
        assess_asset(
            asset_by_id[score.asset_id],
            score=score,
            policy_pack=resolved_policy_pack,
            source_type=source_type,
            asset_evidence=evidence_by_asset.get(score.asset_id),
        )
        for score in score_inventory(inventory)
    ]

_EVIDENCE_QUALITY_KEYS = {
    "data_class": "data_class",
    "retention_years": "retention_years",
    "exposure": "exposure_boundary",
    "criticality": "business_criticality_context",
    "local_blast_radius": "blast_radius_context",
    "migration_effort": "migration_effort_context",
}

_EVIDENCE_QUALITY_ORDER = (
    "data_class",
    "retention_years",
    "exposure",
    "key_size_bits",
    "criticality",
    "local_blast_radius",
    "migration_effort",
)


def _relationship_unresolved(
    asset: CryptographicAsset,
    asset_evidence: AssetEvidenceAssertions | None,
    *,
    source_type: str,
) -> bool:
    if not is_cbom_imported_asset(asset, source_type):
        return False
    assertion = asset_evidence.relationship_completeness if asset_evidence else None
    return assertion is None or assertion.value not in {
        RelationshipEvidenceCompleteness.none,
        RelationshipEvidenceCompleteness.known,
    }


def evaluate_evidence_quality(
    asset: CryptographicAsset,
    classification: AlgorithmClassification,
    *,
    context: NormalizedAssetContext | None = None,
    relationship_unresolved: bool | None = None,
) -> EvidenceQuality:
    resolved = context if context is not None else normalize_asset_context(asset)
    unresolved = {field.field for field in resolved.unresolved_fields}
    missing = []
    limitations = []

    for field in _EVIDENCE_QUALITY_ORDER:
        if field == "key_size_bits":
            if (
                asset.key_size_bits is None
                and key_size_requirement(classification) == KeySizeRequirement.required
            ):
                missing.append("key_size_bits")
        elif field in unresolved:
            missing.append(_EVIDENCE_QUALITY_KEYS[field])

    if relationship_unresolved is None:
        relationship_unresolved = _relationship_unresolved(
            asset, None, source_type="qstriage_inventory"
        )
    if relationship_unresolved:
        limitations.append(
            "CBOM dependency relationships are not imported as QSTriage dependencies."
        )

    score = round(
        max(0.0, 1.0 - (len(missing) * 0.12) - (len(limitations) * 0.08)),
        2,
    )
    return EvidenceQuality(
        score=score,
        missing_evidence=missing,
        limitations=limitations,
    )


def calculate_decision_confidence(
    asset: CryptographicAsset,
    score: ScoreResult,
    evidence_quality: EvidenceQuality,
    evidence_review: EvidenceReview,
) -> DecisionConfidence:
    base_by_label = {
        "low": 0.45,
        "medium": 0.65,
        "medium-high": 0.8,
        "high": 0.9,
    }
    base = base_by_label.get(score.confidence, 0.55)
    confidence = round(
        min(
            base,
            evidence_quality.score,
            evidence_review.evidence_score,
            evidence_review.confidence_cap,
        ),
        2,
    )

    if evidence_review.blocking_finding_codes:
        reason = (
            "Decision confidence is constrained by blocking evidence findings: "
            + ", ".join(evidence_review.blocking_finding_codes)
            + "."
        )
    elif evidence_quality.missing_evidence:
        reason = (
            "Decision confidence is constrained by missing evidence: "
            + ", ".join(evidence_quality.missing_evidence)
            + "."
        )
    elif evidence_review.findings:
        finding_codes = [finding.code for finding in evidence_review.findings[:5]]
        reason = (
            "Decision confidence is constrained by evidence review findings: "
            + ", ".join(finding_codes)
            + "."
        )
    elif evidence_quality.limitations:
        reason = "Decision confidence is constrained by partial CBOM context."
    else:
        reason = (
            "Decision confidence is based on available inventory, scoring, and "
            "standards context."
        )

    return DecisionConfidence(score=confidence, reason=reason)
