from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from qstriage.context import NormalizedAssetContext, normalize_asset_context
from qstriage.decision import CanonicalDecision, DecisionContext, reconcile_decision
from qstriage.evidence import EvidenceReview, review_asset_evidence
from qstriage.models import CryptographicAsset, Inventory
from qstriage.policy import (
    PolicyEvaluationResult,
    PolicyEvaluator,
    PolicyPack,
    get_policy_pack,
)
from qstriage.scoring import ScoreResult, score_inventory
from qstriage.standards import AlgorithmClassification, classify_algorithm


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
) -> AssetAssessment:
    """Build one deterministic assessment for all decision-bearing outputs."""

    if score.asset_id != asset.id:
        raise ValueError(
            f"ScoreResult asset_id '{score.asset_id}' does not match asset '{asset.id}'"
        )

    classification = classify_algorithm(asset.algorithm)
    normalized_context = normalize_asset_context(asset)
    evidence_review = review_asset_evidence(asset, source_type=source_type)
    policy_evaluation = PolicyEvaluator.evaluate_asset(
        asset,
        policy_pack,
        classification,
        source_type=source_type,
        evidence_review=evidence_review,
    )
    evidence_quality = evaluate_evidence_quality(asset, classification)
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

    return [
        assess_asset(
            asset_by_id[score.asset_id],
            score=score,
            policy_pack=resolved_policy_pack,
            source_type=source_type,
        )
        for score in score_inventory(inventory)
    ]

def evaluate_evidence_quality(
    asset: CryptographicAsset,
    classification: AlgorithmClassification,
) -> EvidenceQuality:
    missing = []
    limitations = []

    if asset.data_class.strip().lower() == "unknown":
        missing.append("data_class")

    if asset.retention_years == 0:
        missing.append("retention_years")

    if asset.exposure.strip().lower() == "unknown":
        missing.append("exposure_boundary")

    if (
        asset.key_size_bits is None
        and classification.algorithm_family not in {"ML-KEM", "ML-DSA", "SLH-DSA"}
    ):
        missing.append("key_size_bits")

    if asset.asset_type == "cbom_cryptographic_asset":
        if asset.criticality.value == "medium":
            missing.append("business_criticality_context")
        if asset.local_blast_radius.value == "medium":
            missing.append("blast_radius_context")
        if asset.migration_effort.value == "medium":
            missing.append("migration_effort_context")
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
    elif asset.asset_type == "cbom_cryptographic_asset":
        reason = "Decision confidence is constrained by partial CBOM context."
    else:
        reason = (
            "Decision confidence is based on available inventory, scoring, and "
            "standards context."
        )

    return DecisionConfidence(score=confidence, reason=reason)
