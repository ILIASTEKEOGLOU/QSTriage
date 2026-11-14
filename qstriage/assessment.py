from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from qstriage.context import (
    NormalizedAssetContext,
    is_cbom_imported_asset,
    normalize_asset_context,
)
from qstriage.decision import (
    CanonicalDecision,
    DecisionContext,
    ExecutionState,
    reconcile_decision,
)
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
from qstriage.scoring import ASSUMPTION_CONFLICTING_KEY_SIZE, ScoreResult, score_inventory
from qstriage.standards import (
    IDENTIFIER_FAMILY_UNVERIFIED,
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

@dataclass(frozen=True)
class PartitionedAssessments:
    """Assessments split into the verify-first list and the ranked backlog.

    An asset whose cryptography is not identified has execution state
    ``verification_first``. Its priority score rests on a guessed algorithm,
    so it is listed separately and never ranked.
    """

    verification_first: list[AssetAssessment]
    ranked: list[AssetAssessment]


def partition_assessments(assessments: list[AssetAssessment]) -> PartitionedAssessments:
    """Split assessments by the canonical execution state.

    The ranked list keeps the deterministic risk-attention order of
    ``assess_inventory``. The verify-first list is ordered by risk attention,
    highest first, then by asset id, so the assets with the most exposure
    context are verified first.
    """

    verification_first = [
        assessment
        for assessment in assessments
        if assessment.decision.execution_state is ExecutionState.verification_first
    ]
    ranked = [
        assessment
        for assessment in assessments
        if assessment.decision.execution_state is not ExecutionState.verification_first
    ]
    verification_first.sort(
        key=lambda item: (-item.decision.risk_attention_score, item.asset.id)
    )
    return PartitionedAssessments(verification_first=verification_first, ranked=ranked)


def unranked_reason(classification: AlgorithmClassification) -> str:
    """Explain in one sentence why an asset is in the verify-first list."""

    if classification.identifier_resolution == IDENTIFIER_FAMILY_UNVERIFIED:
        return (
            f"The {classification.algorithm_family} family is recognized, but the "
            "parameter set is missing or not supported, so the exact algorithm is "
            "not identified."
        )
    return "The algorithm identifier is not in the QSTriage algorithm registry."


SCORE_BASIS_NOTE = (
    'Score basis: "confirmed" means every context field the score uses is present '
    "and usable, and no stated key size conflicts with the algorithm identifier. "
    '"worst case" means a listed field cannot be used as stated: a context field is '
    "missing, withheld, not an accepted label, or defaulted on import, or "
    "key_size_bits differs from the size in the algorithm identifier. Each is "
    "scored at its most severe value (for a key size conflict, the smaller size), "
    "so missing or conflicting evidence can raise an asset but never bury it. "
    "Supply or correct the listed fields to replace the assumption with the real "
    "value."
)


def conflict_messages(score: ScoreResult) -> list[str]:
    """Messages for assumptions that record a contradiction, not a gap."""

    return [
        item.message
        for item in score.scoring_assumptions
        if item.kind == ASSUMPTION_CONFLICTING_KEY_SIZE
    ]


def key_size_used_text(score: ScoreResult, algorithm: str) -> str | None:
    """Plain text for the key size the score used, or None when no size applies."""

    if score.key_size_bits_scored is None:
        return None
    bits = score.key_size_bits_scored
    if score.key_size_source == "algorithm_identifier":
        return f"{bits} bits, taken from the algorithm identifier {algorithm}"
    if score.key_size_source == "conflict_smaller":
        return f"{bits} bits, the smaller of two conflicting sizes (provisional)"
    return f"{bits} bits, declared in key_size_bits"


def score_basis_label(score: ScoreResult, *, short: bool = False) -> str:
    """Text for the Score basis column of the ranked backlog."""

    if not score.scoring_assumptions:
        return "confirmed"
    count = len(score.scoring_assumptions)
    noun = "field" if count == 1 else "fields"
    if short:
        return f"worst case ({count} {noun})"
    fields = ", ".join(item.field for item in score.scoring_assumptions)
    return f"worst case for {count} {noun}: {fields}"


VERIFY_FIRST_ACTION = (
    "Confirm the exact algorithm and parameter set with the system owner, then "
    "correct the algorithm field in the inventory."
)


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
