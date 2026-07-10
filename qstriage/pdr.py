from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from qstriage import __version__
from qstriage.assessment import (
    AssetAssessment,
    DecisionConfidence,
    EvidenceQuality,
    assess_asset,
)
from qstriage.decision import (
    ActionType,
    ExecutionState,
    VerificationPriority,
    VerificationRequirement,
)
from qstriage.evidence import EvidenceReview
from qstriage.models import CryptographicAsset, Inventory
from qstriage.policy import (
    BUILTIN_POLICY_PACK_ID,
    BUILTIN_POLICY_PACK_VERSION,
    PolicyEvaluationResult,
    PolicyPack,
    get_policy_pack,
)
from qstriage.scoring import ScoreResult, score_inventory
from qstriage.standards import AlgorithmClassification


PDR_VERSION = "0.2"
ENGINE_NAME = "QSTriage"
ENGINE_VERSION = __version__

DEFAULT_POLICY_PACK_ID = BUILTIN_POLICY_PACK_ID
DEFAULT_POLICY_PACK_VERSION = BUILTIN_POLICY_PACK_VERSION

STANDARD_FIPS_203 = "NIST-FIPS-203"
STANDARD_FIPS_204 = "NIST-FIPS-204"
STANDARD_FIPS_205 = "NIST-FIPS-205"
STANDARD_NIST_IR_8547 = "NIST-IR-8547-IPD"
STANDARD_QSTRIAGE_POLICY = "QSTRIAGE-SAFETY-POLICY"


class PDREngine(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ENGINE_NAME
    version: str = ENGINE_VERSION


class InputSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str = Field(min_length=1)
    source_version: str | None = None
    source_path: str | None = None
    source_hash: str = Field(min_length=1)


class PolicyContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_pack_id: str = Field(min_length=1)
    policy_pack_version: str = Field(min_length=1)
    policy_pack_hash: str = Field(min_length=1)
    standards_applied: list[str]


class ObservedState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    asset_name: str
    environment: str
    asset_type: str
    protocol: str
    algorithm: str
    key_size_bits: int | None
    algorithm_family: str
    primitive: str
    quantum_status: str
    standard_status: str


class MissionContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    business_function: str | None = None
    data_class: str
    retention_years: int
    exposure: str
    mission_impact_if_wrong: str
    mission_impact_if_delayed: str


class Tradeoff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    description: str


class TargetStateSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    option: str
    standards: list[str]
    rationale: str
    operational_risk: str
    requires_human_review: bool


class PDRDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_attention_score: float
    risk_attention_band: str
    execution_state: ExecutionState
    action_type: ActionType
    verification_priority: VerificationPriority
    verification_requirements: list[VerificationRequirement]
    confidence_score: float = Field(ge=0.0, le=1.0)
    human_review_required: bool
    reason_codes: list[str]


class RecordIntegrity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    previous_record_hash: str | None = None
    record_hash: str = Field(min_length=1)


class PQCDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pdr_version: str = PDR_VERSION
    record_id: str
    run_id: str
    lineage_id: str
    sequence_number: int = Field(ge=1)
    engine: PDREngine
    input_snapshot: InputSnapshot
    policy_context: PolicyContext
    policy_evaluation: PolicyEvaluationResult
    observed_state: ObservedState
    evidence_quality: EvidenceQuality
    evidence_review: EvidenceReview
    decision_confidence: DecisionConfidence
    mission_context: MissionContext
    tradeoffs: list[Tradeoff]
    target_state_suggestion: list[TargetStateSuggestion]
    decision: PDRDecision
    assumptions_made: list[str]
    record_integrity: RecordIntegrity


class PDRDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pdr_version: str = PDR_VERSION
    run_id: str
    input_snapshot: InputSnapshot
    policy_context: PolicyContext
    records: list[PQCDecisionRecord]
    document_hash: str


def generate_pdr_document(
    inventory: Inventory,
    *,
    source_path: str | Path | None = None,
    source_type: str = "qstriage_inventory",
    source_version: str | None = None,
    policy_pack_id: str = DEFAULT_POLICY_PACK_ID,
    policy_pack_version: str = DEFAULT_POLICY_PACK_VERSION,
    previous_record_hashes: dict[str, str] | None = None,
) -> PDRDocument:
    input_snapshot = _build_input_snapshot(
        inventory,
        source_path=source_path,
        source_type=source_type,
        source_version=source_version,
    )
    policy_pack = _load_policy_pack(policy_pack_id, policy_pack_version)
    policy_context = _build_policy_context(policy_pack)
    run_id = _run_id(input_snapshot, policy_context)
    lineage_id = _lineage_id(input_snapshot)
    score_by_asset = {result.asset_id: result for result in score_inventory(inventory)}

    records = [
        _build_record(
            asset=asset,
            score=score_by_asset[asset.id],
            sequence_number=index,
            run_id=run_id,
            lineage_id=lineage_id,
            input_snapshot=input_snapshot,
            policy_context=policy_context,
            policy_pack=policy_pack,
            previous_record_hash=(
                previous_record_hashes or {}
            ).get(asset.id),
        )
        for index, asset in enumerate(inventory.assets, start=1)
    ]

    document = PDRDocument(
        run_id=run_id,
        input_snapshot=input_snapshot,
        policy_context=policy_context,
        records=records,
        document_hash="pending",
    )
    document_hash = _hash_model_without_field(document, "document_hash")
    return document.model_copy(update={"document_hash": document_hash})


def _build_record(
    *,
    asset: CryptographicAsset,
    score: ScoreResult,
    sequence_number: int,
    run_id: str,
    lineage_id: str,
    input_snapshot: InputSnapshot,
    policy_context: PolicyContext,
    policy_pack: PolicyPack,
    previous_record_hash: str | None,
) -> PQCDecisionRecord:
    assessment = assess_asset(
        asset,
        score=score,
        policy_pack=policy_pack,
        source_type=input_snapshot.source_type,
    )

    record = PQCDecisionRecord(
        record_id=f"pdr:{asset.id}",
        run_id=run_id,
        lineage_id=lineage_id,
        sequence_number=sequence_number,
        engine=PDREngine(),
        input_snapshot=input_snapshot,
        policy_context=policy_context,
        policy_evaluation=assessment.policy_evaluation,
        observed_state=_observed_state(asset, assessment.classification),
        evidence_quality=assessment.evidence_quality,
        evidence_review=assessment.evidence_review,
        decision_confidence=assessment.decision_confidence,
        mission_context=_mission_context(asset, score),
        tradeoffs=_tradeoffs(asset, assessment.classification),
        target_state_suggestion=_target_state_suggestions(
            asset,
            assessment.classification,
        ),
        decision=_project_decision(assessment),
        assumptions_made=_assumptions(
            asset,
            assessment.evidence_quality,
            assessment.evidence_review,
        ),
        record_integrity=RecordIntegrity(
            previous_record_hash=previous_record_hash,
            record_hash="pending",
        ),
    )
    record_hash = _hash_record(record)
    return record.model_copy(
        update={
            "record_integrity": RecordIntegrity(
                previous_record_hash=previous_record_hash,
                record_hash=record_hash,
            )
        }
    )


def _project_decision(assessment: AssetAssessment) -> PDRDecision:
    decision = assessment.decision
    return PDRDecision(
        risk_attention_score=decision.risk_attention_score,
        risk_attention_band=decision.risk_attention_band,
        execution_state=decision.execution_state,
        action_type=decision.action_type,
        verification_priority=decision.verification_priority,
        verification_requirements=list(decision.verification_requirements),
        confidence_score=decision.decision_confidence,
        human_review_required=decision.human_review_required,
        reason_codes=list(decision.reason_codes),
    )


def _build_input_snapshot(
    inventory: Inventory,
    *,
    source_path: str | Path | None,
    source_type: str,
    source_version: str | None,
) -> InputSnapshot:
    path = Path(source_path) if source_path is not None else None
    if path is not None:
        source_hash = _hash_file(path)
        source_path_text = path.name
    else:
        source_hash = _hash_object(inventory.model_dump(mode="json"))
        source_path_text = None

    return InputSnapshot(
        source_type=source_type,
        source_version=source_version,
        source_path=source_path_text,
        source_hash=source_hash,
    )


def _load_policy_pack(policy_pack_id: str, policy_pack_version: str) -> PolicyPack:
    policy_pack = get_policy_pack(policy_pack_id)
    if policy_pack.version != policy_pack_version:
        raise ValueError(
            f"Policy pack '{policy_pack_id}' version mismatch: "
            f"requested {policy_pack_version}, available {policy_pack.version}"
        )

    return policy_pack


def _build_policy_context(policy_pack: PolicyPack) -> PolicyContext:
    return PolicyContext(
        policy_pack_id=policy_pack.policy_pack_id,
        policy_pack_version=policy_pack.version,
        policy_pack_hash=policy_pack.policy_pack_hash(),
        standards_applied=policy_pack.standards_applied(),
    )


def _observed_state(
    asset: CryptographicAsset,
    classification: AlgorithmClassification,
) -> ObservedState:
    return ObservedState(
        asset_id=asset.id,
        asset_name=asset.name,
        environment=asset.environment,
        asset_type=asset.asset_type,
        protocol=asset.protocol,
        algorithm=asset.algorithm,
        key_size_bits=asset.key_size_bits,
        algorithm_family=classification.algorithm_family,
        primitive=classification.primitive,
        quantum_status=classification.quantum_status,
        standard_status=classification.standard_status,
    )


def _mission_context(asset: CryptographicAsset, score: ScoreResult) -> MissionContext:
    return MissionContext(
        data_class=asset.data_class,
        retention_years=asset.retention_years,
        exposure=asset.exposure,
        mission_impact_if_wrong=asset.criticality.value,
        mission_impact_if_delayed=score.priority_band,
    )


def _tradeoffs(
    asset: CryptographicAsset,
    classification: AlgorithmClassification,
) -> list[Tradeoff]:
    tradeoffs = [
        Tradeoff(
            type="migration_complexity",
            description=f"Migration effort is {asset.migration_effort.value}; production rollout should be staged if effort is high.",
        )
    ]

    if classification.quantum_status == "quantum_vulnerable":
        tradeoffs.append(
            Tradeoff(
                type="cryptographic_risk",
                description="Classical public-key cryptography creates harvest-now-decrypt-later or future forgery exposure depending on use.",
            )
        )

    if "tls" in asset.protocol.lower() or "gateway" in asset.asset_type.lower():
        tradeoffs.append(
            Tradeoff(
                type="operational_risk",
                description="Hybrid or PQC handshake changes may affect interoperability, packet size, middleboxes, or constrained paths.",
            )
        )

    if asset.asset_type == "cbom_cryptographic_asset":
        tradeoffs.append(
            Tradeoff(
                type="evidence_gap",
                description="CBOM crypto evidence lacks QSTriage business and dependency context until enriched.",
            )
        )

    return tradeoffs


def _target_state_suggestions(
    asset: CryptographicAsset,
    classification: AlgorithmClassification,
) -> list[TargetStateSuggestion]:
    protocol = asset.protocol.lower()
    primitive = classification.primitive.lower()

    if classification.quantum_status == "quantum_resistant":
        return [
            TargetStateSuggestion(
                option=f"retain_{classification.algorithm_family.lower().replace('-', '_')}",
                standards=list(classification.source_ids),
                rationale="Observed algorithm is already classified as standardized post-quantum cryptography.",
                operational_risk="low",
                requires_human_review=False,
            )
        ]

    if classification.quantum_status == "quantum_vulnerable":
        suggestions = []

        if (
            "key" in primitive
            or "kem" in protocol
            or "tls" in protocol
            or "ecdh" in asset.algorithm.lower()
            or "ecdhe" in asset.algorithm.lower()
        ):
            suggestions.append(
                TargetStateSuggestion(
                    option="hybrid_key_establishment_with_ml_kem_768",
                    standards=[STANDARD_FIPS_203],
                    rationale="Use ML-KEM as the PQC target for key establishment, with hybrid rollout where compatibility risk exists.",
                    operational_risk="medium",
                    requires_human_review=True,
                )
            )

        if (
            "signature" in primitive
            or "sign" in protocol
            or "rsa" in asset.algorithm.lower()
            or "ecdsa" in asset.algorithm.lower()
        ):
            suggestions.append(
                TargetStateSuggestion(
                    option="signature_migration_to_ml_dsa_profile",
                    standards=[STANDARD_FIPS_204],
                    rationale="Use ML-DSA as the primary standardized PQC signature target where signature semantics are confirmed.",
                    operational_risk="medium",
                    requires_human_review=True,
                )
            )

        if not suggestions:
            suggestions.append(
                TargetStateSuggestion(
                    option="manual_pqc_target_selection",
                    standards=[STANDARD_NIST_IR_8547],
                    rationale="Quantum-vulnerable algorithm was detected, but the primitive/use context is not specific enough for automatic target selection.",
                    operational_risk="high",
                    requires_human_review=True,
                )
            )

        return suggestions

    if classification.primitive in {"symmetric_encryption", "hash", "hash_or_xof"}:
        return [
            TargetStateSuggestion(
                option="review_key_strength_not_public_key_pqc_migration",
                standards=list(classification.source_ids),
                rationale="Observed primitive is not a Shor-broken public-key migration target.",
                operational_risk="low",
                requires_human_review=False,
            )
        ]

    return [
        TargetStateSuggestion(
            option="manual_cryptographic_review_required",
            standards=[STANDARD_QSTRIAGE_POLICY],
            rationale="Algorithm is not recognized by the current QSTriage standards registry.",
            operational_risk="high",
            requires_human_review=True,
        )
    ]


def _assumptions(
    asset: CryptographicAsset,
    evidence_quality: EvidenceQuality,
    evidence_review: EvidenceReview,
) -> list[str]:
    assumptions = []

    if asset.asset_type == "cbom_cryptographic_asset":
        assumptions.append("CBOM crypto assets are treated as partial evidence until enriched with business context.")

    for field in evidence_quality.missing_evidence:
        assumptions.append(f"Missing {field} lowers evidence quality and decision confidence.")

    if evidence_review.decision_grade.value == "not_decision_grade":
        assumptions.append("Evidence review marks this record as not decision-grade until blocking findings are resolved.")

    for finding_code in evidence_review.blocking_finding_codes:
        assumptions.append(f"Blocking evidence finding '{finding_code}' prevents decision-grade status.")

    if not assumptions:
        assumptions.append("No material evidence assumptions were added by the current PDR rules.")

    return assumptions


def _run_id(input_snapshot: InputSnapshot, policy_context: PolicyContext) -> str:
    return "run:" + _hash_object(
        {
            "source_hash": input_snapshot.source_hash,
            "policy_pack_hash": policy_context.policy_pack_hash,
            "pdr_version": PDR_VERSION,
        }
    ).split(":", 1)[1][:16]


def _lineage_id(input_snapshot: InputSnapshot) -> str:
    return "lineage:" + input_snapshot.source_hash.split(":", 1)[1][:16]


def _hash_record(record: PQCDecisionRecord) -> str:
    data = record.model_dump(mode="json")
    data["record_integrity"]["record_hash"] = None
    return _hash_object(data)


def _hash_model_without_field(model: BaseModel, field: str) -> str:
    data = model.model_dump(mode="json")
    data[field] = None
    return _hash_object(data)


def _hash_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_object(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
