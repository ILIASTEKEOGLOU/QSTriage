from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


POLICY_PACK_SCHEMA_VERSION = "0.1"

PolicyScalar = str | int | float | bool


class PolicySeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class PolicyRuleEffect(str, Enum):
    raises_priority = "raises_priority"
    lowers_confidence = "lowers_confidence"
    caps_confidence = "caps_confidence"
    blocks_decision_grade = "blocks_decision_grade"
    requires_human_review = "requires_human_review"
    adds_policy_context = "adds_policy_context"
    constrains_migration = "constrains_migration"
    recommends_target_state = "recommends_target_state"


class PolicyApplicabilityTarget(str, Enum):
    asset = "asset"
    dependency = "dependency"
    evidence_review = "evidence_review"
    classification = "classification"
    migration_context = "migration_context"
    pdr_state = "pdr_state"
    inventory = "inventory"


class PolicyReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    version: str | None = None
    section: str | None = None
    url: str | None = None
    notes: str = ""


class PolicyThreshold(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threshold_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    value: PolicyScalar
    rationale: str = Field(min_length=1)


class PolicyApplicability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: PolicyApplicabilityTarget
    conditions: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    applicability: PolicyApplicability
    severity: PolicySeverity
    effects: list[PolicyRuleEffect] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)


class PolicyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1)
    severity: PolicySeverity
    message: str = Field(min_length=1)
    effects: list[PolicyRuleEffect] = Field(default_factory=list)
    asset_id: str | None = None
    field_path: str | None = None
    rationale: str | None = None
    recommendation: str | None = None
    standards_applied: list[str] = Field(default_factory=list)

    @property
    def blocks_decision_grade(self) -> bool:
        return PolicyRuleEffect.blocks_decision_grade in self.effects

    @property
    def requires_human_review(self) -> bool:
        return (
            PolicyRuleEffect.requires_human_review in self.effects
            or self.blocks_decision_grade
        )


class PolicyEvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_pack_id: str = Field(min_length=1)
    policy_pack_version: str = Field(min_length=1)
    policy_pack_hash: str = Field(min_length=1)
    applied_rule_ids: list[str] = Field(default_factory=list)
    standards_applied: list[str] = Field(default_factory=list)
    thresholds_applied: list[str] = Field(default_factory=list)
    findings: list[PolicyFinding] = Field(default_factory=list)

    @property
    def blocking_rule_ids(self) -> list[str]:
        return [
            finding.rule_id
            for finding in self.findings
            if finding.blocks_decision_grade
        ]

    @property
    def human_review_required(self) -> bool:
        return any(finding.requires_human_review for finding in self.findings)


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_pack_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    schema_version: str = POLICY_PACK_SCHEMA_VERSION
    standards_references: list[PolicyReference] = Field(default_factory=list)
    thresholds: list[PolicyThreshold] = Field(default_factory=list)
    rules: list[PolicyRule] = Field(min_length=1)
    notes: str = ""

    @model_validator(mode="after")
    def validate_policy_pack_integrity(self) -> PolicyPack:
        _ensure_unique([rule.rule_id for rule in self.rules], "policy rule id")
        _ensure_unique(
            [reference.reference_id for reference in self.standards_references],
            "policy reference id",
        )
        _ensure_unique(
            [threshold.threshold_id for threshold in self.thresholds],
            "policy threshold id",
        )

        known_reference_ids = {
            reference.reference_id for reference in self.standards_references
        }
        for rule in self.rules:
            for reference_id in rule.references:
                if reference_id not in known_reference_ids:
                    raise ValueError(
                        f"Policy rule '{rule.rule_id}' references unknown "
                        f"policy reference '{reference_id}'."
                    )

        return self

    def canonical_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def policy_pack_hash(self) -> str:
        digest = hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def rule_ids(self) -> list[str]:
        return [rule.rule_id for rule in self.rules]

    def standards_applied(self) -> list[str]:
        return [reference.reference_id for reference in self.standards_references]

    def threshold_ids(self) -> list[str]:
        return [threshold.threshold_id for threshold in self.thresholds]


def _ensure_unique(values: list[str], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)

    if duplicates:
        joined = ", ".join(sorted(duplicates))
        raise ValueError(f"Duplicate {label}: {joined}")


BUILTIN_POLICY_PACK_ID = "nist-pqc-basic"
BUILTIN_POLICY_PACK_VERSION = "0.1"


def get_policy_pack(policy_pack_id: str = BUILTIN_POLICY_PACK_ID) -> PolicyPack:
    if policy_pack_id != BUILTIN_POLICY_PACK_ID:
        raise ValueError(f"Unknown policy pack: {policy_pack_id}")

    return _build_nist_pqc_basic_policy_pack()


def list_policy_packs() -> list[PolicyPack]:
    return [get_policy_pack(BUILTIN_POLICY_PACK_ID)]


def _build_nist_pqc_basic_policy_pack() -> PolicyPack:
    return PolicyPack(
        policy_pack_id=BUILTIN_POLICY_PACK_ID,
        version=BUILTIN_POLICY_PACK_VERSION,
        title="NIST PQC Basic",
        description=(
            "Baseline standards-backed policy pack for local-first PQC migration "
            "triage."
        ),
        standards_references=_nist_pqc_basic_references(),
        thresholds=_nist_pqc_basic_thresholds(),
        rules=_nist_pqc_basic_rules(),
        notes=(
            "This built-in policy pack provides deterministic policy context for "
            "QSTriage PDRs. It is not a complete compliance framework."
        ),
    )


def _nist_pqc_basic_references() -> list[PolicyReference]:
    return [
        PolicyReference(
            reference_id="NIST-FIPS-203",
            title="NIST FIPS 203 — ML-KEM",
            version="final",
            notes="Standards source for ML-KEM.",
        ),
        PolicyReference(
            reference_id="NIST-FIPS-204",
            title="NIST FIPS 204 — ML-DSA",
            version="final",
            notes="Standards source for ML-DSA.",
        ),
        PolicyReference(
            reference_id="NIST-FIPS-205",
            title="NIST FIPS 205 — SLH-DSA",
            version="final",
            notes="Standards source for SLH-DSA.",
        ),
        PolicyReference(
            reference_id="NIST-SP-800-131A-REV3-IPD",
            title=(
                "NIST SP 800-131A Rev. 3 IPD — Transitioning the Use of "
                "Cryptographic Algorithms and Key Lengths"
            ),
            version="initial-public-draft",
            notes="Transition language for cryptographic algorithms and key lengths.",
        ),
        PolicyReference(
            reference_id="NIST-IR-8547-IPD",
            title=(
                "NIST IR 8547 IPD — Transition to Post-Quantum Cryptography "
                "Standards"
            ),
            version="initial-public-draft",
            notes="PQC migration planning and inventory guidance.",
        ),
        PolicyReference(
            reference_id="NIST-SP-800-227",
            title="NIST SP 800-227 — Recommendations for Key-Encapsulation Mechanisms",
            version="final",
            notes="KEM guidance for key establishment context.",
        ),
        PolicyReference(
            reference_id="NIST-CSWP-39-UPDATE-1",
            title="NIST CSWP 39 Update 1 — Considerations for Achieving Crypto Agility",
            version="update-1",
            notes="Crypto agility considerations.",
        ),
        PolicyReference(
            reference_id="CISA-QUANTUM-READINESS",
            title="CISA Quantum-Readiness: Migration to Post-Quantum Cryptography",
            notes="Quantum-readiness and PQC migration guidance.",
        ),
        PolicyReference(
            reference_id="CISA-PQC-DISCOVERY-INVENTORY",
            title=(
                "CISA Strategy for Migrating to Automated Post-Quantum "
                "Cryptography Discovery and Inventory Tools"
            ),
            notes="Discovery and inventory readiness guidance.",
        ),
        PolicyReference(
            reference_id="QSTRIAGE-SAFETY-POLICY",
            title="QSTriage Local Safety Policy",
            version=BUILTIN_POLICY_PACK_VERSION,
            notes="Local deterministic policy context for QSTriage decisions.",
        ),
    ]


def _nist_pqc_basic_thresholds() -> list[PolicyThreshold]:
    return [
        PolicyThreshold(
            threshold_id="minimum_decision_grade_confidence",
            title="Minimum decision-grade confidence",
            value=0.75,
            rationale=(
                "PDR decisions below this confidence require review before they are "
                "treated as decision-grade."
            ),
        ),
        PolicyThreshold(
            threshold_id="cbom_default_confidence_cap",
            title="CBOM default confidence cap",
            value=0.50,
            rationale=(
                "Imported CBOM evidence without business context should not produce "
                "high-confidence decision-grade records."
            ),
        ),
        PolicyThreshold(
            threshold_id="high_priority_human_review",
            title="High priority human review",
            value=True,
            rationale="High-priority migration findings require human review.",
        ),
        PolicyThreshold(
            threshold_id="long_retention_years",
            title="Long retention threshold",
            value=7,
            rationale=(
                "Long-lived sensitive data increases migration urgency because "
                "confidentiality must survive future cryptanalytic capability."
            ),
        ),
        PolicyThreshold(
            threshold_id="harvest_now_decrypt_later_review_required",
            title="Harvest-now-decrypt-later review required",
            value=True,
            rationale=(
                "Sensitive data protected by quantum-vulnerable public-key "
                "cryptography requires explicit review."
            ),
        ),
    ]


def _nist_pqc_basic_rules() -> list[PolicyRule]:
    return [
        PolicyRule(
            rule_id="quantum_vulnerable_public_key_requires_pqc_migration_review",
            title="Quantum-vulnerable public-key crypto requires PQC migration review",
            description=(
                "Flags quantum-vulnerable public-key cryptography for migration "
                "review."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={
                    "primitive": "public_key",
                    "quantum_status": "quantum_vulnerable",
                },
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.raises_priority,
                PolicyRuleEffect.requires_human_review,
                PolicyRuleEffect.adds_policy_context,
            ],
            rationale=(
                "RSA, finite-field DH, and ECC require migration review in a PQC "
                "transition context."
            ),
            recommendation="Review the asset for hybrid or PQC migration planning.",
            references=[
                "NIST-IR-8547-IPD",
                "NIST-SP-800-131A-REV3-IPD",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="standardized_pqc_can_be_retained_with_operational_review",
            title="Standardized PQC can be retained with operational review",
            description=(
                "Records that recognized standardized PQC algorithms can be retained "
                "when operational context is sufficient."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={"quantum_status": "standardized_pqc"},
            ),
            severity=PolicySeverity.info,
            effects=[
                PolicyRuleEffect.adds_policy_context,
                PolicyRuleEffect.recommends_target_state,
            ],
            rationale=(
                "Standardized PQC use should still be tied to operational context, "
                "protocol role, and implementation evidence."
            ),
            recommendation=(
                "Retain the asset state only after implementation and operational "
                "context are reviewed."
            ),
            references=[
                "NIST-FIPS-203",
                "NIST-FIPS-204",
                "NIST-FIPS-205",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="unknown_algorithm_requires_manual_crypto_review",
            title="Unknown algorithm requires manual crypto review",
            description="Blocks decision-grade treatment when the algorithm is unknown.",
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={"algorithm": "unknown"},
            ),
            severity=PolicySeverity.critical,
            effects=[
                PolicyRuleEffect.caps_confidence,
                PolicyRuleEffect.blocks_decision_grade,
                PolicyRuleEffect.requires_human_review,
            ],
            rationale=(
                "An unknown cryptographic algorithm cannot be safely classified for "
                "PQC migration."
            ),
            recommendation="Identify the algorithm before producing decision-grade PDRs.",
            references=["QSTRIAGE-SAFETY-POLICY"],
        ),
        PolicyRule(
            rule_id="cbom_defaulted_context_blocks_decision_grade",
            title="CBOM defaulted context blocks decision-grade output",
            description=(
                "Blocks decision-grade treatment when imported CBOM context is filled "
                "by QSTriage defaults."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.evidence_review,
                conditions={"source_type": "cyclonedx_cbom", "context": "defaulted"},
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.caps_confidence,
                PolicyRuleEffect.blocks_decision_grade,
                PolicyRuleEffect.requires_human_review,
            ],
            rationale=(
                "CBOM imports can provide cryptographic inventory evidence but may "
                "lack business context required for decisions."
            ),
            recommendation=(
                "Add declared business context before treating CBOM-derived records "
                "as decision-grade."
            ),
            references=[
                "CISA-PQC-DISCOVERY-INVENTORY",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="missing_business_context_requires_human_review",
            title="Missing business context requires human review",
            description=(
                "Requires review when data class, exposure, or retention evidence is "
                "missing."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={"business_context": "missing"},
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.blocks_decision_grade,
                PolicyRuleEffect.requires_human_review,
            ],
            rationale=(
                "Cryptographic migration priority depends on business impact, data "
                "sensitivity, exposure, and retention."
            ),
            recommendation=(
                "Declare data class, exposure, and retention before using the PDR as "
                "decision-grade evidence."
            ),
            references=[
                "CISA-PQC-DISCOVERY-INVENTORY",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="unknown_dependency_completeness_blocks_decision_grade",
            title="Unknown dependency completeness blocks decision-grade output",
            description=(
                "Blocks decision-grade treatment when dependency completeness is "
                "unknown."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.evidence_review,
                conditions={"relationship_completeness": "unknown"},
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.blocks_decision_grade,
                PolicyRuleEffect.requires_human_review,
            ],
            rationale=(
                "Incomplete dependency knowledge can hide upstream or downstream "
                "cryptographic exposure."
            ),
            recommendation="Clarify dependency completeness before decision-grade use.",
            references=[
                "CISA-PQC-DISCOVERY-INVENTORY",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="long_retention_sensitive_data_raises_priority",
            title="Long-retention sensitive data raises migration priority",
            description=(
                "Raises priority when sensitive data retention exceeds the policy "
                "threshold."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={
                    "data_class": "sensitive",
                    "retention_years": ">= long_retention_years",
                },
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.raises_priority,
                PolicyRuleEffect.requires_human_review,
                PolicyRuleEffect.adds_policy_context,
            ],
            rationale=(
                "Long-lived sensitive data increases harvest-now-decrypt-later "
                "migration urgency."
            ),
            recommendation=(
                "Prioritize migration review for long-retention sensitive data."
            ),
            references=[
                "NIST-IR-8547-IPD",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="public_or_partner_exposed_quantum_vulnerable_crypto_raises_priority",
            title="Public or partner exposure raises migration priority",
            description=(
                "Raises priority for exposed quantum-vulnerable public-key "
                "cryptography."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={
                    "quantum_status": "quantum_vulnerable",
                    "exposure": ["public", "partner"],
                },
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.raises_priority,
                PolicyRuleEffect.requires_human_review,
            ],
            rationale=(
                "Externally exposed cryptographic assets carry higher migration and "
                "coordination risk."
            ),
            recommendation=(
                "Review exposed assets for migration sequencing and stakeholder "
                "coordination."
            ),
            references=[
                "NIST-IR-8547-IPD",
                "CISA-QUANTUM-READINESS",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="ml_kem_usage_requires_key_establishment_context",
            title="ML-KEM usage requires key establishment context",
            description=(
                "Records that ML-KEM is a key-establishment mechanism and must be "
                "reviewed in protocol context."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.asset,
                conditions={"algorithm": "ML-KEM"},
            ),
            severity=PolicySeverity.medium,
            effects=[
                PolicyRuleEffect.adds_policy_context,
                PolicyRuleEffect.constrains_migration,
            ],
            rationale=(
                "ML-KEM should be evaluated in the context of key establishment, "
                "protocol integration, and implementation evidence."
            ),
            recommendation=(
                "Confirm the protocol role and implementation context for ML-KEM use."
            ),
            references=[
                "NIST-FIPS-203",
                "NIST-SP-800-227",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
        PolicyRule(
            rule_id="deprecated_or_disallowed_transition_status_requires_policy_finding",
            title="Deprecated or disallowed transition status requires a policy finding",
            description=(
                "Requires explicit policy context when an algorithm or key length is "
                "deprecated or disallowed."
            ),
            applicability=PolicyApplicability(
                target=PolicyApplicabilityTarget.classification,
                conditions={"transition_status": ["deprecated", "disallowed"]},
            ),
            severity=PolicySeverity.high,
            effects=[
                PolicyRuleEffect.raises_priority,
                PolicyRuleEffect.requires_human_review,
                PolicyRuleEffect.adds_policy_context,
            ],
            rationale=(
                "Transition status must be visible in PDR policy context rather than "
                "hidden in scoring code."
            ),
            recommendation=(
                "Produce a policy finding and migration review when transition status "
                "is deprecated or disallowed."
            ),
            references=[
                "NIST-SP-800-131A-REV3-IPD",
                "QSTRIAGE-SAFETY-POLICY",
            ],
        ),
    ]
