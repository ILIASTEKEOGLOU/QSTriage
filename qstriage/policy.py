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
