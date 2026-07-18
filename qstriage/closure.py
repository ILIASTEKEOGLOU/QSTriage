from __future__ import annotations

import hashlib
import json
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from qstriage.evidence import EvidenceFinding, review_inventory_evidence
from qstriage.models import Inventory


_FIELD_ORDER = (
    "data_class",
    "retention_years",
    "exposure",
    "criticality",
    "local_blast_radius",
    "migration_effort",
    "relationship_completeness",
)
_CODE_TO_FIELD = {
    "missing_data_class": "data_class",
    "defaulted_retention_years": "retention_years",
    "missing_exposure": "exposure",
    "defaulted_criticality": "criticality",
    "defaulted_local_blast_radius": "local_blast_radius",
    "defaulted_migration_effort": "migration_effort",
    "unknown_dependency_completeness": "relationship_completeness",
}
_DETAILS = {
    "data_class": ("What business data classification applies?", "string", []),
    "retention_years": ("How many years must the data remain protected?", "integer >= 0", []),
    "exposure": ("What is the asset's exposure boundary?", "string", []),
    "criticality": ("What is the asset's business criticality?", "enum", ["low", "medium", "high", "critical"]),
    "local_blast_radius": ("What is the local blast radius?", "enum", ["low", "medium", "high", "critical"]),
    "migration_effort": ("What migration effort is expected?", "enum", ["low", "medium", "high", "critical"]),
    "relationship_completeness": ("How complete is the asset's relationship evidence?", "enum", ["none", "partial", "known"]),
}


class ClosureGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    code: str
    field: str
    severity: str
    question: str
    expected_type: str
    allowed_values: list[str]
    unresolved_effect: str


class EvidenceGapManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["0.1"] = "0.1"
    source_inventory_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    gaps: list[ClosureGap]


def inventory_hash(inventory: Inventory) -> str:
    payload = json.dumps(
        inventory.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def build_gap_manifest(inventory: Inventory) -> EvidenceGapManifest:
    gaps: list[ClosureGap] = []
    for review in review_inventory_evidence(inventory):
        for finding in review.findings:
            field = _CODE_TO_FIELD.get(finding.code)
            if field is not None:
                gaps.append(_gap_from_finding(finding, field))
    gaps.sort(key=lambda gap: (gap.asset_id, _FIELD_ORDER.index(gap.field)))
    return EvidenceGapManifest(source_inventory_hash=inventory_hash(inventory), gaps=gaps)


def _gap_from_finding(finding: EvidenceFinding, field: str) -> ClosureGap:
    question, expected_type, allowed_values = _DETAILS[field]
    effect = (
        finding.human_action.effect_if_unresolved
        if finding.human_action and finding.human_action.effect_if_unresolved
        else ", ".join(effect.value for effect in finding.effects)
    )
    return ClosureGap(
        asset_id=finding.asset_id or "",
        code=finding.code,
        field=field,
        severity=finding.severity.value,
        question=question,
        expected_type=expected_type,
        allowed_values=allowed_values,
        unresolved_effect=effect,
    )


def manifest_json(manifest: EvidenceGapManifest) -> str:
    return json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ) + "\n"


def build_patch_template(inventory: Inventory) -> str:
    manifest = build_gap_manifest(inventory)
    assertions = []
    relationships = []
    for gap in manifest.gaps:
        if gap.field == "relationship_completeness":
            relationships.append({
                "asset_id": gap.asset_id, "completeness": None, "state": None,
                "provenance": None, "source_reference": None, "rationale": None,
            })
        else:
            assertions.append({
                "asset_id": gap.asset_id, "field": gap.field, "value": None,
                "state": None, "provenance": None, "source_reference": None,
                "rationale": None,
            })
    return yaml.safe_dump(
        {
            "patch_version": "0.1",
            "source_inventory_hash": manifest.source_inventory_hash,
            "assertions": assertions,
            "relationship_assertions": relationships,
        },
        sort_keys=False,
        allow_unicode=True,
    )


def manifest_text(manifest: EvidenceGapManifest) -> str:
    if not manifest.gaps:
        return "No resolvable evidence gaps.\n"
    return "\n".join(
        f"{gap.asset_id}: {gap.field} [{gap.severity}] - {gap.question}"
        for gap in manifest.gaps
    ) + "\n"
