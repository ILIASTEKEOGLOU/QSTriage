from __future__ import annotations

import hashlib
import json
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from qstriage.assessment import assess_inventory
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


class AssetClosureComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    action_before: str
    action_after: str
    execution_state_before: str
    execution_state_after: str
    evidence_score_before: float
    evidence_score_after: float
    confidence_cap_before: float
    confidence_cap_after: float
    verification_priority_before: str
    verification_priority_after: str
    closed_finding_codes: list[str]
    remaining_finding_codes: list[str]
    introduced_finding_codes: list[str]


class InventoryClosureComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["0.1"] = "0.1"
    before_inventory_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    after_inventory_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    assets: list[AssetClosureComparison]


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


def build_inventory_comparison(
    before: Inventory,
    after: Inventory,
) -> InventoryClosureComparison:
    before_ids = set(before.asset_by_id())
    after_ids = set(after.asset_by_id())
    if before_ids != after_ids:
        raise ValueError("Comparison inventories must contain the same asset IDs.")

    before_assessments = {item.asset.id: item for item in assess_inventory(before)}
    after_assessments = {item.asset.id: item for item in assess_inventory(after)}
    before_reviews = {
        item.asset_id: item for item in review_inventory_evidence(before)
    }
    after_reviews = {
        item.asset_id: item for item in review_inventory_evidence(after)
    }
    assets = []
    for asset_id in sorted(before_ids):
        before_assessment = before_assessments[asset_id]
        after_assessment = after_assessments[asset_id]
        before_review = before_reviews[asset_id]
        after_review = after_reviews[asset_id]
        before_codes = [finding.code for finding in before_review.findings]
        after_codes = [finding.code for finding in after_review.findings]
        before_set = set(before_codes)
        after_set = set(after_codes)
        assets.append(AssetClosureComparison(
            asset_id=asset_id,
            action_before=before_assessment.decision.action_type.value,
            action_after=after_assessment.decision.action_type.value,
            execution_state_before=before_assessment.decision.execution_state.value,
            execution_state_after=after_assessment.decision.execution_state.value,
            evidence_score_before=before_review.evidence_score,
            evidence_score_after=after_review.evidence_score,
            confidence_cap_before=before_review.confidence_cap,
            confidence_cap_after=after_review.confidence_cap,
            verification_priority_before=before_assessment.decision.verification_priority.value,
            verification_priority_after=after_assessment.decision.verification_priority.value,
            closed_finding_codes=[code for code in before_codes if code not in after_set],
            remaining_finding_codes=after_codes,
            introduced_finding_codes=[code for code in after_codes if code not in before_set],
        ))
    return InventoryClosureComparison(
        before_inventory_hash=inventory_hash(before),
        after_inventory_hash=inventory_hash(after),
        assets=assets,
    )


def comparison_json(comparison: InventoryClosureComparison) -> str:
    return json.dumps(
        comparison.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ) + "\n"


def comparison_text(comparison: InventoryClosureComparison) -> str:
    lines = ["QSTriage evidence closure comparison"]
    for asset in comparison.assets:
        closed = ", ".join(asset.closed_finding_codes) or "none"
        remaining = ", ".join(asset.remaining_finding_codes) or "none"
        introduced = ", ".join(asset.introduced_finding_codes) or "none"
        lines.extend([
            f"Asset: {asset.asset_id}",
            f"  Action: {asset.action_before} -> {asset.action_after}",
            f"  Execution: {asset.execution_state_before} -> {asset.execution_state_after}",
            f"  Evidence score: {asset.evidence_score_before:.2f} -> {asset.evidence_score_after:.2f}",
            f"  Confidence cap: {asset.confidence_cap_before:.2f} -> {asset.confidence_cap_after:.2f}",
            "  Verification priority: "
            f"{asset.verification_priority_before} -> {asset.verification_priority_after}",
            f"  Closed findings: {closed}",
            f"  Remaining findings: {remaining}",
            f"  Introduced findings: {introduced}",
        ])
    lines.append("This comparison is evidence diagnostics, not production authorization.")
    return "\n".join(lines) + "\n"
