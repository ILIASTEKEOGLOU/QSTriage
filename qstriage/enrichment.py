from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from qstriage.closure import inventory_hash
from qstriage.file_output import write_private_text
from qstriage.limits import MAX_ASSETS, MAX_INVENTORY_FILE_BYTES, read_text_limited
from qstriage.models import (
    AssetEvidenceAssertions,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    Inventory,
    InventoryEvidenceMetadata,
    RelationshipEvidenceAssertion,
    RelationshipEvidenceCompleteness,
    RiskLevel,
)


RegularField = Literal[
    "environment", "data_class", "retention_years", "exposure", "criticality",
    "local_blast_radius", "migration_effort",
]


class RegularEnrichmentAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    field: RegularField
    value: Any
    state: EvidenceAssertionState
    provenance: EvidenceAssertionProvenance
    source_reference: str | None = None
    rationale: str | None = None

    @model_validator(mode="after")
    def require_verified_source(self) -> RegularEnrichmentAssertion:
        if self.state == EvidenceAssertionState.verified and not self.source_reference:
            raise ValueError("Verified assertions require source_reference.")
        return self


class RelationshipEnrichmentAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    completeness: RelationshipEvidenceCompleteness
    state: EvidenceAssertionState
    provenance: EvidenceAssertionProvenance
    source_reference: str | None = None
    rationale: str | None = None

    @model_validator(mode="after")
    def require_verified_source(self) -> RelationshipEnrichmentAssertion:
        if self.state == EvidenceAssertionState.verified and not self.source_reference:
            raise ValueError("Verified assertions require source_reference.")
        return self


class EnrichmentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_version: Literal["0.1"]
    source_inventory_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    assertions: list[RegularEnrichmentAssertion] = Field(
        default_factory=list, max_length=MAX_ASSETS * 7
    )
    relationship_assertions: list[RelationshipEnrichmentAssertion] = Field(
        default_factory=list, max_length=MAX_ASSETS
    )


def load_enrichment_patch(path: str | Path) -> EnrichmentPatch:
    text = read_text_limited(
        Path(path), max_bytes=MAX_INVENTORY_FILE_BYTES, label="Enrichment patch"
    )
    raw = yaml.safe_load(text)
    return EnrichmentPatch.model_validate({} if raw is None else raw)


def validate_enrichment_patch(inventory: Inventory, patch: EnrichmentPatch) -> None:
    if patch.source_inventory_hash != inventory_hash(inventory):
        raise ValueError("Patch source hash does not match the inventory.")

    known_assets = set(inventory.asset_by_id())
    targets: set[tuple[str, str]] = set()
    for assertion in patch.assertions:
        if assertion.asset_id not in known_assets:
            raise ValueError(f"Patch references unknown asset '{assertion.asset_id}'.")
        target = (assertion.asset_id, assertion.field)
        if target in targets:
            raise ValueError(f"Patch contains duplicate assertion for {target}.")
        targets.add(target)
        _validated_value(assertion.field, assertion.value)

    relationship_assets: set[str] = set()
    related_assets = {
        asset_id
        for dependency in inventory.dependencies
        for asset_id in (dependency.source, dependency.target)
    }
    for assertion in patch.relationship_assertions:
        if assertion.asset_id not in known_assets:
            raise ValueError(f"Patch references unknown asset '{assertion.asset_id}'.")
        if assertion.asset_id in relationship_assets:
            raise ValueError(
                f"Patch contains duplicate relationship assertion for '{assertion.asset_id}'."
            )
        relationship_assets.add(assertion.asset_id)
        if (
            assertion.completeness == RelationshipEvidenceCompleteness.none
            and assertion.asset_id in related_assets
        ):
            raise ValueError(
                f"Relationship completeness none conflicts with existing dependencies "
                f"for asset '{assertion.asset_id}'."
            )


def _validated_value(field: str, value: Any) -> Any:
    if field == "retention_years":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("retention_years must be an integer greater than or equal to 0.")
        return value
    if field in {"criticality", "local_blast_radius", "migration_effort"}:
        if not isinstance(value, str) or value not in {item.value for item in RiskLevel}:
            raise ValueError(f"{field} must be low, medium, high, or critical.")
        return RiskLevel(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string.")
    return value


def apply_enrichment_patch(inventory: Inventory, patch: EnrichmentPatch) -> Inventory:
    validate_enrichment_patch(inventory, patch)
    enriched = inventory.model_copy(deep=True)
    assets = enriched.asset_by_id()
    evidence_assets = (
        {key: value.model_copy(deep=True) for key, value in enriched.evidence.assets.items()}
        if enriched.evidence is not None
        else {}
    )

    for assertion in patch.assertions:
        setattr(
            assets[assertion.asset_id],
            assertion.field,
            _validated_value(assertion.field, assertion.value),
        )
        evidence = evidence_assets.get(assertion.asset_id, AssetEvidenceAssertions.model_construct())
        setattr(evidence, assertion.field, _field_evidence(assertion))
        evidence_assets[assertion.asset_id] = evidence

    for assertion in patch.relationship_assertions:
        evidence = evidence_assets.get(assertion.asset_id, AssetEvidenceAssertions.model_construct())
        evidence.relationship_completeness = RelationshipEvidenceAssertion(
            state=assertion.state,
            provenance=assertion.provenance,
            source_reference=assertion.source_reference,
            rationale=assertion.rationale,
            value=assertion.completeness,
        )
        evidence_assets[assertion.asset_id] = evidence

    if evidence_assets:
        enriched.evidence = InventoryEvidenceMetadata(
            version="0.1",
            source_inventory_hash=patch.source_inventory_hash,
            assets=evidence_assets,
        )
    return Inventory.model_validate(enriched.model_dump(mode="json"))


def _field_evidence(assertion: RegularEnrichmentAssertion) -> FieldEvidenceAssertion:
    return FieldEvidenceAssertion(
        state=assertion.state,
        provenance=assertion.provenance,
        source_reference=assertion.source_reference,
        rationale=assertion.rationale,
    )


def write_enriched_inventory(
    inventory: Inventory,
    patch: EnrichmentPatch,
    output_path: str | Path,
    *,
    input_path: str | Path | None = None,
) -> Path:
    enriched = apply_enrichment_patch(inventory, patch)
    payload = yaml.safe_dump(
        enriched.model_dump(mode="json"), sort_keys=False, allow_unicode=True
    )
    return write_private_text(
        output_path,
        payload,
        protected_paths=(input_path,),
    )
