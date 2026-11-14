from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    StrictInt,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from qstriage.canonical_json import MAX_SAFE_INTEGER

from qstriage.limits import (
    MAX_ASSETS,
    MAX_DEPENDENCIES,
    MAX_IDENTIFIER_LENGTH,
    MAX_INVENTORY_FILE_BYTES,
    MAX_NOTES_LENGTH,
    MAX_SCENARIOS,
    MAX_SIMULATION_RESULTS,
    MAX_TEXT_LENGTH,
    load_yaml_limited,
    read_text_limited,
)


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class DependencyDirection(str, Enum):
    inbound = "inbound"
    outbound = "outbound"
    bidirectional = "bidirectional"


class DependencyType(str, Enum):
    auth = "auth"
    dataflow = "dataflow"
    tls_termination = "tls_termination"
    database = "database"
    logging = "logging"
    firmware_update = "firmware_update"
    api_call = "api_call"
    telemetry_upload = "telemetry_upload"


CBOM_KEY_SIZE_PROPERTIES = ("keySize", "keySizeBits", "keyLength", "publicKeySize")


class CbomKeySize(BaseModel):
    """One size field of a CBOM component, kept as the CBOM stated it."""

    model_config = ConfigDict(extra="forbid")

    property: Literal["keySize", "keySizeBits", "keyLength", "publicKeySize"]
    bits: StrictInt = Field(ge=0, le=MAX_SAFE_INTEGER)


class CryptographicAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    name: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    environment: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    asset_type: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    protocol: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    algorithm: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    key_size_bits: int | None = Field(default=None, ge=0)
    cbom_key_sizes: list[CbomKeySize] | None = Field(
        default=None, min_length=2, max_length=len(CBOM_KEY_SIZE_PROPERTIES)
    )
    data_class: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    retention_years: int = Field(ge=0)
    exposure: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    criticality: RiskLevel
    local_blast_radius: RiskLevel
    migration_effort: RiskLevel
    notes: str = Field(default="", max_length=MAX_NOTES_LENGTH)

    @field_validator("cbom_key_sizes")
    @classmethod
    def _cbom_key_sizes_record_a_disagreement(
        cls, value: list[CbomKeySize] | None
    ) -> list[CbomKeySize] | None:
        if value is None:
            return value
        seen: set[str] = set()
        for entry in value:
            if entry.property in seen:
                raise ValueError(
                    f"cbom_key_sizes lists {entry.property} more than once. "
                    "List each CBOM size field once."
                )
            seen.add(entry.property)
        sizes = {entry.bits for entry in value}
        if len(sizes) == 1:
            raise ValueError(
                "cbom_key_sizes records CBOM size fields that disagree, but every "
                f"listed value is {value[0].bits} bits. Remove cbom_key_sizes and "
                f"set key_size_bits to {value[0].bits}."
            )
        return value

    # No return annotation: pydantic then keeps the model's own
    # serialization schema (an ``Any`` return would make it ``{}``).
    @model_serializer(mode="wrap")
    def _omit_absent_cbom_key_sizes(self, handler: SerializerFunctionWrapHandler):
        # Inventories without the field keep the hash they had before the
        # field existed: closure patches and PDR source hashes stay valid.
        data = handler(self)
        if self.cbom_key_sizes is None and isinstance(data, dict):
            data.pop("cbom_key_sizes", None)
        return data


def cbom_key_size_pairs(asset: CryptographicAsset) -> tuple[tuple[str, int], ...]:
    """The CBOM size fields kept on an asset, as (property, bits) pairs."""

    return tuple((entry.property, entry.bits) for entry in asset.cbom_key_sizes or ())


class Dependency(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    source: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    target: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    direction: DependencyDirection
    dependency_type: DependencyType
    protocol: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    weight: float = Field(ge=0.0, le=1.0)
    criticality: RiskLevel
    carries_crypto_context: bool = False
    notes: str = Field(default="", max_length=MAX_NOTES_LENGTH)


class MigrationScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    name: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    pqc_profile: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    mtu_bytes: int = Field(default=1500, ge=576)
    notes: str = Field(default="", max_length=MAX_NOTES_LENGTH)


class EvidenceAssertionState(str, Enum):
    declared = "declared"
    verified = "verified"


class EvidenceAssertionProvenance(str, Enum):
    user_declared = "user_declared"
    supplier_authoritative = "supplier_authoritative"
    third_party_asserted = "third_party_asserted"
    tool_generated = "tool_generated"


class RelationshipEvidenceCompleteness(str, Enum):
    none = "none"
    partial = "partial"
    known = "known"


class FieldEvidenceAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: EvidenceAssertionState
    provenance: EvidenceAssertionProvenance
    source_reference: str | None = Field(default=None, max_length=MAX_TEXT_LENGTH)
    rationale: str | None = Field(default=None, max_length=MAX_NOTES_LENGTH)

    @model_validator(mode="after")
    def require_verified_source_reference(self) -> FieldEvidenceAssertion:
        if self.state == EvidenceAssertionState.verified and not self.source_reference:
            raise ValueError("Verified evidence assertions require source_reference.")
        return self


class RelationshipEvidenceAssertion(FieldEvidenceAssertion):
    value: RelationshipEvidenceCompleteness


class AssetEvidenceAssertions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: FieldEvidenceAssertion | None = None
    data_class: FieldEvidenceAssertion | None = None
    retention_years: FieldEvidenceAssertion | None = None
    exposure: FieldEvidenceAssertion | None = None
    criticality: FieldEvidenceAssertion | None = None
    local_blast_radius: FieldEvidenceAssertion | None = None
    migration_effort: FieldEvidenceAssertion | None = None
    relationship_completeness: RelationshipEvidenceAssertion | None = None

    @model_validator(mode="after")
    def require_assertion(self) -> AssetEvidenceAssertions:
        if not any(value is not None for value in self.__dict__.values()):
            raise ValueError("Asset evidence must contain at least one assertion.")
        return self


class InventoryEvidenceMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal["0.1"]
    source_inventory_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    assets: dict[str, AssetEvidenceAssertions] = Field(min_length=1)


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[CryptographicAsset] = Field(min_length=1, max_length=MAX_ASSETS)
    dependencies: list[Dependency] = Field(default_factory=list, max_length=MAX_DEPENDENCIES)
    scenarios: list[MigrationScenario] = Field(default_factory=list, max_length=MAX_SCENARIOS)
    evidence: InventoryEvidenceMetadata | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def validate_inventory_integrity(self) -> Inventory:
        asset_ids = [asset.id for asset in self.assets]
        dependency_ids = [dependency.id for dependency in self.dependencies]
        scenario_ids = [scenario.id for scenario in self.scenarios]

        _ensure_unique(asset_ids, "asset id")
        _ensure_unique(dependency_ids, "dependency id")
        _ensure_unique(scenario_ids, "scenario id")

        known_assets = set(asset_ids)

        if self.evidence is not None:
            unknown_evidence_assets = set(self.evidence.assets) - known_assets
            if unknown_evidence_assets:
                joined = ", ".join(sorted(unknown_evidence_assets))
                raise ValueError(f"Evidence references unknown asset id: {joined}")

        simulation_result_count = len(self.assets) * max(1, len(self.scenarios))
        if simulation_result_count > MAX_SIMULATION_RESULTS:
            raise ValueError(
                "Inventory would generate "
                f"{simulation_result_count} simulation results; the supported limit is "
                f"{MAX_SIMULATION_RESULTS}. Reduce assets or scenarios."
            )

        for dependency in self.dependencies:
            if dependency.source not in known_assets:
                raise ValueError(
                    f"Dependency '{dependency.id}' references unknown source asset '{dependency.source}'."
                )
            if dependency.target not in known_assets:
                raise ValueError(
                    f"Dependency '{dependency.id}' references unknown target asset '{dependency.target}'."
                )
            if dependency.source == dependency.target:
                raise ValueError(
                    f"Dependency '{dependency.id}' cannot point an asset to itself."
                )

        return self

    def asset_by_id(self) -> dict[str, CryptographicAsset]:
        return {asset.id: asset for asset in self.assets}


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


def parse_inventory_yaml(text: str) -> Inventory:
    """Parse one already-captured inventory text snapshot."""

    raw_data: Any = load_yaml_limited(text, label="Inventory YAML")

    if raw_data is None:
        raw_data = {}

    try:
        return Inventory.model_validate(raw_data)
    except ValidationError:
        raise


def load_inventory(path: str | Path) -> Inventory:
    inventory_path = Path(path)

    text = read_text_limited(
        inventory_path,
        max_bytes=MAX_INVENTORY_FILE_BYTES,
        label="Inventory file",
    )
    return parse_inventory_yaml(text)
