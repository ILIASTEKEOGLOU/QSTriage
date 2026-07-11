from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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


class CryptographicAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    name: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    environment: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    asset_type: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    protocol: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    algorithm: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    key_size_bits: int | None = Field(default=None, ge=0)
    data_class: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    retention_years: int = Field(ge=0)
    exposure: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    criticality: RiskLevel
    local_blast_radius: RiskLevel
    migration_effort: RiskLevel
    notes: str = Field(default="", max_length=MAX_NOTES_LENGTH)


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


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[CryptographicAsset] = Field(min_length=1, max_length=MAX_ASSETS)
    dependencies: list[Dependency] = Field(default_factory=list, max_length=MAX_DEPENDENCIES)
    scenarios: list[MigrationScenario] = Field(default_factory=list, max_length=MAX_SCENARIOS)

    @model_validator(mode="after")
    def validate_inventory_integrity(self) -> Inventory:
        asset_ids = [asset.id for asset in self.assets]
        dependency_ids = [dependency.id for dependency in self.dependencies]
        scenario_ids = [scenario.id for scenario in self.scenarios]

        _ensure_unique(asset_ids, "asset id")
        _ensure_unique(dependency_ids, "dependency id")
        _ensure_unique(scenario_ids, "scenario id")

        known_assets = set(asset_ids)

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


def load_inventory(path: str | Path) -> Inventory:
    inventory_path = Path(path)

    text = read_text_limited(
        inventory_path,
        max_bytes=MAX_INVENTORY_FILE_BYTES,
        label="Inventory file",
    )
    raw_data: Any = load_yaml_limited(text, label="Inventory YAML")

    if raw_data is None:
        raw_data = {}

    try:
        return Inventory.model_validate(raw_data)
    except ValidationError:
        raise
