from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


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

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    asset_type: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    key_size_bits: int | None = Field(default=None, ge=0)
    data_class: str = Field(min_length=1)
    retention_years: int = Field(ge=0)
    exposure: str = Field(min_length=1)
    criticality: RiskLevel
    local_blast_radius: RiskLevel
    migration_effort: RiskLevel
    notes: str = ""


class Dependency(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    direction: DependencyDirection
    dependency_type: DependencyType
    protocol: str = Field(min_length=1)
    weight: float = Field(ge=0.0, le=1.0)
    criticality: RiskLevel
    carries_crypto_context: bool = False
    notes: str = ""


class MigrationScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    pqc_profile: str = Field(min_length=1)
    mtu_bytes: int = Field(default=1500, ge=576)
    notes: str = ""


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[CryptographicAsset]
    dependencies: list[Dependency] = Field(default_factory=list)
    scenarios: list[MigrationScenario] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_inventory_integrity(self) -> Inventory:
        asset_ids = [asset.id for asset in self.assets]
        dependency_ids = [dependency.id for dependency in self.dependencies]
        scenario_ids = [scenario.id for scenario in self.scenarios]

        _ensure_unique(asset_ids, "asset id")
        _ensure_unique(dependency_ids, "dependency id")
        _ensure_unique(scenario_ids, "scenario id")

        known_assets = set(asset_ids)

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

    with inventory_path.open("r", encoding="utf-8") as file:
        raw_data: Any = yaml.safe_load(file)

    if raw_data is None:
        raw_data = {}

    try:
        return Inventory.model_validate(raw_data)
    except ValidationError:
        raise
