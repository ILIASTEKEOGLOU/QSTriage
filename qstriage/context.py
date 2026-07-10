from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from qstriage.models import CryptographicAsset, RiskLevel


class ContextValueState(str, Enum):
    declared = "declared"
    missing = "missing"
    defaulted = "defaulted"
    unmapped = "unmapped"


class DataSensitivity(str, Enum):
    sensitive = "sensitive"
    operational = "operational"
    unknown = "unknown"


class ExposureCategory(str, Enum):
    public = "public"
    partner = "partner"
    internal = "internal"
    restricted = "restricted"
    isolated = "isolated"
    unknown = "unknown"


@dataclass(frozen=True)
class NormalizedDataSensitivity:
    raw_value: str | None
    canonical_value: DataSensitivity
    state: ContextValueState

    @property
    def requires_verification(self) -> bool:
        return self.state in {
            ContextValueState.missing,
            ContextValueState.defaulted,
            ContextValueState.unmapped,
        }


@dataclass(frozen=True)
class NormalizedExposure:
    raw_value: str | None
    canonical_value: ExposureCategory
    state: ContextValueState

    @property
    def requires_verification(self) -> bool:
        return self.state in {
            ContextValueState.missing,
            ContextValueState.defaulted,
            ContextValueState.unmapped,
        }


@dataclass(frozen=True)
class NormalizedRiskValue:
    raw_value: RiskLevel | int | None
    canonical_value: RiskLevel | int | None
    state: ContextValueState

    @property
    def requires_verification(self) -> bool:
        return self.state in {
            ContextValueState.missing,
            ContextValueState.defaulted,
            ContextValueState.unmapped,
        }


@dataclass(frozen=True)
class NormalizedAssetContext:
    data_sensitivity: NormalizedDataSensitivity
    exposure: NormalizedExposure
    retention_years: NormalizedRiskValue
    criticality: NormalizedRiskValue
    local_blast_radius: NormalizedRiskValue
    migration_effort: NormalizedRiskValue

    @property
    def business_context_present(self) -> bool:
        return not any(
            value.requires_verification
            for value in (
                self.data_sensitivity,
                self.exposure,
                self.retention_years,
                self.criticality,
                self.local_blast_radius,
                self.migration_effort,
            )
        )

    @property
    def requires_verification(self) -> bool:
        return not self.business_context_present


_SENSITIVE_ALIASES = {
    "customer_pii",
    "pii_data",
    "pii",
    "identity_tokens",
    "payment_metadata",
    "payment_data",
    "gdpr_scope",
    "cardholder",
    "cardholder_data",
    "patient",
    "patient_records",
    "medical",
    "medical_records",
    "health",
    "health_data",
}

_OPERATIONAL_ALIASES = {
    "telemetry",
    "internal",
    "operational",
    "logs",
    "metrics",
}

_PUBLIC_EXPOSURE_ALIASES = {
    "public_internet",
    "internet",
    "public",
    "public_facing",
    "internet_facing",
    "external",
    "external_facing",
    "dmz",
    "perimeter",
    "edge",
}

_PARTNER_EXPOSURE_ALIASES = {
    "partner_network",
    "partner",
    "partner_facing",
    "third_party",
    "vendor",
    "supplier",
}

_INTERNAL_EXPOSURE_ALIASES = {
    "internal",
    "internal_only",
    "private_network",
    "corp",
    "corporate",
    "lan",
}

_RESTRICTED_EXPOSURE_ALIASES = {
    "restricted_network",
    "restricted",
    "offline",
    "air_gapped",
    "segmented",
}

_ISOLATED_EXPOSURE_ALIASES = {"isolated"}

_UNKNOWN_VALUES = {
    "",
    "unknown",
    "no_assertion",
    "no_value",
    "no-value",
    "redacted",
}



def normalize_context_text(value: str | None) -> str:
    return "_".join((value or "").strip().lower().replace("-", "_").split())


def is_unknown_like(value: str | None) -> bool:
    return normalize_context_text(value) in _UNKNOWN_VALUES


def is_cbom_imported_asset(asset: CryptographicAsset) -> bool:
    return (
        asset.asset_type == "cbom_cryptographic_asset"
        or "Imported from CycloneDX CBOM" in asset.notes
    )


def normalize_data_sensitivity(value: str | None) -> NormalizedDataSensitivity:
    normalized = normalize_context_text(value)

    if is_unknown_like(value):
        return NormalizedDataSensitivity(value, DataSensitivity.unknown, ContextValueState.missing)
    if normalized in _SENSITIVE_ALIASES:
        return NormalizedDataSensitivity(value, DataSensitivity.sensitive, ContextValueState.declared)
    if normalized in _OPERATIONAL_ALIASES:
        return NormalizedDataSensitivity(value, DataSensitivity.operational, ContextValueState.declared)

    return NormalizedDataSensitivity(value, DataSensitivity.unknown, ContextValueState.unmapped)


def normalize_exposure(value: str | None) -> NormalizedExposure:
    normalized = normalize_context_text(value)

    if is_unknown_like(value):
        return NormalizedExposure(value, ExposureCategory.unknown, ContextValueState.missing)
    if normalized in _PUBLIC_EXPOSURE_ALIASES:
        return NormalizedExposure(value, ExposureCategory.public, ContextValueState.declared)
    if normalized in _PARTNER_EXPOSURE_ALIASES:
        return NormalizedExposure(value, ExposureCategory.partner, ContextValueState.declared)
    if normalized in _INTERNAL_EXPOSURE_ALIASES:
        return NormalizedExposure(value, ExposureCategory.internal, ContextValueState.declared)
    if normalized in _RESTRICTED_EXPOSURE_ALIASES:
        return NormalizedExposure(value, ExposureCategory.restricted, ContextValueState.declared)
    if normalized in _ISOLATED_EXPOSURE_ALIASES:
        return NormalizedExposure(value, ExposureCategory.isolated, ContextValueState.declared)

    return NormalizedExposure(value, ExposureCategory.unknown, ContextValueState.unmapped)


def normalize_asset_context(asset: CryptographicAsset) -> NormalizedAssetContext:
    imported_from_cbom = is_cbom_imported_asset(asset)

    return NormalizedAssetContext(
        data_sensitivity=normalize_data_sensitivity(asset.data_class),
        exposure=normalize_exposure(asset.exposure),
        retention_years=NormalizedRiskValue(
            raw_value=asset.retention_years,
            canonical_value=asset.retention_years,
            state=(ContextValueState.missing if asset.retention_years == 0 else ContextValueState.declared),
        ),
        criticality=NormalizedRiskValue(
            raw_value=asset.criticality,
            canonical_value=asset.criticality,
            state=(ContextValueState.defaulted if imported_from_cbom and asset.criticality == RiskLevel.medium else ContextValueState.declared),
        ),
        local_blast_radius=NormalizedRiskValue(
            raw_value=asset.local_blast_radius,
            canonical_value=asset.local_blast_radius,
            state=(ContextValueState.defaulted if imported_from_cbom and asset.local_blast_radius == RiskLevel.medium else ContextValueState.declared),
        ),
        migration_effort=NormalizedRiskValue(
            raw_value=asset.migration_effort,
            canonical_value=asset.migration_effort,
            state=(ContextValueState.defaulted if imported_from_cbom and asset.migration_effort == RiskLevel.medium else ContextValueState.declared),
        ),
    )
