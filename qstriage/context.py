"""One resolver for asset business context.

Every view that decides whether business context is usable (evidence review,
evidence quality, Evidence Closure, context review, policy facts, decision
requirements, score confidence) reads the result of ``normalize_asset_context``
so that the views cannot disagree. The design is recorded in
``design/context-resolution.md``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any

from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    RiskLevel,
)


class ContextValueState(str, Enum):
    verified = "verified"
    declared = "declared"
    defaulted = "defaulted"
    missing = "missing"
    redacted = "redacted"
    unmapped = "unmapped"


class ContextEffect(str, Enum):
    none = "none"
    review = "review"
    block = "block"


class DataSensitivity(str, Enum):
    sensitive = "sensitive"
    operational = "operational"
    public = "public"
    unknown = "unknown"


class ExposureCategory(str, Enum):
    public = "public"
    partner = "partner"
    internal = "internal"
    restricted = "restricted"
    isolated = "isolated"
    unknown = "unknown"


_UNRESOLVED_STATES = {
    ContextValueState.missing,
    ContextValueState.redacted,
    ContextValueState.unmapped,
    ContextValueState.defaulted,
}


@dataclass(frozen=True)
class NormalizedDataSensitivity:
    """Value-level reading of a data_class label, without evidence."""

    raw_value: str | None
    canonical_value: DataSensitivity
    state: ContextValueState

    @property
    def requires_verification(self) -> bool:
        return self.state in _UNRESOLVED_STATES


@dataclass(frozen=True)
class NormalizedExposure:
    """Value-level reading of an exposure label, without evidence."""

    raw_value: str | None
    canonical_value: ExposureCategory
    state: ContextValueState

    @property
    def requires_verification(self) -> bool:
        return self.state in _UNRESOLVED_STATES


@dataclass(frozen=True)
class ResolvedField:
    """The resolved value, state, provenance and required action of one field."""

    field: str
    field_path: str
    raw_value: Any
    canonical_value: Any
    state: ContextValueState
    provenance: str
    source_reference: str | None
    reason_code: str | None
    message: str | None
    accepted_values: tuple[str, ...]
    effect: ContextEffect
    severity: str | None

    @property
    def requires_verification(self) -> bool:
        return self.effect is not ContextEffect.none


@dataclass(frozen=True)
class NormalizedAssetContext:
    data_sensitivity: ResolvedField
    exposure: ResolvedField
    retention_years: ResolvedField
    criticality: ResolvedField
    local_blast_radius: ResolvedField
    migration_effort: ResolvedField

    @property
    def fields(self) -> tuple[ResolvedField, ...]:
        return (
            self.data_sensitivity,
            self.retention_years,
            self.exposure,
            self.criticality,
            self.local_blast_radius,
            self.migration_effort,
        )

    @property
    def unresolved_fields(self) -> tuple[ResolvedField, ...]:
        return tuple(field for field in self.fields if field.requires_verification)

    @property
    def business_context_present(self) -> bool:
        return not self.unresolved_fields

    @property
    def requires_verification(self) -> bool:
        return not self.business_context_present


# QSTriage-defined labels (profile "qstriage-legacy"). They are not taken from
# an external classification scheme; see design/context-resolution.md, 4.2.
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

# FIPS 199 uses public information as its example of an information type
# whose confidentiality impact is not applicable.
_PUBLIC_DATA_ALIASES = {"public"}

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

# One set of unknown tokens for every module. "noassertion" is the SPDX
# spelling NOASSERTION after normalization.
_UNKNOWN_VALUES = {
    "",
    "unknown",
    "no_assertion",
    "noassertion",
    "no_value",
}

_REDACTED_VALUES = {"redacted"}

DATA_CLASS_LABELS: tuple[str, ...] = tuple(
    sorted(_SENSITIVE_ALIASES | _OPERATIONAL_ALIASES | _PUBLIC_DATA_ALIASES)
)
EXPOSURE_LABELS: tuple[str, ...] = tuple(
    sorted(
        _PUBLIC_EXPOSURE_ALIASES
        | _PARTNER_EXPOSURE_ALIASES
        | _INTERNAL_EXPOSURE_ALIASES
        | _RESTRICTED_EXPOSURE_ALIASES
        | _ISOLATED_EXPOSURE_ALIASES
    )
)
RISK_LEVEL_VALUES: tuple[str, ...] = ("low", "medium", "high", "critical")

CBOM_IMPORT_NOTE_MARKER = "Imported from CycloneDX CBOM"

_UNTIL_GATED = "Until then the decision for this asset stays gated."
_UNTIL_CAPPED = (
    "Until then decision confidence stays capped and human review is required."
)


def normalize_context_text(value: str | None) -> str:
    return "_".join((value or "").strip().lower().replace("-", "_").split())


def is_unknown_like(value: str | None) -> bool:
    return normalize_context_text(value) in _UNKNOWN_VALUES


def is_redacted(value: str | None) -> bool:
    return normalize_context_text(value) in _REDACTED_VALUES


def is_cbom_imported_asset(
    asset: CryptographicAsset,
    source_type: str = "qstriage_inventory",
) -> bool:
    return (
        source_type == "cyclonedx_cbom"
        or asset.asset_type == "cbom_cryptographic_asset"
        or CBOM_IMPORT_NOTE_MARKER in asset.notes
    )


def display_value(value: Any) -> str:
    """Quote a value for a message; invisible characters are shown as <U+XXXX>."""

    text = str(value)
    shown = "".join(
        f"<U+{ord(character):04X}>"
        if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"}
        else character
        for character in text
    )
    return f'"{shown}"'


def closest_label(value: str, labels: tuple[str, ...]) -> str | None:
    """Return the single accepted label within edit distance 2, if unique."""

    normalized = normalize_context_text(value)
    if not normalized:
        return None
    distances = [(_edit_distance(normalized, label), label) for label in labels]
    best = min(distance for distance, _ in distances)
    if best == 0 or best > 2:
        return None
    candidates = [label for distance, label in distances if distance == best]
    return candidates[0] if len(candidates) == 1 else None


def _edit_distance(left: str, right: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment)."""

    rows = len(left) + 1
    columns = len(right) + 1
    table = [[0] * columns for _ in range(rows)]
    for row in range(rows):
        table[row][0] = row
    for column in range(columns):
        table[0][column] = column
    for row in range(1, rows):
        for column in range(1, columns):
            cost = 0 if left[row - 1] == right[column - 1] else 1
            table[row][column] = min(
                table[row - 1][column] + 1,
                table[row][column - 1] + 1,
                table[row - 1][column - 1] + cost,
            )
            if (
                row > 1
                and column > 1
                and left[row - 1] == right[column - 2]
                and left[row - 2] == right[column - 1]
            ):
                table[row][column] = min(table[row][column], table[row - 2][column - 2] + 1)
    return table[-1][-1]


def normalize_data_sensitivity(value: str | None) -> NormalizedDataSensitivity:
    normalized = normalize_context_text(value)

    if normalized in _UNKNOWN_VALUES:
        return NormalizedDataSensitivity(value, DataSensitivity.unknown, ContextValueState.missing)
    if normalized in _REDACTED_VALUES:
        return NormalizedDataSensitivity(value, DataSensitivity.unknown, ContextValueState.redacted)
    if normalized in _SENSITIVE_ALIASES:
        return NormalizedDataSensitivity(value, DataSensitivity.sensitive, ContextValueState.declared)
    if normalized in _OPERATIONAL_ALIASES:
        return NormalizedDataSensitivity(value, DataSensitivity.operational, ContextValueState.declared)
    if normalized in _PUBLIC_DATA_ALIASES:
        return NormalizedDataSensitivity(value, DataSensitivity.public, ContextValueState.declared)

    return NormalizedDataSensitivity(value, DataSensitivity.unknown, ContextValueState.unmapped)


def normalize_exposure(value: str | None) -> NormalizedExposure:
    normalized = normalize_context_text(value)

    if normalized in _UNKNOWN_VALUES:
        return NormalizedExposure(value, ExposureCategory.unknown, ContextValueState.missing)
    if normalized in _REDACTED_VALUES:
        return NormalizedExposure(value, ExposureCategory.unknown, ContextValueState.redacted)
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


def normalize_asset_context(
    asset: CryptographicAsset,
    asset_evidence: AssetEvidenceAssertions | None = None,
    *,
    source_type: str = "qstriage_inventory",
) -> NormalizedAssetContext:
    """Resolve every business context field of one asset."""

    imported_from_cbom = is_cbom_imported_asset(asset, source_type)
    default_provenance = "qstriage_default" if imported_from_cbom else "user_declared"

    def assertion(field: str) -> FieldEvidenceAssertion | None:
        return getattr(asset_evidence, field) if asset_evidence is not None else None

    return NormalizedAssetContext(
        data_sensitivity=_resolve_label(
            asset,
            field="data_class",
            label="data classification",
            reading=normalize_data_sensitivity(asset.data_class),
            labels=DATA_CLASS_LABELS,
            assertion=assertion("data_class"),
            default_provenance=default_provenance,
        ),
        exposure=_resolve_label(
            asset,
            field="exposure",
            label="exposure",
            reading=normalize_exposure(asset.exposure),
            labels=EXPOSURE_LABELS,
            assertion=assertion("exposure"),
            default_provenance=default_provenance,
        ),
        retention_years=_resolve_retention(
            asset,
            assertion=assertion("retention_years"),
            imported_from_cbom=imported_from_cbom,
        ),
        criticality=_resolve_risk(
            asset,
            field="criticality",
            value=asset.criticality,
            assertion=assertion("criticality"),
            imported_from_cbom=imported_from_cbom,
        ),
        local_blast_radius=_resolve_risk(
            asset,
            field="local_blast_radius",
            value=asset.local_blast_radius,
            assertion=assertion("local_blast_radius"),
            imported_from_cbom=imported_from_cbom,
        ),
        migration_effort=_resolve_risk(
            asset,
            field="migration_effort",
            value=asset.migration_effort,
            assertion=assertion("migration_effort"),
            imported_from_cbom=imported_from_cbom,
        ),
    )


def resolve_asset_context(
    asset: CryptographicAsset,
    asset_evidence: AssetEvidenceAssertions | None = None,
    *,
    source_type: str = "qstriage_inventory",
) -> NormalizedAssetContext:
    """Alias of ``normalize_asset_context`` under the name used in the design."""

    return normalize_asset_context(asset, asset_evidence, source_type=source_type)


def _asserted_state(assertion: FieldEvidenceAssertion | None) -> ContextValueState:
    if assertion is not None and assertion.state == EvidenceAssertionState.verified:
        return ContextValueState.verified
    return ContextValueState.declared


def _provenance(assertion: FieldEvidenceAssertion | None, default: str) -> str:
    return assertion.provenance.value if assertion is not None else default


def _field_path(asset: CryptographicAsset, field: str) -> str:
    return f"assets[{asset.id}].{field}"


def _resolve_label(
    asset: CryptographicAsset,
    *,
    field: str,
    label: str,
    reading: NormalizedDataSensitivity | NormalizedExposure,
    labels: tuple[str, ...],
    assertion: FieldEvidenceAssertion | None,
    default_provenance: str,
) -> ResolvedField:
    path = _field_path(asset, field)
    raw = reading.raw_value
    shown = display_value(raw)
    accepted = ", ".join(labels)
    common = {
        "field": field,
        "field_path": path,
        "raw_value": raw,
        "canonical_value": reading.canonical_value,
        "provenance": _provenance(assertion, default_provenance),
        "source_reference": assertion.source_reference if assertion else None,
        "accepted_values": labels,
    }

    if reading.state is ContextValueState.missing:
        if assertion is not None:
            message = (
                f"{path}: an evidence assertion is recorded, but the value is {shown}. "
                "An assertion confirms a value; it cannot supply one. "
                f"Set {field} to an accepted label. {_UNTIL_GATED}"
            )
        else:
            message = (
                f"{path}: the value is {shown}, so no {label} is stated. "
                f"Set {field} to an accepted label: {accepted}. {_UNTIL_GATED}"
            )
        return ResolvedField(
            **common,
            state=ContextValueState.missing,
            reason_code=f"missing_{field}",
            message=message,
            effect=ContextEffect.block,
            severity="high",
        )

    if reading.state is ContextValueState.redacted:
        return ResolvedField(
            **common,
            state=ContextValueState.redacted,
            reason_code=f"redacted_{field}",
            message=(
                f"{path}: the value is {shown}. The source withheld the {label}. "
                f"Obtain it from the data owner and set {field}, or record it in an "
                f"Evidence Closure patch with a source_reference. {_UNTIL_GATED}"
            ),
            effect=ContextEffect.block,
            severity="high",
        )

    if reading.state is ContextValueState.unmapped:
        suggestion = closest_label(str(raw), labels)
        hint = f' Closest accepted label: "{suggestion}".' if suggestion else ""
        return ResolvedField(
            **common,
            state=ContextValueState.unmapped,
            reason_code=f"unmapped_{field}",
            message=(
                f"{path}: the value {shown} is not an accepted {label} label. "
                f"Accepted labels: {accepted}.{hint} Set {field} to one of these labels "
                f"in the inventory or in an Evidence Closure patch. {_UNTIL_GATED}"
            ),
            effect=ContextEffect.block,
            severity="high",
        )

    return ResolvedField(
        **common,
        state=_asserted_state(assertion),
        reason_code=None,
        message=None,
        effect=ContextEffect.none,
        severity=None,
    )


def _resolve_retention(
    asset: CryptographicAsset,
    *,
    assertion: FieldEvidenceAssertion | None,
    imported_from_cbom: bool,
) -> ResolvedField:
    field = "retention_years"
    path = _field_path(asset, field)
    common = {
        "field": field,
        "field_path": path,
        "raw_value": asset.retention_years,
        "canonical_value": asset.retention_years,
        "source_reference": assertion.source_reference if assertion else None,
        "accepted_values": ("integer number of years",),
    }

    if asset.retention_years != 0 or assertion is not None:
        return ResolvedField(
            **common,
            state=_asserted_state(assertion),
            provenance=_provenance(assertion, "user_declared"),
            reason_code=None,
            message=None,
            effect=ContextEffect.none,
            severity=None,
        )

    if imported_from_cbom:
        return ResolvedField(
            **common,
            state=ContextValueState.defaulted,
            provenance="qstriage_default",
            reason_code="defaulted_retention_years",
            message=(
                f"{path}: the value 0 is the default that the CBOM import assigns. "
                "No evidence assertion confirms it. Set retention_years to the number "
                "of years the data must remain protected, in the inventory or in an "
                f"Evidence Closure patch. {_UNTIL_GATED}"
            ),
            effect=ContextEffect.block,
            severity="high",
        )

    return ResolvedField(
        **common,
        state=ContextValueState.missing,
        provenance="user_declared",
        reason_code="unconfirmed_zero_retention_years",
        message=(
            f"{path}: the value is 0, which means the data is not retained, and no "
            "evidence assertion confirms it. Set retention_years to the number of "
            "years the data must remain protected, or confirm 0 with an evidence "
            f"assertion. {_UNTIL_GATED}"
        ),
        effect=ContextEffect.block,
        severity="high",
    )


def _resolve_risk(
    asset: CryptographicAsset,
    *,
    field: str,
    value: RiskLevel,
    assertion: FieldEvidenceAssertion | None,
    imported_from_cbom: bool,
) -> ResolvedField:
    path = _field_path(asset, field)
    common = {
        "field": field,
        "field_path": path,
        "raw_value": value,
        "canonical_value": value,
        "source_reference": assertion.source_reference if assertion else None,
        "accepted_values": RISK_LEVEL_VALUES,
    }

    if imported_from_cbom and value == RiskLevel.medium and assertion is None:
        return ResolvedField(
            **common,
            state=ContextValueState.defaulted,
            provenance="qstriage_default",
            reason_code=f"defaulted_{field}",
            message=(
                f'{path}: the value "medium" is the default that the CBOM import '
                "assigns. No evidence assertion confirms it. Confirm or replace "
                f"{field} ({', '.join(RISK_LEVEL_VALUES)}) in an Evidence Closure "
                f"patch. {_UNTIL_CAPPED}"
            ),
            effect=ContextEffect.review,
            severity="medium",
        )

    return ResolvedField(
        **common,
        state=_asserted_state(assertion),
        provenance=_provenance(assertion, "user_declared"),
        reason_code=None,
        message=None,
        effect=ContextEffect.none,
        severity=None,
    )
