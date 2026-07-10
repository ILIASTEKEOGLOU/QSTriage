from qstriage.context import (
    ContextValueState,
    DataSensitivity,
    ExposureCategory,
    normalize_asset_context,
    normalize_context_text,
    normalize_data_sensitivity,
    normalize_exposure,
)
from qstriage.models import CryptographicAsset, RiskLevel


def _asset(**overrides: object) -> CryptographicAsset:
    values = {
        "id": "asset-1",
        "name": "Asset 1",
        "environment": "prod",
        "asset_type": "service",
        "protocol": "TLS",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "customer_pii",
        "retention_years": 5,
        "exposure": "public_internet",
        "criticality": RiskLevel.high,
        "local_blast_radius": RiskLevel.medium,
        "migration_effort": RiskLevel.low,
        "notes": "",
    }
    values.update(overrides)
    return CryptographicAsset(**values)


def test_normalize_context_text_unifies_case_spaces_and_separators() -> None:
    assert normalize_context_text(" Public-Facing ") == "public_facing"
    assert normalize_context_text("PII DATA") == "pii_data"


def test_known_data_sensitivity_aliases_preserve_raw_value() -> None:
    result = normalize_data_sensitivity("GDPR scope")

    assert result.raw_value == "GDPR scope"
    assert result.canonical_value is DataSensitivity.sensitive
    assert result.state is ContextValueState.declared
    assert result.requires_verification is False


def test_unmapped_enterprise_data_term_is_not_guessed_sensitive() -> None:
    result = normalize_data_sensitivity("Personal_Info_Scope")

    assert result.raw_value == "Personal_Info_Scope"
    assert result.canonical_value is DataSensitivity.unknown
    assert result.state is ContextValueState.unmapped
    assert result.requires_verification is True


def test_unknown_data_sensitivity_is_missing_not_unmapped() -> None:
    result = normalize_data_sensitivity("unknown")

    assert result.canonical_value is DataSensitivity.unknown
    assert result.state is ContextValueState.missing


def test_known_exposure_aliases_preserve_raw_value() -> None:
    result = normalize_exposure("partner-facing")

    assert result.raw_value == "partner-facing"
    assert result.canonical_value is ExposureCategory.partner
    assert result.state is ContextValueState.declared


def test_unmapped_exposure_term_requires_verification_without_public_guess() -> None:
    result = normalize_exposure("publicish-admin-zone")

    assert result.canonical_value is ExposureCategory.unknown
    assert result.state is ContextValueState.unmapped


def test_cbom_import_defaults_are_stateful_context_not_raw_loss() -> None:
    context = normalize_asset_context(
        _asset(
            asset_type="cbom_cryptographic_asset",
            criticality=RiskLevel.medium,
            local_blast_radius=RiskLevel.medium,
            migration_effort=RiskLevel.medium,
        )
    )

    assert context.criticality.raw_value is RiskLevel.medium
    assert context.criticality.state is ContextValueState.defaulted
    assert context.local_blast_radius.state is ContextValueState.defaulted
    assert context.migration_effort.state is ContextValueState.defaulted
    assert context.requires_verification is True


def test_complete_declared_context_is_present() -> None:
    context = normalize_asset_context(_asset())

    assert context.business_context_present is True
    assert context.requires_verification is False
