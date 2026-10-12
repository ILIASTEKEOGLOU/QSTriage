"""Reading rules of the business context resolver (design section 3)."""

import pytest

from qstriage.context import (
    ContextEffect,
    ContextValueState,
    DataSensitivity,
    closest_label,
    display_value,
    normalize_asset_context,
)
from qstriage.evidence import EvidenceState, review_asset_evidence
from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    RiskLevel,
)


def _asset(**overrides: object) -> CryptographicAsset:
    values: dict[str, object] = {
        "id": "asset-1",
        "name": "Asset 1",
        "environment": "production",
        "asset_type": "service",
        "protocol": "tls",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "customer_pii",
        "retention_years": 10,
        "exposure": "internal",
        "criticality": RiskLevel.high,
        "local_blast_radius": RiskLevel.high,
        "migration_effort": RiskLevel.high,
    }
    values.update(overrides)
    return CryptographicAsset(**values)


def _assertion(state: EvidenceAssertionState = EvidenceAssertionState.declared):
    return FieldEvidenceAssertion(
        state=state,
        provenance=EvidenceAssertionProvenance.supplier_authoritative,
        source_reference="records-policy-RP-14",
    )


@pytest.mark.parametrize("value", ["", "unknown", "NOASSERTION", "no assertion", "no_value"])
def test_unknown_tokens_are_missing(value: str) -> None:
    resolved = normalize_asset_context(_asset(data_class=value or " ")).data_sensitivity

    assert resolved.state is ContextValueState.missing
    assert resolved.reason_code == "missing_data_class"
    assert resolved.effect is ContextEffect.block


def test_redacted_is_its_own_state_in_every_view() -> None:
    asset = _asset(exposure="REDACTED")
    resolved = normalize_asset_context(asset).exposure
    [finding] = review_asset_evidence(asset).findings

    assert resolved.state is ContextValueState.redacted
    assert resolved.effect is ContextEffect.block
    assert finding.code == "redacted_exposure"
    assert finding.evidence_state is EvidenceState.redacted
    assert "withheld" in finding.message


def test_public_is_an_accepted_data_class_without_sensitivity_increment() -> None:
    resolved = normalize_asset_context(_asset(data_class="public")).data_sensitivity

    assert resolved.state is ContextValueState.declared
    assert resolved.canonical_value is DataSensitivity.public
    assert resolved.effect is ContextEffect.none


def test_unmapped_label_names_accepted_labels_and_a_close_match() -> None:
    resolved = normalize_asset_context(_asset(data_class="customer_pi")).data_sensitivity

    assert resolved.state is ContextValueState.unmapped
    assert resolved.reason_code == "unmapped_data_class"
    assert 'the value "customer_pi" is not an accepted data classification label' in (
        resolved.message
    )
    assert 'Closest accepted label: "customer_pii".' in resolved.message
    assert "customer_pii, gdpr_scope" in resolved.message


def test_unmapped_label_without_close_match_gets_no_suggestion() -> None:
    resolved = normalize_asset_context(_asset(data_class="Confidential")).data_sensitivity

    assert resolved.state is ContextValueState.unmapped
    assert "Closest accepted label" not in resolved.message


def test_verified_assertion_does_not_make_an_unrecognized_value_usable() -> None:
    evidence = AssetEvidenceAssertions(
        data_class=_assertion(EvidenceAssertionState.verified)
    )
    resolved = normalize_asset_context(
        _asset(data_class="Confidential"), evidence
    ).data_sensitivity

    assert resolved.state is ContextValueState.unmapped
    assert resolved.effect is ContextEffect.block


def test_assertion_cannot_supply_a_missing_value() -> None:
    evidence = AssetEvidenceAssertions(data_class=_assertion())
    asset = _asset(data_class="unknown")
    resolved = normalize_asset_context(asset, evidence).data_sensitivity
    [finding] = review_asset_evidence(asset, asset_evidence=evidence).findings

    assert resolved.state is ContextValueState.missing
    assert "it cannot supply one" in resolved.message
    assert finding.evidence_state is EvidenceState.unknown


def test_assertion_resolves_a_cbom_default() -> None:
    asset = _asset(
        asset_type="cbom_cryptographic_asset",
        migration_effort=RiskLevel.medium,
    )
    without = normalize_asset_context(asset).migration_effort
    with_assertion = normalize_asset_context(
        asset, AssetEvidenceAssertions(migration_effort=_assertion())
    ).migration_effort

    assert without.state is ContextValueState.defaulted
    assert without.effect is ContextEffect.review
    assert with_assertion.state is ContextValueState.declared
    assert with_assertion.effect is ContextEffect.none
    assert with_assertion.provenance == "supplier_authoritative"


def test_verified_assertion_gives_verified_state() -> None:
    resolved = normalize_asset_context(
        _asset(), AssetEvidenceAssertions(retention_years=_assertion(EvidenceAssertionState.verified))
    ).retention_years

    assert resolved.state is ContextValueState.verified
    assert resolved.source_reference == "records-policy-RP-14"


def test_zero_retention_needs_an_assertion_in_every_inventory() -> None:
    hand_written = normalize_asset_context(_asset(retention_years=0)).retention_years
    imported = normalize_asset_context(
        _asset(retention_years=0, asset_type="cbom_cryptographic_asset")
    ).retention_years
    confirmed = normalize_asset_context(
        _asset(retention_years=0), AssetEvidenceAssertions(retention_years=_assertion())
    ).retention_years

    assert hand_written.reason_code == "unconfirmed_zero_retention_years"
    assert hand_written.effect is ContextEffect.block
    assert imported.reason_code == "defaulted_retention_years"
    assert imported.state is ContextValueState.defaulted
    assert confirmed.effect is ContextEffect.none


def test_cbom_detection_uses_source_type_asset_type_or_import_note() -> None:
    for asset, source_type in (
        (_asset(criticality=RiskLevel.medium), "cyclonedx_cbom"),
        (_asset(criticality=RiskLevel.medium, asset_type="cbom_cryptographic_asset"), "qstriage_inventory"),
        (_asset(criticality=RiskLevel.medium, notes="Imported from CycloneDX CBOM."), "qstriage_inventory"),
    ):
        resolved = normalize_asset_context(asset, source_type=source_type).criticality
        assert resolved.state is ContextValueState.defaulted


def test_invisible_characters_are_shown_in_messages() -> None:
    assert display_value("pii​") == '"pii<U+200B>"'
    assert display_value("a‮b") == '"a<U+202E>b"'


def test_closest_label_requires_a_unique_match_within_two_edits() -> None:
    labels = ("internal", "internet", "isolated")

    assert closest_label("isolatd", labels) == "isolated"
    assert closest_label("interna", labels) == "internal"
    assert closest_label("intern", labels) is None
    assert closest_label("completely-different", labels) is None
