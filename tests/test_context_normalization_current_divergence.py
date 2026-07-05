import pytest

from qstriage.models import CryptographicAsset, RiskLevel
from qstriage.policy import (
    _derive_data_class_sensitivity,
    _derive_exposure_category,
)
from qstriage.scoring import (
    _deadline_pressure,
    _exposure_risk,
    _shelf_life_risk,
)
from qstriage.simulator import _middlebox_risk


def _asset_with_exposure(exposure: str) -> CryptographicAsset:
    return CryptographicAsset(
        id=f"asset-{exposure}",
        name=f"Asset {exposure}",
        environment="test",
        asset_type="service",
        protocol="custom",
        algorithm="AES-256",
        key_size_bits=256,
        data_class="internal",
        retention_years=5,
        exposure=exposure,
        criticality=RiskLevel.medium,
        local_blast_radius=RiskLevel.low,
        migration_effort=RiskLevel.low,
    )


@pytest.mark.parametrize(
    "data_class",
    ["GDPR_scope", "cardholder_data", "patient_records"],
)
def test_new_sensitive_data_classes_currently_miss_scoring_shelf_life_bonus(
    data_class: str,
) -> None:
    # Known v1.1E gap: policy classifies these as sensitive after v1.1D,
    # but scoring still applies no sensitive-data shelf-life bonus.
    assert _derive_data_class_sensitivity(data_class) == "sensitive"
    assert _shelf_life_risk(5, data_class) == 7.0


@pytest.mark.parametrize(
    ("exposure", "policy_category"),
    [
        ("public-facing", "public"),
        ("internet_facing", "public"),
        ("dmz", "public"),
        ("perimeter", "public"),
        ("edge", "public"),
        ("partner-facing", "partner"),
        ("third-party", "partner"),
        ("vendor", "partner"),
        ("supplier", "partner"),
    ],
)
def test_policy_external_exposures_currently_miss_deadline_pressure(
    exposure: str,
    policy_category: str,
) -> None:
    # Known v1.1E gap: policy sees these as external, but scoring deadline
    # pressure still recognizes only public_internet and partner_network.
    asset = _asset_with_exposure(exposure)

    assert _derive_exposure_category(exposure) == policy_category
    assert _deadline_pressure(asset) == 1.0


@pytest.mark.parametrize(
    ("exposure", "policy_category"),
    [
        ("internet_facing", "public"),
        ("dmz", "public"),
        ("perimeter", "public"),
        ("edge", "public"),
        ("third-party", "partner"),
        ("vendor", "partner"),
        ("supplier", "partner"),
    ],
)
def test_policy_external_exposures_currently_miss_simulator_external_path(
    exposure: str,
    policy_category: str,
) -> None:
    # Known v1.1E gap: policy sees these as external, but simulator external
    # path checks still look only for public/partner substrings.
    asset = _asset_with_exposure(exposure)

    assert _derive_exposure_category(exposure) == policy_category
    assert _middlebox_risk(asset, 1.0) == "medium"


@pytest.mark.parametrize(
    ("exposure", "policy_category"),
    [
        ("dmz", "public"),
        ("perimeter", "public"),
        ("edge", "public"),
        ("third-party", "partner"),
        ("vendor", "partner"),
        ("supplier", "partner"),
    ],
)
def test_policy_external_exposures_currently_default_scoring_exposure_risk(
    exposure: str,
    policy_category: str,
) -> None:
    # Known v1.1E gap: policy sees these as public or partner exposure,
    # but scoring currently falls back to its generic 5.0 exposure default.
    assert _derive_exposure_category(exposure) == policy_category
    assert _exposure_risk(exposure) == 5.0

@pytest.mark.parametrize(
    "exposure",
    ["private-network", "corp", "corporate", "lan"],
)
def test_policy_internal_exposures_currently_default_scoring_exposure_risk(
    exposure: str,
) -> None:
    # Known v1.1E gap: policy sees these as internal exposure,
    # but scoring currently falls back to its generic 5.0 exposure default.
    # After shared normalization, these should become internal-tier exposure risk.
    assert _derive_exposure_category(exposure) == "internal"
    assert _exposure_risk(exposure) == 5.0
