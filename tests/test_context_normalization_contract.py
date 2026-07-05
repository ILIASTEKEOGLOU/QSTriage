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
    ("data_class", "policy_sensitivity", "shelf_life_risk"),
    [
        ("customer_pii", "sensitive", 8.0),
        ("identity_tokens", "sensitive", 8.0),
        ("payment_metadata", "sensitive", 8.0),
        ("telemetry", "operational", 7.0),
    ],
)
def test_legacy_data_class_context_contract(
    data_class: str,
    policy_sensitivity: str,
    shelf_life_risk: float,
) -> None:
    assert _derive_data_class_sensitivity(data_class) == policy_sensitivity
    assert _shelf_life_risk(5, data_class) == shelf_life_risk


@pytest.mark.parametrize(
    (
        "exposure",
        "policy_category",
        "exposure_risk",
        "deadline_pressure",
        "middlebox_risk",
    ),
    [
        ("public_internet", "public", 9.0, 3.0, "high"),
        ("partner_network", "partner", 7.0, 3.0, "high"),
        ("internal", "internal", 4.0, 1.0, "medium"),
        ("restricted_network", "restricted", 5.0, 1.0, "medium"),
        ("isolated", "isolated", 2.0, 1.0, "medium"),
    ],
)
def test_legacy_exposure_context_contract(
    exposure: str,
    policy_category: str,
    exposure_risk: float,
    deadline_pressure: float,
    middlebox_risk: str,
) -> None:
    asset = _asset_with_exposure(exposure)

    assert _derive_exposure_category(exposure) == policy_category
    assert _exposure_risk(exposure) == exposure_risk
    assert _deadline_pressure(asset) == deadline_pressure
    assert _middlebox_risk(asset, 1.0) == middlebox_risk
