import pytest

from qstriage.policy import (
    _derive_data_class_sensitivity,
    _derive_exposure_category,
)


@pytest.mark.parametrize(
    "data_class",
    ["GDPR_scope", "cardholder_data", "patient_records"],
)
def test_policy_derived_data_class_sensitivity_normalizes_realistic_terms(
    data_class: str,
) -> None:
    assert _derive_data_class_sensitivity(data_class) == "sensitive"


@pytest.mark.parametrize(
    ("exposure", "expected"),
    [
        ("public-facing", "public"),
        ("internet_facing", "public"),
        ("external-facing", "public"),
        ("dmz", "public"),
        ("perimeter", "public"),
        ("edge", "public"),
        ("partner-facing", "partner"),
        ("third-party", "partner"),
        ("vendor", "partner"),
        ("supplier", "partner"),
        ("internal-only", "internal"),
        ("private-network", "internal"),
        ("corp", "internal"),
        ("corporate", "internal"),
        ("lan", "internal"),
        ("offline", "restricted"),
        ("air-gapped", "restricted"),
        ("segmented", "restricted"),
    ],
)
def test_policy_derived_exposure_category_normalizes_common_terms(
    exposure: str,
    expected: str,
) -> None:
    assert _derive_exposure_category(exposure) == expected


@pytest.mark.parametrize(
    "exposure",
    ["dmz_zone_1", "edge_gateway", "planning"],
)
def test_policy_exposure_category_keeps_unrecognized_variants_unknown(
    exposure: str,
) -> None:
    assert _derive_exposure_category(exposure) == "unknown"
