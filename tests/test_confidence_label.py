"""The score confidence label depends on key length and business context only.

Free text in ``notes`` must never change the label, the decision confidence,
or the execution state (design/context-resolution.md, section 6.1).
"""

import pytest

from qstriage.models import CryptographicAsset, Inventory
from qstriage.pdr import generate_pdr_document
from qstriage.scoring import score_inventory


def _asset(**overrides: object) -> CryptographicAsset:
    values: dict[str, object] = {
        "id": "asset-1",
        "name": "Asset 1",
        "environment": "production",
        "asset_type": "tls_endpoint",
        "protocol": "tls",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "customer_pii",
        "retention_years": 10,
        "exposure": "internal",
        "criticality": "high",
        "local_blast_radius": "high",
        "migration_effort": "high",
        "notes": "",
    }
    values.update(overrides)
    return CryptographicAsset(**values)


def _label(asset: CryptographicAsset) -> str:
    return score_inventory(Inventory(assets=[asset])).pop().confidence


def _record(asset: CryptographicAsset):
    return generate_pdr_document(Inventory(assets=[asset])).records[0]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, "medium-high"),
        ({"key_size_bits": None, "algorithm": "RSA"}, "low"),
        ({"data_class": "unknown"}, "medium"),
        ({"data_class": "Confidential"}, "medium"),
        ({"exposure": "redacted"}, "medium"),
        ({"retention_years": 0}, "medium"),
        (
            {
                "asset_type": "cbom_cryptographic_asset",
                "criticality": "medium",
            },
            "medium",
        ),
    ],
)
def test_label_follows_key_length_and_business_context(
    overrides: dict[str, object], expected: str
) -> None:
    assert _label(_asset(**overrides)) == expected
    assert _label(_asset(notes="Reviewed by the service owner.", **overrides)) == expected


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"algorithm": "ML-KEM-768", "key_size_bits": None},
        {"algorithm": "X25519MLKEM768", "key_size_bits": None},
        {"data_class": "Confidential"},
        {"retention_years": 0},
    ],
)
def test_notes_do_not_change_the_decision(overrides: dict[str, object]) -> None:
    without_notes = _record(_asset(**overrides))
    with_notes = _record(_asset(notes="x", **overrides))

    assert with_notes.decision_confidence == without_notes.decision_confidence
    assert with_notes.decision.execution_state == without_notes.decision.execution_state
    assert with_notes.decision.human_review_required == (
        without_notes.decision.human_review_required
    )
    assert with_notes.decision.reason_codes == without_notes.decision.reason_codes
