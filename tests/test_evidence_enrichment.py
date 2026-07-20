from pathlib import Path

import pytest

from qstriage.cbom import import_cbom_inventory
from qstriage.evidence import (
    EvidenceCategory,
    EvidenceProvenance,
    EvidenceState,
    RelationshipCompleteness,
    review_asset_evidence,
    review_inventory_evidence,
)
from qstriage.models import Inventory


SAMPLE_CBOM = Path("tests/fixtures/sample_cbom.json")
SOURCE_HASH = f"sha256:{'a' * 64}"


def _assertion(
    state: str = "declared",
    provenance: str = "user_declared",
) -> dict[str, str]:
    assertion = {"state": state, "provenance": provenance}
    if state == "verified":
        assertion["source_reference"] = "evidence://source/1"
    return assertion


def _enrich(
    inventory: Inventory,
    assets: dict[str, dict[str, object]],
) -> Inventory:
    return Inventory.model_validate(
        {
            **inventory.model_dump(mode="json"),
            "evidence": {
                "version": "0.1",
                "source_inventory_hash": SOURCE_HASH,
                "assets": assets,
            },
        }
    )


def _review_by_asset(inventory: Inventory):
    return {
        review.asset_id: review
        for review in review_inventory_evidence(
            inventory, source_type="cyclonedx_cbom"
        )
    }


def _finding_codes(inventory: Inventory, asset_id: str) -> list[str]:
    return [
        finding.code
        for finding in _review_by_asset(inventory)[asset_id].findings
    ]


def test_unenriched_cbom_inventory_preserves_existing_findings_exactly() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    inventory_reviews = review_inventory_evidence(
        inventory, source_type="cyclonedx_cbom"
    )
    direct_reviews = [
        review_asset_evidence(asset, source_type="cyclonedx_cbom")
        for asset in inventory.assets
    ]

    assert [review.findings for review in inventory_reviews] == [
        review.findings for review in direct_reviews
    ]


def test_asset_evidence_is_scoped_to_its_asset() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    baseline = _review_by_asset(inventory)
    enriched = _review_by_asset(
        _enrich(
            inventory,
            {"crypto-rsa-2048": {"retention_years": _assertion()}},
        )
    )

    assert "defaulted_retention_years" not in {
        finding.code for finding in enriched["crypto-rsa-2048"].findings
    }
    assert enriched["crypto-ml-kem-768"].findings == baseline[
        "crypto-ml-kem-768"
    ].findings


@pytest.mark.parametrize("state", ["declared", "verified"])
def test_explicit_zero_retention_with_assertion_is_not_defaulted(state: str) -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    enriched = _enrich(
        inventory,
        {"crypto-rsa-2048": {"retention_years": _assertion(state)}},
    )

    assert "defaulted_retention_years" not in _finding_codes(
        enriched, "crypto-rsa-2048"
    )


@pytest.mark.parametrize(
    ("field_name", "finding_code"),
    [
        ("criticality", "defaulted_criticality"),
        ("local_blast_radius", "defaulted_local_blast_radius"),
        ("migration_effort", "defaulted_migration_effort"),
    ],
)
def test_imported_medium_risk_value_with_assertion_is_not_defaulted(
    field_name: str,
    finding_code: str,
) -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    enriched = _enrich(
        inventory,
        {"crypto-rsa-2048": {field_name: _assertion()}},
    )

    assert finding_code not in _finding_codes(enriched, "crypto-rsa-2048")


@pytest.mark.parametrize("completeness", ["none", "known"])
def test_explicit_relationship_boundary_closes_unknown_completeness(
    completeness: str,
) -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    enriched = _enrich(
        inventory,
        {
            "crypto-rsa-2048": {
                "relationship_completeness": {
                    **_assertion(),
                    "value": completeness,
                }
            }
        },
    )

    assert "unknown_dependency_completeness" not in _finding_codes(
        enriched, "crypto-rsa-2048"
    )


@pytest.mark.parametrize(
    ("state", "provenance"),
    [
        ("declared", "third_party_asserted"),
        ("verified", "supplier_authoritative"),
    ],
)
def test_partial_relationships_remain_open_with_assertion_provenance(
    state: str,
    provenance: str,
) -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    enriched = _enrich(
        inventory,
        {
            "crypto-rsa-2048": {
                "relationship_completeness": {
                    **_assertion(state, provenance),
                    "value": "partial",
                }
            }
        },
    )

    finding = next(
        finding
        for finding in _review_by_asset(enriched)["crypto-rsa-2048"].findings
        if finding.code == "unknown_dependency_completeness"
    )
    assert finding.relationship_completeness == RelationshipCompleteness.partial
    assert finding.evidence_state == EvidenceState(state)
    assert finding.provenance == EvidenceProvenance(provenance)
    assert finding.requires_human_review is True


def test_algorithm_and_key_size_findings_are_unchanged_by_enrichment() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    rsa_asset = inventory.asset_by_id()["crypto-rsa-2048"]
    inventory = inventory.model_copy(
        update={
            "assets": [
                rsa_asset.model_copy(update={"algorithm": "unknown", "key_size_bits": None}),
                inventory.asset_by_id()["crypto-ml-kem-768"].model_copy(
                    update={"algorithm": "RSA-3072", "key_size_bits": None}
                ),
            ]
        }
    )
    enriched_reviews = _review_by_asset(
        _enrich(
            inventory,
            {
                "crypto-rsa-2048": {"retention_years": _assertion()},
                "crypto-ml-kem-768": {"retention_years": _assertion()},
            },
        )
    )
    baseline_reviews = _review_by_asset(inventory)

    assert {
        asset_id: [
            finding
            for finding in review.findings
            if finding.category == EvidenceCategory.cryptographic_context
        ]
        for asset_id, review in enriched_reviews.items()
    } == {
        asset_id: [
            finding
            for finding in review.findings
            if finding.category == EvidenceCategory.cryptographic_context
        ]
        for asset_id, review in baseline_reviews.items()
    }


def test_metadata_does_not_invent_values_or_infer_verified_state() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)
    enriched = _enrich(
        inventory,
        {
            "crypto-rsa-2048": {
                "data_class": _assertion(),
                "exposure": _assertion(),
            }
        },
    )
    findings = _review_by_asset(enriched)["crypto-rsa-2048"].findings
    finding_by_code = {finding.code: finding for finding in findings}

    assert "missing_data_class" in finding_by_code
    assert "missing_exposure" in finding_by_code
    assert finding_by_code["defaulted_criticality"].evidence_state == EvidenceState.defaulted
    assert finding_by_code["defaulted_criticality"].evidence_state != EvidenceState.verified
