import pytest
from pydantic import ValidationError

from qstriage import models


def _asset() -> dict[str, object]:
    return {
        "id": "payments-api",
        "name": "Payments API",
        "environment": "production",
        "asset_type": "service",
        "protocol": "TLS 1.3",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "restricted",
        "retention_years": 7,
        "exposure": "internet-facing",
        "criticality": "critical",
        "local_blast_radius": "high",
        "migration_effort": "medium",
    }


def _inventory_data() -> dict[str, object]:
    return {"assets": [_asset()]}


def _declared_assertion() -> dict[str, str]:
    return {"state": "declared", "provenance": "user_declared"}


def test_inventory_without_evidence_metadata_remains_backward_compatible() -> None:
    inventory = models.Inventory.model_validate(_inventory_data())

    assert inventory.assets[0].id == "payments-api"
    assert inventory.evidence is None


def test_legacy_inventory_json_dump_omits_null_evidence() -> None:
    inventory = models.Inventory.model_validate(_inventory_data())

    assert "evidence" not in inventory.model_dump(mode="json")


def test_strict_evidence_metadata_accepts_valid_assertions() -> None:
    inventory = models.Inventory.model_validate(
        {
            **_inventory_data(),
            "evidence": {
                "version": "0.1",
                "source_inventory_hash": f"sha256:{'a' * 64}",
                "assets": {
                    "payments-api": {
                        "environment": _declared_assertion(),
                        "criticality": {
                            "state": "verified",
                            "provenance": "supplier_authoritative",
                            "source_reference": "supplier-attestation-42",
                            "rationale": "Signed supplier statement",
                        },
                        "relationship_completeness": {
                            **_declared_assertion(),
                            "value": "known",
                        },
                    }
                },
            },
        }
    )

    assert inventory.evidence is not None
    assert inventory.evidence.assets["payments-api"].criticality is not None


def test_unknown_evidence_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        models.FieldEvidenceAssertion.model_validate(
            {**_declared_assertion(), "confidence": "high"}
        )


def test_verified_assertions_require_source_reference() -> None:
    with pytest.raises(ValidationError):
        models.FieldEvidenceAssertion(
            state="verified", provenance="third_party_asserted"
        )


def test_declared_assertions_may_omit_source_reference() -> None:
    assertion = models.FieldEvidenceAssertion.model_validate(_declared_assertion())

    assert assertion.source_reference is None


def test_relationship_completeness_accepts_only_defined_values() -> None:
    for value in ("none", "partial", "known"):
        assertion = models.RelationshipEvidenceAssertion.model_validate(
            {**_declared_assertion(), "value": value}
        )
        assert assertion.value.value == value

    with pytest.raises(ValidationError):
        models.RelationshipEvidenceAssertion.model_validate(
            {**_declared_assertion(), "value": "complete"}
        )


def test_empty_asset_evidence_blocks_are_rejected() -> None:
    with pytest.raises(ValidationError):
        models.AssetEvidenceAssertions.model_validate({})


def test_evidence_rejects_unknown_assets_and_malformed_source_hashes() -> None:
    evidence = {
        "version": "0.1",
        "source_inventory_hash": f"sha256:{'a' * 64}",
        "assets": {"unknown-asset": {"exposure": _declared_assertion()}},
    }
    with pytest.raises(ValidationError):
        models.Inventory.model_validate({**_inventory_data(), "evidence": evidence})

    evidence["assets"] = {"payments-api": {"exposure": _declared_assertion()}}
    for invalid_hash in ("a" * 64, f"sha256:{'A' * 64}", "sha256:abc"):
        evidence["source_inventory_hash"] = invalid_hash
        with pytest.raises(ValidationError):
            models.Inventory.model_validate({**_inventory_data(), "evidence": evidence})
