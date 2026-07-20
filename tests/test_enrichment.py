from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from qstriage.cbom import import_cbom_inventory
from qstriage.closure import inventory_hash
from qstriage.enrichment import (
    EnrichmentPatch,
    apply_enrichment_patch,
    validate_enrichment_patch,
    write_enriched_inventory,
)
from qstriage.file_output import UnsafeOutputError
from qstriage.models import Dependency


def _inventory():
    return import_cbom_inventory("tests/fixtures/sample_cbom.json")


def _patch(inventory, **updates):
    payload = {
        "patch_version": "0.1",
        "source_inventory_hash": inventory_hash(inventory),
        "assertions": [{
            "asset_id": "crypto-rsa-2048", "field": "retention_years", "value": 0,
            "state": "declared", "provenance": "user_declared",
        }],
        "relationship_assertions": [],
    }
    payload.update(updates)
    return payload


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"source_inventory_hash": f"sha256:{'b' * 64}"}, "source hash"),
        ({"assertions": [{"asset_id": "missing", "field": "exposure", "value": "internal", "state": "declared", "provenance": "user_declared"}]}, "unknown asset"),
        ({"assertions": [{"asset_id": "crypto-rsa-2048", "field": "retention_years", "value": 1, "state": "declared", "provenance": "user_declared"}] * 2}, "duplicate"),
    ],
)
def test_inventory_bound_patch_validation_rejects_invalid_scope(change, message) -> None:
    inventory = _inventory()
    patch = EnrichmentPatch.model_validate(_patch(inventory, **change))
    with pytest.raises(ValueError, match=message):
        validate_enrichment_patch(inventory, patch)


@pytest.mark.parametrize("field", ["algorithm", "protocol", "key_size_bits"])
def test_patch_rejects_forbidden_fields(field: str) -> None:
    inventory = _inventory()
    payload = _patch(inventory)
    payload["assertions"][0]["field"] = field
    with pytest.raises(ValidationError):
        EnrichmentPatch.model_validate(payload)


@pytest.mark.parametrize("value", ["urgent", 1, True])
def test_patch_rejects_invalid_risk_enum_without_unsafe_coercion(value) -> None:
    inventory = _inventory()
    payload = _patch(inventory)
    payload["assertions"][0].update(field="criticality", value=value)
    patch = EnrichmentPatch.model_validate(payload)
    with pytest.raises(ValueError, match="criticality"):
        validate_enrichment_patch(inventory, patch)


def test_patch_rejects_negative_retention_and_verified_without_source() -> None:
    inventory = _inventory()
    negative = EnrichmentPatch.model_validate(_patch(inventory))
    negative.assertions[0].value = -1
    with pytest.raises(ValueError, match="retention_years"):
        validate_enrichment_patch(inventory, negative)

    payload = _patch(inventory)
    payload["assertions"][0]["state"] = "verified"
    with pytest.raises(ValidationError, match="source_reference"):
        EnrichmentPatch.model_validate(payload)


def test_patch_rejects_unknown_keys() -> None:
    inventory = _inventory()
    with pytest.raises(ValidationError):
        EnrichmentPatch.model_validate({**_patch(inventory), "approve": True})


def test_relationship_none_rejects_existing_dependency() -> None:
    inventory = _inventory()
    inventory.dependencies = [Dependency(
        id="dep", source="crypto-rsa-2048", target="crypto-ml-kem-768",
        direction="outbound", dependency_type="api_call", protocol="https",
        weight=1, criticality="medium",
    )]
    payload = _patch(inventory, assertions=[], relationship_assertions=[{
        "asset_id": "crypto-rsa-2048", "completeness": "none",
        "state": "declared", "provenance": "user_declared",
    }])
    patch = EnrichmentPatch.model_validate(payload)
    with pytest.raises(ValueError, match="dependencies"):
        validate_enrichment_patch(inventory, patch)


def test_duplicate_relationship_assertions_are_rejected() -> None:
    inventory = _inventory()
    relationship = {
        "asset_id": "crypto-rsa-2048", "completeness": "known",
        "state": "declared", "provenance": "user_declared",
    }
    patch = EnrichmentPatch.model_validate(
        _patch(
            inventory,
            assertions=[],
            relationship_assertions=[relationship, relationship],
        )
    )
    with pytest.raises(ValueError, match="duplicate relationship"):
        validate_enrichment_patch(inventory, patch)


def test_apply_is_immutable_idempotent_and_deterministic(tmp_path: Path) -> None:
    inventory = _inventory()
    original = inventory.model_dump(mode="json")
    patch = EnrichmentPatch.model_validate(_patch(inventory))

    first = apply_enrichment_patch(inventory, patch)
    second = apply_enrichment_patch(inventory, patch)
    assert inventory.model_dump(mode="json") == original
    assert first == second
    assert list(first.evidence.assets) == ["crypto-rsa-2048"]

    one = tmp_path / "one.yaml"
    two = tmp_path / "two.yaml"
    write_enriched_inventory(inventory, patch, one)
    write_enriched_inventory(inventory, patch, two)
    assert one.read_bytes() == two.read_bytes()


def test_apply_refuses_input_collision_and_existing_output(tmp_path: Path) -> None:
    inventory = _inventory()
    patch = EnrichmentPatch.model_validate(_patch(inventory))
    source = tmp_path / "source.yaml"
    source.write_text(yaml.safe_dump(inventory.model_dump(mode="json")), encoding="utf-8")

    with pytest.raises(UnsafeOutputError):
        write_enriched_inventory(inventory, patch, source, input_path=source)
    output = tmp_path / "existing.yaml"
    output.write_text("existing", encoding="utf-8")
    with pytest.raises(UnsafeOutputError):
        write_enriched_inventory(inventory, patch, output, input_path=source)
