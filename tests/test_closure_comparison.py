from qstriage.cbom import import_cbom_inventory
from qstriage.closure import build_inventory_comparison, comparison_json
from qstriage.enrichment import EnrichmentPatch, apply_enrichment_patch


def _inventory():
    return import_cbom_inventory("tests/fixtures/sample_cbom.json")


def _enriched(completeness: str = "known"):
    inventory = _inventory()
    from qstriage.closure import inventory_hash

    patch = EnrichmentPatch.model_validate({
        "patch_version": "0.1",
        "source_inventory_hash": inventory_hash(inventory),
        "assertions": [
            {"asset_id": "crypto-rsa-2048", "field": "retention_years", "value": 0, "state": "declared", "provenance": "user_declared"},
            {"asset_id": "crypto-rsa-2048", "field": "criticality", "value": "high", "state": "verified", "provenance": "supplier_authoritative", "source_reference": "supplier://1"},
        ],
        "relationship_assertions": [{
            "asset_id": "crypto-rsa-2048", "completeness": completeness,
            "state": "declared", "provenance": "user_declared",
        }],
    })
    return inventory, apply_enrichment_patch(inventory, patch)


def test_identical_inventories_have_no_false_changes_and_stable_json() -> None:
    inventory = _inventory()
    comparison = build_inventory_comparison(inventory, inventory)

    assert comparison.before_inventory_hash == comparison.after_inventory_hash
    assert all(not item.closed_finding_codes for item in comparison.assets)
    assert all(not item.introduced_finding_codes for item in comparison.assets)
    assert comparison_json(comparison) == comparison_json(
        build_inventory_comparison(inventory, inventory)
    )


def test_expected_findings_close_after_enrichment_without_affecting_other_assets() -> None:
    before, after = _enriched()
    comparison = build_inventory_comparison(before, after)
    by_id = {item.asset_id: item for item in comparison.assets}

    rsa = by_id["crypto-rsa-2048"]
    assert "defaulted_retention_years" in rsa.closed_finding_codes
    assert "defaulted_criticality" in rsa.closed_finding_codes
    assert "unknown_dependency_completeness" in rsa.closed_finding_codes
    other = by_id["crypto-ml-kem-768"]
    assert other.closed_finding_codes == []
    assert other.introduced_finding_codes == []
    assert other.evidence_score_before == other.evidence_score_after
    assert other.action_before == other.action_after


def test_partial_relationship_completeness_remains_unresolved() -> None:
    before, after = _enriched("partial")
    rsa = next(
        item
        for item in build_inventory_comparison(before, after).assets
        if item.asset_id == "crypto-rsa-2048"
    )

    assert "unknown_dependency_completeness" in rsa.remaining_finding_codes
    assert "unknown_dependency_completeness" not in rsa.closed_finding_codes

