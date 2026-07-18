import json

import yaml

from qstriage.cbom import import_cbom_inventory
from qstriage.closure import (
    build_gap_manifest,
    build_patch_template,
    inventory_hash,
    manifest_json,
)


def test_gap_manifest_is_stable_targeted_and_canonical() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")
    manifest = build_gap_manifest(inventory)

    assert manifest.source_inventory_hash == inventory_hash(inventory)
    assert [(gap.asset_id, gap.field) for gap in manifest.gaps] == sorted(
        [(gap.asset_id, gap.field) for gap in manifest.gaps],
        key=lambda item: (
            item[0],
            [
                "data_class", "retention_years", "exposure", "criticality",
                "local_blast_radius", "migration_effort", "relationship_completeness",
            ].index(item[1]),
        ),
    )
    relationship = next(g for g in manifest.gaps if g.field == "relationship_completeness")
    assert relationship.allowed_values == ["none", "partial", "known"]
    assert "relationship" in relationship.question.lower()
    assert manifest_json(manifest) == manifest_json(build_gap_manifest(inventory))
    assert json.loads(manifest_json(manifest))["version"] == "0.1"


def test_patch_template_has_only_empty_unresolved_assertion_skeletons() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")
    template = yaml.safe_load(build_patch_template(inventory))

    assert template["patch_version"] == "0.1"
    assert template["source_inventory_hash"] == inventory_hash(inventory)
    assert template["assertions"]
    assert template["relationship_assertions"]
    assert all(item["value"] is None for item in template["assertions"])
    assert all(item["state"] is None for item in template["assertions"])
    assert all(item["completeness"] is None for item in template["relationship_assertions"])

