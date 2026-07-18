import json
from pathlib import Path
import subprocess
import sys

import yaml

from qstriage.cbom import import_cbom_inventory
from qstriage.closure import (
    build_gap_manifest,
    build_inventory_comparison,
    comparison_json,
    inventory_hash,
    manifest_json,
)
from qstriage.enrichment import (
    apply_enrichment_patch,
    load_enrichment_patch,
    validate_enrichment_patch,
)
from qstriage.evidence import DecisionGrade, review_inventory_evidence
from qstriage.models import load_inventory


DEMO = Path("examples/build-week")
EXPECTED = DEMO / "expected"
REQUIRED_PATHS = [
    DEMO / "sample_cbom.json",
    DEMO / "imported.yaml",
    DEMO / "approved_enrichment.patch.yaml",
    EXPECTED / "enriched.yaml",
    EXPECTED / "gaps.json",
    EXPECTED / "comparison.json",
    Path("scripts/build_week_demo.py"),
]
GAP_CODES = [
    "missing_data_class",
    "defaulted_retention_years",
    "missing_exposure",
    "defaulted_criticality",
    "defaulted_local_blast_radius",
    "defaulted_migration_effort",
    "unknown_dependency_completeness",
]


def test_demo_cbom_and_generated_import_are_exact() -> None:
    assert all(path.is_file() for path in REQUIRED_PATHS)
    cbom = json.loads((DEMO / "sample_cbom.json").read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 1
    component = cbom["components"][0]
    algorithm = component["cryptoProperties"]["algorithmProperties"]
    assert component["bom-ref"] == "customer-api-rsa"
    assert component["name"] == "Customer API RSA Signing Key"
    assert algorithm == {
        "primitive": "signature",
        "algorithmFamily": "RSA",
        "parameterSetIdentifier": "RSA-2048",
    }
    assert cbom.get("dependencies", []) == []

    imported = import_cbom_inventory(DEMO / "sample_cbom.json")
    committed = load_inventory(DEMO / "imported.yaml")
    assert imported == committed
    assert yaml.safe_dump(
        imported.model_dump(mode="json"), sort_keys=False, allow_unicode=True
    ).encode() == (DEMO / "imported.yaml").read_bytes()


def test_demo_gaps_patch_and_generated_outputs_are_exact() -> None:
    imported = load_inventory(DEMO / "imported.yaml")
    manifest = build_gap_manifest(imported)
    assert [gap.code for gap in manifest.gaps] == GAP_CODES
    assert manifest_json(manifest).encode() == (EXPECTED / "gaps.json").read_bytes()

    patch = load_enrichment_patch(DEMO / "approved_enrichment.patch.yaml")
    assert patch.source_inventory_hash == inventory_hash(imported)
    regular = {
        assertion.field: (
            assertion.value,
            assertion.state.value,
            assertion.provenance.value,
            assertion.source_reference,
        )
        for assertion in patch.assertions
    }
    assert regular == {
        "data_class": ("customer_identity_claims", "declared", "user_declared", "architecture-review-AR-27"),
        "retention_years": (10, "verified", "supplier_authoritative", "records-policy-RP-14"),
        "exposure": ("public_internet", "declared", "user_declared", "architecture-review-AR-27"),
        "criticality": ("high", "declared", "user_declared", "service-owner-confirmation"),
        "local_blast_radius": ("high", "declared", "user_declared", "architecture-review-AR-27"),
        "migration_effort": ("medium", "declared", "user_declared", "migration-workshop-MW-03"),
    }
    relationship = patch.relationship_assertions[0]
    assert (
        relationship.completeness.value,
        relationship.state.value,
        relationship.provenance.value,
        relationship.source_reference,
    ) == ("none", "declared", "user_declared", "system-owner-confirmation")
    validate_enrichment_patch(imported, patch)

    enriched = apply_enrichment_patch(imported, patch)
    assert yaml.safe_dump(
        enriched.model_dump(mode="json"), sort_keys=False, allow_unicode=True
    ).encode() == (EXPECTED / "enriched.yaml").read_bytes()
    comparison = build_inventory_comparison(imported, enriched)
    assert comparison_json(comparison).encode() == (EXPECTED / "comparison.json").read_bytes()


def test_demo_verified_outcome_preserves_canonical_migration_gate() -> None:
    before = load_inventory(DEMO / "imported.yaml")
    after = load_inventory(EXPECTED / "enriched.yaml")
    result = build_inventory_comparison(before, after).assets[0]
    assert result.closed_finding_codes == GAP_CODES
    assert result.remaining_finding_codes == []
    assert result.introduced_finding_codes == []
    assert (result.evidence_score_before, result.evidence_score_after) == (0.0, 1.0)
    assert (result.confidence_cap_before, result.confidence_cap_after) == (0.5, 1.0)
    assert (result.action_before, result.action_after) == (
        "migration_planning", "migration_planning"
    )
    assert (result.execution_state_before, result.execution_state_after) == (
        "gated", "gated"
    )
    assert (result.verification_priority_before, result.verification_priority_after) == (
        "high", "high"
    )

    before_review = review_inventory_evidence(before)[0]
    after_review = review_inventory_evidence(after)[0]
    assert before_review.decision_grade == DecisionGrade.not_decision_grade
    assert after_review.decision_grade == DecisionGrade.decision_grade
    assert before_review.human_review_required is True
    assert after_review.human_review_required is False


def test_demo_runner_is_cross_platform_safe_and_deterministic(tmp_path: Path) -> None:
    script = Path("scripts/build_week_demo.py")
    source = script.read_text(encoding="utf-8")
    assert "shell=True" not in source
    committed_before = {
        path.relative_to(DEMO): path.read_bytes()
        for path in DEMO.rglob("*")
        if path.is_file()
    }
    outputs = []
    for name in ("run-one", "run-two"):
        output = tmp_path / name
        result = subprocess.run(
            [sys.executable, str(script), "--output-dir", str(output)],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Execution: gated -> gated" in result.stdout
        assert "not production authorization" in result.stdout
        assert sorted(path.name for path in output.iterdir()) == [
            "approved.patch.yaml", "comparison.json", "enriched.yaml",
            "gaps.json", "imported.yaml",
        ]
        outputs.append({path.name: path.read_bytes() for path in output.iterdir()})
        repeated = subprocess.run(
            [sys.executable, str(script), "--output-dir", str(output)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert repeated.returncode != 0
    assert outputs[0] == outputs[1]
    assert {
        path.relative_to(DEMO): path.read_bytes()
        for path in DEMO.rglob("*")
        if path.is_file()
    } == committed_before
