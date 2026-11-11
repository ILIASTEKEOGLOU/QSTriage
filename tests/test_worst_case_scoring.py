"""Unresolved context is scored at its worst case and never buries an asset.

Design D6 (design/context-resolution.md). Every surface that shows a score
names the fields that were scored at worst case, and the decision itself keeps
reading the declared values.
"""

from __future__ import annotations

import csv
import io
import itertools
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage.assessment import SCORE_BASIS_NOTE, assess_inventory, score_basis_label
from qstriage.cli import app
from qstriage.context import DATA_CLASS_LABELS, EXPOSURE_LABELS
from qstriage.exporters import export_score_results
from qstriage.models import (
    AssetEvidenceAssertions,
    CryptographicAsset,
    Dependency,
    EvidenceAssertionProvenance,
    EvidenceAssertionState,
    FieldEvidenceAssertion,
    Inventory,
    InventoryEvidenceMetadata,
    RiskLevel,
    load_inventory,
)
from qstriage.pdr import generate_pdr_document
from qstriage.report import generate_markdown_report
from qstriage.scoring import score_inventory


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "evidence-closure"
IMPORTED = DEMO / "imported.yaml"
ENRICHED = DEMO / "expected" / "enriched.yaml"

UNRESOLVED_TEXT = ["unknown", "", "REDACTED", "Confidential"]
LEVELS = [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical]

runner = CliRunner()


def _flat(output: str) -> str:
    return " ".join(output.split())


def _asset(asset_id: str = "asset-1", **overrides: object) -> CryptographicAsset:
    values: dict[str, object] = {
        "id": asset_id,
        "name": f"Asset {asset_id}",
        "environment": "production",
        "asset_type": "service",
        "protocol": "tls",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "internal",
        "retention_years": 5,
        "exposure": "internal",
        "criticality": RiskLevel.medium,
        "local_blast_radius": RiskLevel.medium,
        "migration_effort": RiskLevel.medium,
    }
    values.update(overrides)
    return CryptographicAsset(**values)


def _declared() -> FieldEvidenceAssertion:
    return FieldEvidenceAssertion(
        state=EvidenceAssertionState.declared,
        provenance=EvidenceAssertionProvenance.user_declared,
        source_reference="owner-confirmation",
    )


def _score(asset: CryptographicAsset, evidence: AssetEvidenceAssertions | None = None) -> float:
    metadata = None
    if evidence is not None:
        metadata = InventoryEvidenceMetadata(
            version="0.1",
            source_inventory_hash="sha256:" + "0" * 64,
            assets={asset.id: evidence},
        )
    [result] = score_inventory(Inventory(assets=[asset], evidence=metadata))
    return result.priority_score


# Monotonicity: an unresolved value never scores below any accepted value.


@pytest.mark.parametrize(
    ("unresolved", "label"), list(itertools.product(UNRESOLVED_TEXT, DATA_CLASS_LABELS))
)
def test_unresolved_data_class_never_scores_below_an_accepted_label(
    unresolved: str, label: str
) -> None:
    assert _score(_asset(data_class=unresolved or " ")) >= _score(_asset(data_class=label))


@pytest.mark.parametrize(
    ("unresolved", "label"), list(itertools.product(UNRESOLVED_TEXT, EXPOSURE_LABELS))
)
def test_unresolved_exposure_never_scores_below_an_accepted_label(
    unresolved: str, label: str
) -> None:
    assert _score(_asset(exposure=unresolved or " ")) >= _score(_asset(exposure=label))


@pytest.mark.parametrize("years", [0, 1, 2, 3, 5, 7, 10, 25])
def test_unconfirmed_zero_retention_never_scores_below_a_confirmed_value(years: int) -> None:
    confirmed = _score(
        _asset(retention_years=years), AssetEvidenceAssertions(retention_years=_declared())
    )
    assert _score(_asset(retention_years=0)) >= confirmed


@pytest.mark.parametrize(
    ("field", "level"),
    list(itertools.product(["criticality", "local_blast_radius", "migration_effort"], LEVELS)),
)
def test_defaulted_cbom_level_never_scores_below_a_declared_level(
    field: str, level: RiskLevel
) -> None:
    imported = _asset(asset_type="cbom_cryptographic_asset")
    declared = _asset(asset_type="cbom_cryptographic_asset", **{field: level})
    evidence = AssetEvidenceAssertions(**{field: _declared()})

    assert _score(imported) >= _score(declared, evidence)


def test_unresolved_downstream_criticality_never_lowers_an_upstream_score() -> None:
    def inventory(downstream_type: str) -> Inventory:
        return Inventory(
            assets=[
                _asset("upstream"),
                # medium is the CBOM import default: declared for a service,
                # defaulted on import for a CBOM asset.
                _asset("downstream", asset_type=downstream_type, criticality=RiskLevel.medium),
            ],
            dependencies=[
                Dependency(
                    id="dep-1",
                    source="upstream",
                    target="downstream",
                    direction="outbound",
                    dependency_type="api_call",
                    protocol="HTTPS/TLS1.3",
                    weight=0.9,
                    criticality=RiskLevel.high,
                )
            ],
        )

    declared = {r.asset_id: r.priority_score for r in score_inventory(inventory("service"))}
    defaulted = {
        r.asset_id: r.priority_score
        for r in score_inventory(inventory("cbom_cryptographic_asset"))
    }

    assert defaulted["upstream"] >= declared["upstream"]
    assert defaulted["upstream"] > declared["upstream"]


# What is recorded and shown.


def test_demo_asset_moves_from_worst_case_to_confirmed() -> None:
    [before] = score_inventory(load_inventory(IMPORTED))
    [after] = score_inventory(load_inventory(ENRICHED))

    assert (before.priority_score, before.score_basis) == (100.0, "worst_case")
    assert [item.field for item in before.scoring_assumptions] == [
        "data_class", "retention_years", "exposure",
        "criticality", "local_blast_radius", "migration_effort",
    ]
    assert (after.priority_score, after.score_basis) == (93.0, "confirmed")
    assert after.scoring_assumptions == ()


def test_assumptions_name_value_problem_and_scored_value() -> None:
    [result] = score_inventory(load_inventory(IMPORTED))
    rows = [
        (item.field, item.inventory_value, item.problem, item.scored_as)
        for item in result.scoring_assumptions
    ]

    assert rows == [
        ("data_class", "unknown", "missing", "sensitive"),
        ("retention_years", "0", "defaulted on import", "10 years"),
        ("exposure", "unknown", "missing", "public"),
        ("criticality", "medium", "defaulted on import", "critical"),
        ("local_blast_radius", "medium", "defaulted on import", "critical"),
        ("migration_effort", "medium", "defaulted on import", "low"),
    ]
    assert result.explanation[-1] == (
        "Unresolved migration_effort (defaulted on import) is scored as low (worst case)."
    )


def test_problem_words_cover_every_unresolved_state() -> None:
    cases = {
        "unknown": "missing",
        "REDACTED": "withheld",
        "Confidential": "not an accepted label",
    }
    for value, problem in cases.items():
        [result] = score_inventory(Inventory(assets=[_asset(data_class=value)]))
        assert result.scoring_assumptions[0].problem == problem
    [result] = score_inventory(Inventory(assets=[_asset(retention_years=0)]))
    assert result.scoring_assumptions[0].problem == "zero retention not confirmed"


def test_decision_fields_keep_reading_declared_values() -> None:
    [assessment] = assess_inventory(load_inventory(IMPORTED))

    assert assessment.score.score_basis == "worst_case"
    assert assessment.decision.execution_state.value == "gated"
    assert assessment.decision.action_type.value == "migration_planning"
    assert assessment.decision.human_review_required is True
    assert assessment.asset.exposure == "unknown"


def test_every_surface_lists_the_same_worst_case_fields(tmp_path: Path) -> None:
    inventory = load_inventory(IMPORTED)
    expected = [
        "data_class", "retention_years", "exposure",
        "criticality", "local_blast_radius", "migration_effort",
    ]

    document = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )
    [record] = document["ranked"]
    assert record["score_basis"] == "worst_case"
    assert [item["field"] for item in record["scoring_assumptions"]] == expected
    assert record["scoring_assumptions"][0] == {
        "field": "data_class", "inventory_value": "unknown",
        "problem": "missing", "scored_as": "sensitive",
    }

    rows = list(
        csv.DictReader(
            io.StringIO(
                export_score_results(inventory, tmp_path / "s.csv", "csv").read_text(encoding="utf-8")
            )
        )
    )
    assert rows[0]["score_basis"] == "worst_case"
    assert rows[0]["scoring_assumptions"].startswith(
        "data_class: unknown (missing) -> sensitive | retention_years: 0 (defaulted on import) -> 10 years"
    )

    [pdr_record] = generate_pdr_document(inventory).records
    assert [
        line for line in pdr_record.assumptions_made if line.endswith("(worst case).")
    ] == [
        f"Unresolved {item['field']} ({item['problem']}) is scored as {item['scored_as']} (worst case)."
        for item in record["scoring_assumptions"]
    ]

    report = generate_markdown_report(inventory)
    assert "| worst case (6 fields) | gated |" in report
    assert "- Ranked assets scored at worst case because context is missing: 1 of 1" in report
    assert SCORE_BASIS_NOTE in report
    assert "| exposure | `unknown` | missing | public |" in report

    result = runner.invoke(app, ["score", str(IMPORTED)])
    output = _flat(result.output)
    assert result.exit_code == 0
    assert "basis=worst case (6 fields)" in output
    assert "Worst case fields for Customer API RSA Signing Key: " + ", ".join(expected) in output
    assert _flat(SCORE_BASIS_NOTE) in output


def test_confirmed_inventory_shows_no_worst_case_note(tmp_path: Path) -> None:
    inventory = load_inventory(ENRICHED)

    result = runner.invoke(app, ["score", str(ENRICHED)])
    report = generate_markdown_report(inventory)
    document = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )

    assert "basis=confirmed" in result.output
    assert "Score basis:" not in result.output
    assert "| confirmed | justified |" in report
    assert SCORE_BASIS_NOTE not in report
    assert "Scoring assumptions" not in report
    assert document["ranked"][0]["score_basis"] == "confirmed"
    assert document["ranked"][0]["scoring_assumptions"] == []


def test_score_basis_label_counts_fields() -> None:
    [one] = score_inventory(Inventory(assets=[_asset(exposure="unknown")]))
    [six] = score_inventory(load_inventory(IMPORTED))

    assert score_basis_label(one) == "worst case for 1 field: exposure"
    assert score_basis_label(one, short=True) == "worst case (1 field)"
    assert score_basis_label(six, short=True) == "worst case (6 fields)"


def test_bundled_sample_inventory_is_fully_confirmed() -> None:
    results = score_inventory(load_inventory(ROOT / "examples" / "sample_inventory.yaml"))

    assert {result.score_basis for result in results} == {"confirmed"}
