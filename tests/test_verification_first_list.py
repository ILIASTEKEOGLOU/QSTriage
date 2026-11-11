"""Assets whose cryptography is not identified are listed apart and never ranked.

The partition comes from the canonical execution state
(`verification_first`). The score CLI, the Markdown report, and both score
export formats must show the same partition, and an unidentified asset must
never appear in a ranking, whatever its priority score.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage.assessment import (
    VERIFY_FIRST_ACTION,
    assess_inventory,
    partition_assessments,
    unranked_reason,
)
from qstriage.cli import app
from qstriage.exporters import export_score_results
from qstriage.models import Inventory, load_inventory
from qstriage.report import generate_markdown_report
from qstriage.standards import classify_algorithm


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_inventory.yaml"
UNIDENTIFIED = ["WEIRD-THING-9000", "ML-KEM", "ML-DSA", "X25519-ML-KEM-768"]

runner = CliRunner()


def _flat(output: str) -> str:
    """Join lines so assertions do not depend on the console width."""
    return " ".join(output.split())


def _inventory(algorithms: dict[str, str]) -> Inventory:
    inventory = load_inventory(SAMPLE)
    for asset in inventory.assets:
        if asset.id in algorithms:
            asset.algorithm = algorithms[asset.id]
    return inventory


def _write(inventory: Inventory, path: Path) -> Path:
    path.write_text(
        json.dumps(inventory.model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    return path


def _ranked_ids_in_report(report: str) -> list[str]:
    backlog = report.split("## Priority Backlog", 1)[1].split("\n## ", 1)[0]
    return [
        line.split("|")[2].strip()
        for line in backlog.splitlines()
        if line.startswith("| ") and line[2].isdigit()
    ]


def _surfaces(inventory: Inventory, tmp_path: Path) -> dict[str, tuple[list[str], list[str]]]:
    """Return (verification_first ids, ranked ids) as each surface shows them."""

    names = {asset.id: asset.name for asset in inventory.assets}
    by_name = {name: asset_id for asset_id, name in names.items()}

    json_path = export_score_results(inventory, tmp_path / "scores.json", "json", overwrite=True)
    document = json.loads(json_path.read_text(encoding="utf-8"))

    csv_path = export_score_results(inventory, tmp_path / "scores.csv", "csv", overwrite=True)
    rows = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8"))))

    report = generate_markdown_report(inventory)
    verify_section = report.split("## Verify First", 1)[1].split("\n## ", 1)[0]
    report_first = [
        asset_id
        for asset_id in names
        if f"`{asset_id}`" in verify_section
    ]
    report_first.sort(key=lambda asset_id: verify_section.index(f"`{asset_id}`"))

    return {
        "json": (
            [record["asset_id"] for record in document["verification_first"]],
            [record["asset_id"] for record in document["ranked"]],
        ),
        "csv": (
            [row["asset_id"] for row in rows if row["list"] == "verification_first"],
            [row["asset_id"] for row in rows if row["list"] == "ranked"],
        ),
        "report": (
            report_first,
            [by_name[name] for name in _ranked_ids_in_report(report)],
        ),
    }


def test_partition_follows_the_canonical_execution_state() -> None:
    inventory = _inventory({"public-api-gateway": "WEIRD-THING-9000"})
    assessments = assess_inventory(inventory)
    partition = partition_assessments(assessments)

    assert [item.asset.id for item in partition.verification_first] == ["public-api-gateway"]
    assert "public-api-gateway" not in [item.asset.id for item in partition.ranked]
    assert len(partition.ranked) == len(assessments) - 1
    assert all(
        item.decision.execution_state.value == "verification_first"
        for item in partition.verification_first
    )
    # The ranked list keeps the existing deterministic order.
    assert partition.ranked == [
        item for item in assessments if item.asset.id != "public-api-gateway"
    ]


@pytest.mark.parametrize("algorithm", UNIDENTIFIED)
def test_unidentified_asset_is_never_ranked_on_any_surface(
    tmp_path: Path, algorithm: str
) -> None:
    # customer-db has the highest score in the sample inventory.
    inventory = _inventory({"customer-db": algorithm})
    surfaces = _surfaces(inventory, tmp_path)

    for name, (first, ranked) in surfaces.items():
        assert first == ["customer-db"], name
        assert "customer-db" not in ranked, name
        assert len(ranked) == len(inventory.assets) - 1, name


def test_every_surface_shows_the_same_partition(tmp_path: Path) -> None:
    inventory = _inventory(
        {"public-api-gateway": "WEIRD-THING-9000", "ot-gateway": "ML-KEM"}
    )
    surfaces = _surfaces(inventory, tmp_path)

    assert surfaces["json"] == surfaces["csv"] == surfaces["report"]


def test_ranks_are_contiguous_and_explicit(tmp_path: Path) -> None:
    inventory = _inventory({"public-api-gateway": "WEIRD-THING-9000"})
    document = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )
    rows = list(
        csv.DictReader(
            io.StringIO(
                export_score_results(inventory, tmp_path / "s.csv", "csv").read_text(encoding="utf-8")
            )
        )
    )

    assert [record["rank"] for record in document["ranked"]] == [1, 2, 3, 4]
    assert "rank" not in document["verification_first"][0]
    assert [row["rank"] for row in rows] == ["", "1", "2", "3", "4"]


def test_verification_first_records_state_why_they_are_unranked(tmp_path: Path) -> None:
    inventory = _inventory(
        {"public-api-gateway": "WEIRD-THING-9000", "ot-gateway": "ML-KEM"}
    )
    document = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )
    reasons = {
        record["asset_id"]: record["unranked_reason"]
        for record in document["verification_first"]
    }

    assert reasons == {
        "public-api-gateway": "The algorithm identifier is not in the QSTriage algorithm registry.",
        "ot-gateway": (
            "The ML-KEM family is recognized, but the parameter set is missing or not "
            "supported, so the exact algorithm is not identified."
        ),
    }
    assert all("unranked_reason" not in record for record in document["ranked"])


def test_verification_first_order_is_risk_attention_then_asset_id() -> None:
    inventory = _inventory({asset_id: "WEIRD" for asset_id in ("payments-api", "auth-service", "ot-gateway")})
    partition = partition_assessments(assess_inventory(inventory))
    keys = [
        (-item.decision.risk_attention_score, item.asset.id)
        for item in partition.verification_first
    ]

    assert keys == sorted(keys)


def test_score_cli_prints_verify_first_table_before_the_backlog(tmp_path: Path) -> None:
    path = _write(_inventory({"customer-db": "WEIRD-THING-9000"}), tmp_path / "inventory.json")
    result = runner.invoke(app, ["score", str(path)])
    output = _flat(result.output)

    assert result.exit_code == 0
    assert output.index("Verify First: Cryptography Not Identified (not ranked)") < output.index(
        "QSTriage Canonical Decision Backlog"
    )
    assert "WEIRD-THING-9000" in output
    assert "The algorithm identifier is not in the QSTriage algorithm registry." in output
    assert f"What to do: {VERIFY_FIRST_ACTION}" in output
    backlog = output.split("QSTriage Canonical Decision Backlog", 1)[1]
    assert "Customer Database" not in backlog


def test_score_cli_without_unidentified_assets_has_no_verify_first_table() -> None:
    result = runner.invoke(app, ["score", str(SAMPLE)])

    assert result.exit_code == 0
    assert "Verify First" not in result.output


def test_all_unidentified_inventory_explains_the_empty_ranking(tmp_path: Path) -> None:
    inventory = _inventory({asset.id: "WEIRD" for asset in load_inventory(SAMPLE).assets})
    path = _write(inventory, tmp_path / "inventory.json")

    result = runner.invoke(app, ["score", str(path)])
    report = generate_markdown_report(inventory)
    document = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )

    assert result.exit_code == 0
    assert "No asset can be ranked yet" in _flat(result.output)
    assert "QSTriage Canonical Decision Backlog" not in result.output
    assert "No asset can be ranked yet" in report
    assert "Highest risk-attention ranked asset" not in report
    assert document["ranked"] == []
    assert len(document["verification_first"]) == len(inventory.assets)


def test_report_states_when_no_asset_needs_verification_first() -> None:
    report = generate_markdown_report(load_inventory(SAMPLE))

    assert "## Verify First: Cryptography Not Identified" in report
    assert "None. Every asset has an identified algorithm and is ranked below." in report
    assert report.index("## Verify First") < report.index("## Priority Backlog")
    assert "- Assets to verify first (cryptography not identified, not ranked): 0" in report


def test_score_exports_are_deterministic(tmp_path: Path) -> None:
    inventory = _inventory({"public-api-gateway": "WEIRD-THING-9000"})

    for export_format in ("json", "csv"):
        first = export_score_results(inventory, tmp_path / f"a.{export_format}", export_format)
        second = export_score_results(inventory, tmp_path / f"b.{export_format}", export_format)
        assert first.read_bytes() == second.read_bytes()


def test_unranked_reason_names_the_recognized_family() -> None:
    assert unranked_reason(classify_algorithm("ML-DSA")).startswith(
        "The ML-DSA family is recognized"
    )
