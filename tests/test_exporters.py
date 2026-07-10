import csv
import json
from pathlib import Path

import pytest

from qstriage.cbom import import_cbom_inventory
from qstriage.exporters import export_score_results, export_simulation_results
from qstriage.models import (
    CryptographicAsset,
    Inventory,
    MigrationScenario,
    load_inventory,
)


def test_export_score_results_as_json(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "scores.json"

    written_path = export_score_results(inventory, output_path, "json")

    assert written_path == output_path
    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert len(data) == 5
    assert data[0]["asset_id"]
    assert data[0]["score_export_version"] == "0.2"
    assert "breakdown" in data[0]
    assert "priority_score" in data[0]
    assert "execution_state" in data[0]
    assert "action_type" in data[0]
    assert data[0]["recommended_action"] == data[0]["action_type"]
    assert not any(
        line.startswith("Recommended action:")
        for line in data[0]["explanation"]
    )


def test_export_score_results_as_csv(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "scores.csv"

    export_score_results(inventory, output_path, "csv")

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 5
    assert "asset_id" in rows[0]
    assert rows[0]["score_export_version"] == "0.2"
    assert "priority_score" in rows[0]
    assert "execution_state" in rows[0]
    assert "action_type" in rows[0]
    assert rows[0]["recommended_action"] == rows[0]["action_type"]
    assert "cryptographic_risk" in rows[0]
    assert "Recommended action:" not in rows[0]["explanation"]


def test_score_exports_project_canonical_actions_for_known_divergences(
    tmp_path: Path,
) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    json_path = tmp_path / "scores.json"
    csv_path = tmp_path / "scores.csv"

    export_score_results(inventory, json_path, "json")
    export_score_results(inventory, csv_path, "csv")

    json_rows = {
        row["asset_id"]: row
        for row in json.loads(json_path.read_text(encoding="utf-8"))
    }
    with csv_path.open("r", encoding="utf-8", newline="") as file:
        csv_rows = {row["asset_id"]: row for row in csv.DictReader(file)}

    for rows in (json_rows, csv_rows):
        assert rows["payments-api"]["action_type"] == "simulate_before_migration"
        assert rows["payments-api"]["recommended_action"] == (
            "simulate_before_migration"
        )
        assert rows["ot-gateway"]["action_type"] == "simulate_before_migration"
        assert rows["ot-gateway"]["recommended_action"] == (
            "simulate_before_migration"
        )


def test_score_export_projects_gated_cbom_decision(tmp_path: Path) -> None:
    inventory = import_cbom_inventory(Path("tests/fixtures/sample_cbom.json"))
    output_path = tmp_path / "cbom-scores.json"

    export_score_results(inventory, output_path, "json")

    rows = {
        row["asset_id"]: row
        for row in json.loads(output_path.read_text(encoding="utf-8"))
    }
    rsa = rows["crypto-rsa-2048"]

    assert rsa["execution_state"] == "gated"
    assert rsa["action_type"] == "migration_planning"
    assert rsa["verification_priority"] == "high"
    assert rsa["human_review_required"] is True
    assert "business_context" in rsa["verification_requirements"]
    assert "policy_resolution" in rsa["verification_requirements"]


def test_export_simulation_results_as_json(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "simulations.json"

    export_simulation_results(inventory, output_path, "json")

    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert len(data) == 5
    assert "estimated_handshake_bytes" in data[0]
    assert "warnings" in data[0]


def test_export_simulation_results_as_csv(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "simulations.csv"

    export_simulation_results(inventory, output_path, "csv")

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 5
    assert "fragmentation_risk" in rows[0]
    assert "middlebox_risk" in rows[0]


def test_export_rejects_unknown_format(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    with pytest.raises(ValueError):
        export_score_results(inventory, tmp_path / "scores.txt", "txt")


def _inventory_with_csv_text(value: str) -> Inventory:
    return Inventory(
        assets=[
            CryptographicAsset(
                id=value,
                name=value,
                environment="production",
                asset_type="service",
                protocol=value,
                algorithm="RSA",
                key_size_bits=2048,
                data_class="telemetry",
                retention_years=1,
                exposure="internal",
                criticality="medium",
                local_blast_radius="medium",
                migration_effort="medium",
            )
        ],
        dependencies=[],
        scenarios=[
            MigrationScenario(
                id=value,
                name=value,
                pqc_profile=value,
                mtu_bytes=1500,
            )
        ],
    )


@pytest.mark.parametrize(
    "formula_like_value",
    [
        "=1+1",
        "+1+1",
        "-1+1",
        "@SUM(1,1)",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
    ],
)
def test_csv_exports_neutralize_all_formula_reachable_text_fields(
    tmp_path: Path,
    formula_like_value: str,
) -> None:
    inventory = _inventory_with_csv_text(formula_like_value)
    score_path = tmp_path / "scores.csv"
    simulation_path = tmp_path / "simulations.csv"

    export_score_results(inventory, score_path, "csv")
    export_simulation_results(inventory, simulation_path, "csv")

    with score_path.open("r", encoding="utf-8", newline="") as file:
        score_row = next(csv.DictReader(file))

    with simulation_path.open("r", encoding="utf-8", newline="") as file:
        simulation_row = next(csv.DictReader(file))

    expected = "'" + formula_like_value

    assert score_row["asset_id"] == expected
    assert score_row["asset_name"] == expected
    assert score_row["explanation"].startswith(expected + " is rated ")

    assert simulation_row["asset_id"] == expected
    assert simulation_row["asset_name"] == expected
    assert simulation_row["protocol"] == expected
    assert simulation_row["scenario_id"] == expected
    assert simulation_row["scenario_name"] == expected
    assert simulation_row["pqc_profile"] == expected


def test_csv_exports_preserve_normal_text_and_numeric_fields(tmp_path: Path) -> None:
    inventory = _inventory_with_csv_text("normal-value")
    score_path = tmp_path / "scores.csv"
    simulation_path = tmp_path / "simulations.csv"

    export_score_results(inventory, score_path, "csv")
    export_simulation_results(inventory, simulation_path, "csv")

    with score_path.open("r", encoding="utf-8", newline="") as file:
        score_row = next(csv.DictReader(file))

    with simulation_path.open("r", encoding="utf-8", newline="") as file:
        simulation_row = next(csv.DictReader(file))

    assert score_row["asset_id"] == "normal-value"
    assert score_row["asset_name"] == "normal-value"
    assert score_row["explanation"].startswith("normal-value is rated ")
    float(score_row["priority_score"])

    assert simulation_row["asset_id"] == "normal-value"
    assert simulation_row["asset_name"] == "normal-value"
    assert simulation_row["protocol"] == "normal-value"
    assert simulation_row["scenario_id"] == "normal-value"
    assert simulation_row["scenario_name"] == "normal-value"
    assert simulation_row["pqc_profile"] == "normal-value"
    int(simulation_row["estimated_handshake_bytes"])


def test_json_exports_preserve_formula_like_text(tmp_path: Path) -> None:
    formula_like_value = "=1+1"
    inventory = _inventory_with_csv_text(formula_like_value)
    score_path = tmp_path / "scores.json"
    simulation_path = tmp_path / "simulations.json"

    export_score_results(inventory, score_path, "json")
    export_simulation_results(inventory, simulation_path, "json")

    score_row = json.loads(score_path.read_text(encoding="utf-8"))[0]
    simulation_row = json.loads(simulation_path.read_text(encoding="utf-8"))[0]

    assert score_row["asset_id"] == formula_like_value
    assert score_row["asset_name"] == formula_like_value
    assert score_row["explanation"][0].startswith(formula_like_value + " is rated ")

    assert simulation_row["asset_id"] == formula_like_value
    assert simulation_row["asset_name"] == formula_like_value
    assert simulation_row["protocol"] == formula_like_value
    assert simulation_row["scenario_id"] == formula_like_value
    assert simulation_row["scenario_name"] == formula_like_value
    assert simulation_row["pqc_profile"] == formula_like_value
