import csv
import json
from pathlib import Path

import pytest

from qstriage.exporters import export_score_results, export_simulation_results
from qstriage.models import load_inventory


def test_export_score_results_as_json(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "scores.json"

    written_path = export_score_results(inventory, output_path, "json")

    assert written_path == output_path
    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert len(data) == 5
    assert data[0]["asset_id"]
    assert "breakdown" in data[0]
    assert "priority_score" in data[0]


def test_export_score_results_as_csv(tmp_path: Path) -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))
    output_path = tmp_path / "scores.csv"

    export_score_results(inventory, output_path, "csv")

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 5
    assert "asset_id" in rows[0]
    assert "priority_score" in rows[0]
    assert "cryptographic_risk" in rows[0]


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
