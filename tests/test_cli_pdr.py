import json
from pathlib import Path

from typer.testing import CliRunner

from qstriage.cli import app


runner = CliRunner()


def test_pdr_generate_inventory_writes_json_document(tmp_path: Path) -> None:
    output = tmp_path / "pdr.json"

    result = runner.invoke(
        app,
        [
            "pdr",
            "generate",
            "examples/sample_inventory.yaml",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "PDR written" in result.output

    document = json.loads(output.read_text(encoding="utf-8"))

    assert document["pdr_version"] == "0.1"
    assert document["input_snapshot"]["source_type"] == "qstriage_inventory"
    assert document["input_snapshot"]["source_hash"].startswith("sha256:")
    assert document["document_hash"].startswith("sha256:")
    assert len(document["records"]) == 5


def test_pdr_generate_cbom_writes_cyclonedx_pdr_document(tmp_path: Path) -> None:
    output = tmp_path / "cbom-pdr.json"

    result = runner.invoke(
        app,
        [
            "pdr",
            "generate",
            "tests/fixtures/sample_cbom.json",
            "--input-format",
            "cbom",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output

    document = json.loads(output.read_text(encoding="utf-8"))

    assert document["input_snapshot"]["source_type"] == "cyclonedx_cbom"
    assert document["input_snapshot"]["source_version"] == "1.6"
    assert len(document["records"]) == 2
    assert document["records"][0]["record_integrity"]["record_hash"].startswith("sha256:")


def test_pdr_generate_rejects_unknown_input_format(tmp_path: Path) -> None:
    output = tmp_path / "bad.json"

    result = runner.invoke(
        app,
        [
            "pdr",
            "generate",
            "examples/sample_inventory.yaml",
            "--input-format",
            "unknown",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1
    assert "Unsupported PDR input format" in result.output
    assert not output.exists()
