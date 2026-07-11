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

    assert document["pdr_version"] == "0.2"
    assert document["input_snapshot"]["source_type"] == "qstriage_inventory"
    assert document["input_snapshot"]["source_hash"].startswith("sha256:")
    assert document["document_hash"].startswith("sha256:")
    assert len(document["records"]) == 5

    decision = document["records"][0]["decision"]
    assert set(decision) == {
        "risk_attention_score",
        "risk_attention_band",
        "execution_state",
        "action_type",
        "verification_priority",
        "verification_requirements",
        "confidence_score",
        "human_review_required",
        "reason_codes",
    }


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


def test_pdr_generate_refuses_input_output_collision(tmp_path: Path) -> None:
    input_path = tmp_path / "inventory.yaml"
    original = Path("examples/sample_inventory.yaml").read_text(encoding="utf-8")
    input_path.write_text(original, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "pdr",
            "generate",
            str(input_path),
            "--output",
            str(input_path),
            "--overwrite",
        ],
    )

    assert result.exit_code == 1
    assert "protected input/config" in result.output
    assert input_path.read_text(encoding="utf-8") == original
