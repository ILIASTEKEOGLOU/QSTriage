from pathlib import Path

from typer.testing import CliRunner

from qstriage.cli import app
from qstriage.models import load_inventory


runner = CliRunner()


def test_import_cbom_cli_writes_valid_qstriage_inventory(tmp_path: Path) -> None:
    output_path = tmp_path / "imported_inventory.yaml"

    result = runner.invoke(
        app,
        [
            "import",
            "cbom",
            "tests/fixtures/sample_cbom.json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "CBOM imported" in result.output
    assert "dependencies were not imported" in result.output

    inventory = load_inventory(output_path)

    assert len(inventory.assets) == 2
    assert inventory.dependencies == []
    assert inventory.assets[0].id == "crypto-rsa-2048"


def test_import_cbom_refuses_input_output_collision(tmp_path: Path) -> None:
    input_path = tmp_path / "cbom.json"
    original = Path("tests/fixtures/sample_cbom.json").read_text(encoding="utf-8")
    input_path.write_text(original, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "import",
            "cbom",
            str(input_path),
            "--output",
            str(input_path),
            "--overwrite",
        ],
    )

    assert result.exit_code == 1
    assert "protected input/config" in result.output
    assert input_path.read_text(encoding="utf-8") == original
