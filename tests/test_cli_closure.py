import json

import yaml
from typer.testing import CliRunner

from qstriage.cbom import import_cbom_inventory
from qstriage.cli import app


runner = CliRunner()


def _inventory_path(tmp_path):
    path = tmp_path / "inventory.yaml"
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")
    path.write_text(
        yaml.safe_dump(inventory.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return path


def test_closure_inspect_json_and_output(tmp_path) -> None:
    inventory_path = _inventory_path(tmp_path)
    direct = runner.invoke(app, ["closure", "inspect", str(inventory_path), "--format", "json"])
    output = tmp_path / "gaps.json"
    written = runner.invoke(
        app,
        ["closure", "inspect", str(inventory_path), "--format", "json", "--output", str(output)],
    )

    assert direct.exit_code == 0
    assert json.loads(direct.output)["version"] == "0.1"
    assert written.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["gaps"]


def test_closure_template_writes_no_invented_values(tmp_path) -> None:
    inventory_path = _inventory_path(tmp_path)
    output = tmp_path / "enrichment.patch.yaml"
    result = runner.invoke(
        app, ["closure", "template", str(inventory_path), "--output", str(output)]
    )

    assert result.exit_code == 0
    payload = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert payload["patch_version"] == "0.1"
    assert all(item.get("value") is None for item in payload["assertions"])


def test_closure_commands_report_expected_errors_without_tracebacks(tmp_path) -> None:
    missing = tmp_path / "missing.yaml"
    result = runner.invoke(app, ["closure", "inspect", str(missing)])

    assert result.exit_code == 1
    assert "not found" in result.output.lower()
    assert "traceback" not in result.output.lower()
