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


def test_closure_validate_and_apply_commands(tmp_path) -> None:
    inventory_path = _inventory_path(tmp_path)
    template = tmp_path / "patch.yaml"
    runner.invoke(app, ["closure", "template", str(inventory_path), "--output", str(template)])
    payload = yaml.safe_load(template.read_text(encoding="utf-8"))
    payload["assertions"] = [{
        "asset_id": "crypto-rsa-2048", "field": "retention_years", "value": 0,
        "state": "declared", "provenance": "user_declared",
    }]
    payload["relationship_assertions"] = []
    template.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    valid = runner.invoke(app, ["closure", "validate", str(inventory_path), str(template)])
    output = tmp_path / "enriched.yaml"
    applied = runner.invoke(app, ["closure", "apply", str(inventory_path), str(template), "--output", str(output)])
    collision = runner.invoke(app, ["closure", "apply", str(inventory_path), str(template), "--output", str(inventory_path)])

    assert valid.exit_code == 0
    assert "valid" in valid.output.lower()
    assert applied.exit_code == 0 and output.exists()
    assert collision.exit_code == 1
    assert "traceback" not in collision.output.lower()


def test_closure_compare_text_json_and_deterministic_output(tmp_path) -> None:
    before = _inventory_path(tmp_path)
    direct = runner.invoke(app, ["closure", "compare", str(before), str(before)])
    json_direct = runner.invoke(
        app, ["closure", "compare", str(before), str(before), "--format", "json"]
    )
    one = tmp_path / "one.json"
    two = tmp_path / "two.json"
    args = ["closure", "compare", str(before), str(before), "--format", "json"]
    first = runner.invoke(app, [*args, "--output", str(one)])
    second = runner.invoke(app, [*args, "--output", str(two)])

    assert direct.exit_code == 0
    assert "not production authorization" in direct.output.lower()
    assert json_direct.exit_code == 0
    assert json.loads(json_direct.output)["assets"]
    assert first.exit_code == second.exit_code == 0
    assert one.read_bytes() == two.read_bytes()
