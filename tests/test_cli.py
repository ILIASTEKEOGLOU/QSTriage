from pathlib import Path

from typer.testing import CliRunner

from qstriage.cli import app


runner = CliRunner()


def test_validate_command_accepts_sample_inventory() -> None:
    result = runner.invoke(app, ["validate", "examples/sample_inventory.yaml"])

    assert result.exit_code == 0
    assert "Inventory is valid" in result.output
    assert "Assets: 5" in result.output


def test_score_command_prints_priority_backlog() -> None:
    result = runner.invoke(app, ["score", "examples/sample_inventory.yaml"])

    assert result.exit_code == 0
    assert "QSTriage Priority Backlog" in result.output
    assert "Public API Gateway" in result.output


def test_graph_command_prints_text_dependency_graph() -> None:
    result = runner.invoke(
        app,
        ["graph", "examples/sample_inventory.yaml", "public-api-gateway"],
    )

    assert result.exit_code == 0
    assert "[public-api-gateway]" in result.output
    assert "auth" in result.output


def test_report_command_writes_markdown_report(tmp_path: Path) -> None:
    output_path = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "report",
            "examples/sample_inventory.yaml",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Report written" in result.output
    assert output_path.exists()
    assert "QSTriage PQC Migration Assessment Report" in output_path.read_text(
        encoding="utf-8"
    )


def test_validate_command_prints_friendly_error_for_malformed_yaml(tmp_path: Path) -> None:
    inventory_path = tmp_path / "broken.yaml"
    inventory_path.write_text("assets:\n  - id: api\n    name: [broken\n", encoding="utf-8")

    result = runner.invoke(app, ["validate", str(inventory_path)])

    assert result.exit_code == 1
    assert "Inventory YAML is malformed" in result.output
    assert "line" in result.output
    assert "column" in result.output


def test_validate_command_prints_friendly_error_for_invalid_inventory(tmp_path: Path) -> None:
    inventory_path = tmp_path / "invalid.yaml"
    inventory_path.write_text(
        "assets:\n"
        "  - id: api\n"
        "    name: API\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate", str(inventory_path)])

    assert result.exit_code == 1
    assert "Inventory validation failed" in result.output
    assert "Missing required field" in result.output
    assert "assets[0].environment" in result.output


def test_score_command_prints_friendly_error_for_invalid_inventory(tmp_path: Path) -> None:
    inventory_path = tmp_path / "invalid.yaml"
    inventory_path.write_text(
        "assets:\n"
        "  - id: api\n"
        "    name: API\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["score", str(inventory_path)])

    assert result.exit_code == 1
    assert "Inventory validation failed" in result.output
    assert "Missing required field" in result.output


def test_report_command_prints_friendly_error_for_malformed_yaml(tmp_path: Path) -> None:
    inventory_path = tmp_path / "broken.yaml"
    output_path = tmp_path / "report.md"
    inventory_path.write_text("assets:\n  - id: api\n    name: [broken\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["report", str(inventory_path), "--output", str(output_path)],
    )

    assert result.exit_code == 1
    assert "Inventory YAML is malformed" in result.output
    assert not output_path.exists()


def test_export_scores_command_writes_json(tmp_path: Path) -> None:
    output_path = tmp_path / "scores.json"

    result = runner.invoke(
        app,
        [
            "export",
            "scores",
            "examples/sample_inventory.yaml",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Scores exported" in result.output
    assert output_path.exists()


def test_export_scores_command_writes_csv(tmp_path: Path) -> None:
    output_path = tmp_path / "scores.csv"

    result = runner.invoke(
        app,
        [
            "export",
            "scores",
            "examples/sample_inventory.yaml",
            "--format",
            "csv",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Scores exported" in result.output
    assert output_path.exists()


def test_export_simulations_command_writes_json(tmp_path: Path) -> None:
    output_path = tmp_path / "simulations.json"

    result = runner.invoke(
        app,
        [
            "export",
            "simulations",
            "examples/sample_inventory.yaml",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Simulations exported" in result.output
    assert output_path.exists()


def test_report_command_uses_configured_output_path(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    output_path = tmp_path / "configured-report.md"
    config_path.write_text(
        f"outputs:\n  report_path: {output_path.as_posix()}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "examples/sample_inventory.yaml",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "Report written" in result.output


def test_report_command_explicit_output_overrides_config(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    configured_output = tmp_path / "configured-report.md"
    explicit_output = tmp_path / "explicit-report.md"
    config_path.write_text(
        f"outputs:\n  report_path: {configured_output.as_posix()}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            "examples/sample_inventory.yaml",
            "--config",
            str(config_path),
            "--output",
            str(explicit_output),
        ],
    )

    assert result.exit_code == 0
    assert explicit_output.exists()
    assert not configured_output.exists()


def test_export_scores_command_uses_config_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    output_path = tmp_path / "configured-scores.csv"
    config_path.write_text(
        "exports:\n"
        "  default_format: csv\n"
        "outputs:\n"
        f"  scores_path: {output_path.as_posix()}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "export",
            "scores",
            "examples/sample_inventory.yaml",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8").startswith("asset_id,asset_name")


def test_export_simulations_command_uses_config_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    output_path = tmp_path / "configured-simulations.csv"
    config_path.write_text(
        "exports:\n"
        "  default_format: csv\n"
        "outputs:\n"
        f"  simulations_path: {output_path.as_posix()}\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "export",
            "simulations",
            "examples/sample_inventory.yaml",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8").startswith("asset_id,asset_name")
