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


def test_review_context_command_prints_decision_context_findings(tmp_path: Path) -> None:
    cbom_path = tmp_path / "sample_cbom.json"
    inventory_path = tmp_path / "imported_inventory.yaml"

    cbom_path.write_text(
        Path("tests/fixtures/sample_cbom.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    import_result = runner.invoke(
        app,
        [
            "import",
            "cbom",
            str(cbom_path),
            "--output",
            str(inventory_path),
        ],
    )

    assert import_result.exit_code == 0

    result = runner.invoke(app, ["review", "context", str(inventory_path)])

    assert result.exit_code == 0
    assert "Decision context status: incomplete" in result.output
    assert "Incomplete assets: 2" in result.output
    assert "Issues:" in result.output
    assert "Inventory-level issues:" in result.output
    assert "No QSTriage business/security dependencies declared" in result.output
    assert "crypto-rsa-2048" in result.output
    assert "data_class is unknown" in result.output
    assert "retention_years is 0" in result.output
    assert "exposure is unknown" in result.output
    assert "criticality is the CBOM import default medium" in result.output
    assert "Add business context before treating this asset score as" in result.output
    assert "decision-grade" in result.output


def test_review_context_command_prints_complete_status_for_sample_inventory() -> None:
    result = runner.invoke(app, ["review", "context", "examples/sample_inventory.yaml"])

    assert result.exit_code == 0
    assert "Decision context status: complete" in result.output
    assert "Incomplete assets: 0" in result.output
    assert "Issues: 0" in result.output
    assert "Missing or defaulted context" not in result.output


def test_review_evidence_command_prints_inventory_evidence_table() -> None:
    result = runner.invoke(
        app,
        ["review", "evidence", "examples/sample_inventory.yaml"],
    )

    assert result.exit_code == 0, result.output
    assert "QSTriage Evidence Quality Review" in result.output
    assert "public-api-gateway" in result.output
    assert "decision_grade" in result.output


def test_review_evidence_command_supports_cbom_input() -> None:
    result = runner.invoke(
        app,
        [
            "review",
            "evidence",
            "tests/fixtures/sample_cbom.json",
            "--input-format",
            "cbom",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "QSTriage Evidence Quality Review" in result.output
    assert "crypto-rsa-2048" in result.output
    assert "not_decision_grade" in result.output
    assert "missing_data_class" in result.output


def test_review_evidence_command_rejects_unknown_input_format() -> None:
    result = runner.invoke(
        app,
        [
            "review",
            "evidence",
            "examples/sample_inventory.yaml",
            "--input-format",
            "unknown",
        ],
    )

    assert result.exit_code == 1
    assert "Unsupported evidence review input format" in result.output
