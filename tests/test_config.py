from pathlib import Path

import pytest
from pydantic import ValidationError

from qstriage.config import QSTriageConfig, load_config


def test_default_config_has_safe_output_paths() -> None:
    config = QSTriageConfig()

    assert config.outputs.report_path == Path("reports/qstriage_report.md")
    assert config.outputs.scores_path == Path("reports/scores.json")
    assert config.outputs.simulations_path == Path("reports/simulations.json")
    assert config.exports.default_format == "json"


def test_load_config_reads_yaml_file(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    config_path.write_text(
        "outputs:\n"
        "  report_path: custom/report.md\n"
        "  scores_path: custom/scores.csv\n"
        "  simulations_path: custom/simulations.json\n"
        "exports:\n"
        "  default_format: csv\n",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.outputs.report_path == Path("custom/report.md")
    assert config.outputs.scores_path == Path("custom/scores.csv")
    assert config.outputs.simulations_path == Path("custom/simulations.json")
    assert config.exports.default_format == "csv"


def test_load_config_uses_defaults_for_missing_sections(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    config_path.write_text("exports:\n  default_format: csv\n", encoding="utf-8")

    config = load_config(config_path)

    assert config.outputs.report_path == Path("reports/qstriage_report.md")
    assert config.exports.default_format == "csv"


def test_load_config_rejects_unknown_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    config_path.write_text("unknown: true\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        load_config(config_path)


def test_load_config_rejects_unknown_export_format(tmp_path: Path) -> None:
    config_path = tmp_path / "qstriage.yaml"
    config_path.write_text("exports:\n  default_format: txt\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        load_config(config_path)


def test_load_config_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yaml")
