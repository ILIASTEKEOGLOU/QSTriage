from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from qstriage.limits import MAX_CONFIG_FILE_BYTES, load_yaml_limited, read_text_limited


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_path: Path = Path("reports/qstriage_report.md")
    scores_path: Path = Path("reports/scores.json")
    simulations_path: Path = Path("reports/simulations.json")


class ExportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_format: str = Field(default="json", pattern="^(json|csv)$")


class QSTriageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outputs: OutputConfig = Field(default_factory=OutputConfig)
    exports: ExportConfig = Field(default_factory=ExportConfig)


def load_config(config_path: str | Path | None = None) -> QSTriageConfig:
    if config_path is None:
        return QSTriageConfig()

    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(path)

    text = read_text_limited(
        path,
        max_bytes=MAX_CONFIG_FILE_BYTES,
        label="Configuration file",
    )
    data = load_yaml_limited(text, label="Configuration YAML") or {}

    return QSTriageConfig.model_validate(data)
