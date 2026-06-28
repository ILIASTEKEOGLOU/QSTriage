from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


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

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    return QSTriageConfig.model_validate(data)
