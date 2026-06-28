from __future__ import annotations

import csv
import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any

from qstriage.models import Inventory
from qstriage.scoring import ScoreResult, score_inventory
from qstriage.simulator import ImpactSimulationResult, simulate_inventory


class ExportFormat(str, Enum):
    json = "json"
    csv = "csv"


def export_score_results(
    inventory: Inventory,
    output_path: str | Path,
    export_format: ExportFormat | str,
) -> Path:
    results = score_inventory(inventory)
    destination = Path(output_path)
    normalized_format = _normalize_export_format(export_format)

    if normalized_format == ExportFormat.json:
        _write_json(destination, [_to_json_ready(result) for result in results])
    elif normalized_format == ExportFormat.csv:
        _write_csv(destination, _score_result_rows(results))
    else:
        raise ValueError(f"Unsupported export format: {export_format}")

    return destination


def export_simulation_results(
    inventory: Inventory,
    output_path: str | Path,
    export_format: ExportFormat | str,
) -> Path:
    results = simulate_inventory(inventory)
    destination = Path(output_path)
    normalized_format = _normalize_export_format(export_format)

    if normalized_format == ExportFormat.json:
        _write_json(destination, [_to_json_ready(result) for result in results])
    elif normalized_format == ExportFormat.csv:
        _write_csv(destination, _simulation_result_rows(results))
    else:
        raise ValueError(f"Unsupported export format: {export_format}")

    return destination


def _normalize_export_format(export_format: ExportFormat | str) -> ExportFormat:
    if isinstance(export_format, ExportFormat):
        return export_format

    try:
        return ExportFormat(export_format.lower())
    except ValueError as error:
        raise ValueError(f"Unsupported export format: {export_format}") from error


def _to_json_ready(value: Any) -> dict[str, Any]:
    return asdict(value)


def _score_result_rows(results: list[ScoreResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
        rows.append(
            {
                "asset_id": result.asset_id,
                "asset_name": result.asset_name,
                "priority_score": result.priority_score,
                "priority_band": result.priority_band,
                "recommended_action": result.recommended_action,
                "confidence": result.confidence,
                "cryptographic_risk": result.breakdown.cryptographic_risk,
                "shelf_life_risk": result.breakdown.shelf_life_risk,
                "exposure_risk": result.breakdown.exposure_risk,
                "criticality_score": result.breakdown.criticality_score,
                "graph_blast_radius": result.breakdown.graph_blast_radius,
                "deadline_pressure": result.breakdown.deadline_pressure,
                "effort_penalty": result.breakdown.effort_penalty,
                "total": result.breakdown.total,
                "explanation": " | ".join(result.explanation),
            }
        )

    return rows


def _simulation_result_rows(results: list[ImpactSimulationResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for result in results:
        rows.append(
            {
                "asset_id": result.asset_id,
                "asset_name": result.asset_name,
                "scenario_id": result.scenario_id,
                "scenario_name": result.scenario_name,
                "pqc_profile": result.pqc_profile,
                "protocol": result.protocol,
                "estimated_handshake_bytes": result.estimated_handshake_bytes,
                "mtu_bytes": result.mtu_bytes,
                "mtu_ratio": result.mtu_ratio,
                "fragmentation_risk": result.fragmentation_risk,
                "middlebox_risk": result.middlebox_risk,
                "compatibility_risk": result.compatibility_risk,
                "crypto_dependency_count": result.crypto_dependency_count,
                "warnings": " | ".join(result.warnings),
            }
        )

    return rows


def _write_json(destination: Path, data: list[dict[str, Any]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_csv(destination: Path, rows: list[dict[str, Any]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        destination.write_text("", encoding="utf-8")
        return

    with destination.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
