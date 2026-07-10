from __future__ import annotations

import csv
import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any

from qstriage.assessment import AssetAssessment, assess_inventory
from qstriage.models import Inventory
from qstriage.scoring import ScoreResult
from qstriage.simulator import ImpactSimulationResult, simulate_inventory


class ExportFormat(str, Enum):
    json = "json"
    csv = "csv"


SCORE_EXPORT_VERSION = "0.2"


def export_score_results(
    inventory: Inventory,
    output_path: str | Path,
    export_format: ExportFormat | str,
) -> Path:
    assessments = assess_inventory(inventory)
    destination = Path(output_path)
    normalized_format = _normalize_export_format(export_format)

    if normalized_format == ExportFormat.json:
        _write_json(destination, _score_result_records(assessments))
    elif normalized_format == ExportFormat.csv:
        _write_csv(destination, _score_result_rows(assessments))
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


def _score_result_records(
    assessments: list[AssetAssessment],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for assessment in assessments:
        score = assessment.score
        decision = assessment.decision
        records.append(
            {
                "asset_id": score.asset_id,
                "asset_name": score.asset_name,
                "score_export_version": SCORE_EXPORT_VERSION,
                "priority_score": score.priority_score,
                "priority_band": score.priority_band,
                # Compatibility alias retained for existing consumers. The value now
                # comes from the canonical decision rather than score heuristics.
                "recommended_action": decision.action_type.value,
                "confidence": score.confidence,
                "execution_state": decision.execution_state.value,
                "action_type": decision.action_type.value,
                "verification_priority": decision.verification_priority.value,
                "verification_requirements": [
                    requirement.value
                    for requirement in decision.verification_requirements
                ],
                "decision_confidence": decision.decision_confidence,
                "human_review_required": decision.human_review_required,
                "reason_codes": list(decision.reason_codes),
                "breakdown": _to_json_ready(score.breakdown),
                "explanation": _decision_safe_explanation(score),
            }
        )

    return records


def _score_result_rows(
    assessments: list[AssetAssessment],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for assessment in assessments:
        score = assessment.score
        decision = assessment.decision
        rows.append(
            {
                "asset_id": score.asset_id,
                "asset_name": score.asset_name,
                "score_export_version": SCORE_EXPORT_VERSION,
                "priority_score": score.priority_score,
                "priority_band": score.priority_band,
                "recommended_action": decision.action_type.value,
                "confidence": score.confidence,
                "execution_state": decision.execution_state.value,
                "action_type": decision.action_type.value,
                "verification_priority": decision.verification_priority.value,
                "verification_requirements": " | ".join(
                    requirement.value
                    for requirement in decision.verification_requirements
                ),
                "decision_confidence": decision.decision_confidence,
                "human_review_required": decision.human_review_required,
                "reason_codes": " | ".join(decision.reason_codes),
                "cryptographic_risk": score.breakdown.cryptographic_risk,
                "shelf_life_risk": score.breakdown.shelf_life_risk,
                "exposure_risk": score.breakdown.exposure_risk,
                "criticality_score": score.breakdown.criticality_score,
                "graph_blast_radius": score.breakdown.graph_blast_radius,
                "deadline_pressure": score.breakdown.deadline_pressure,
                "effort_penalty": score.breakdown.effort_penalty,
                "total": score.breakdown.total,
                "explanation": " | ".join(_decision_safe_explanation(score)),
            }
        )

    return rows


def _decision_safe_explanation(score: ScoreResult) -> list[str]:
    return [
        line
        for line in score.explanation
        if not line.startswith("Recommended action:")
    ]


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

    safe_rows = [
        {key: _csv_safe_cell(value) for key, value in row.items()}
        for row in rows
    ]

    with destination.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(safe_rows)


def _csv_safe_cell(value: Any) -> Any:
    if not isinstance(value, str):
        return value

    if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value

    return value
