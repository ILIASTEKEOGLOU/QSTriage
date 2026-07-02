from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from qstriage.graph import build_dependency_graph, render_text_graph
from qstriage.models import Inventory, load_inventory
from qstriage.scoring import ScoreResult, score_inventory
from qstriage.simulator import ImpactSimulationResult, simulate_inventory


def generate_markdown_report(inventory: Inventory) -> str:
    graph = build_dependency_graph(inventory)
    scores = score_inventory(inventory)
    simulations = simulate_inventory(inventory)

    simulation_by_asset = _simulation_by_asset(simulations)

    lines: list[str] = []

    lines.append("# QSTriage PQC Migration Assessment Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(UTC).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        "QSTriage analyzed the supplied cryptographic inventory, dependency graph, "
        "explainable priority scores, and hybrid PQC migration impact simulation."
    )
    lines.append("")
    lines.append(f"- Assets analyzed: {len(inventory.assets)}")
    lines.append(f"- Dependencies analyzed: {len(inventory.dependencies)}")
    if not inventory.dependencies:
        lines.append(
            "- Dependency scope warning: Graph-amplified blast radius is limited "
            "because no QSTriage business dependencies were declared. CBOM dependency "
            "relationships, if present, are not treated as QSTriage blast-radius dependencies."
        )
    lines.append(f"- Migration scenarios analyzed: {max(1, len(inventory.scenarios))}")
    lines.append(f"- Highest priority asset: {scores[0].asset_name} ({scores[0].priority_score})")
    lines.append("")
    lines.append("## Priority Backlog")
    lines.append("")
    lines.append("| Rank | Asset | Score | Band | Recommended Action |")
    lines.append("|---:|---|---:|---|---|")

    for index, score in enumerate(scores, start=1):
        lines.append(
            f"| {index} | {score.asset_name} | {score.priority_score:.2f} | "
            f"{score.priority_band} | {score.recommended_action} |"
        )

    lines.append("")
    lines.append("## Asset-Level Findings")
    lines.append("")

    for score in scores:
        lines.extend(_render_asset_finding(score, simulation_by_asset.get(score.asset_id, [])))

    lines.append("## Dependency Graph Views")
    lines.append("")

    for score in scores[:3]:
        lines.append(f"### {score.asset_name}")
        lines.append("")
        lines.append("```text")
        lines.append(render_text_graph(graph, score.asset_id))
        lines.append("```")
        lines.append("")

    lines.append("## Method Notes")
    lines.append("")
    lines.append(
        "This report is a local-first decision aid. It does not touch production systems, "
        "rotate certificates, change cryptographic settings, or perform automated rollout."
    )
    lines.append("")
    lines.append(
        "Scores are explainable planning signals, not absolute measurements. They combine "
        "cryptographic risk, data shelf-life, exposure, criticality, graph-amplified blast "
        "radius, deadline pressure, migration effort, and simulated PQC impact warnings."
    )
    lines.append("")

    return "\n".join(lines)


def write_markdown_report(inventory_path: str | Path, output_path: str | Path) -> Path:
    inventory = load_inventory(inventory_path)
    report = generate_markdown_report(inventory)

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")

    return destination


def _render_asset_finding(
    score: ScoreResult,
    simulations: list[ImpactSimulationResult],
) -> list[str]:
    lines: list[str] = []

    lines.append(f"### {score.asset_name}")
    lines.append("")
    lines.append(f"- Asset ID: `{score.asset_id}`")
    lines.append(f"- Priority score: **{score.priority_score:.2f}**")
    lines.append(f"- Priority band: **{score.priority_band}**")
    lines.append(f"- Confidence: {score.confidence}")
    lines.append(f"- Recommended action: {score.recommended_action}")
    lines.append("")
    lines.append("Score breakdown:")
    lines.append("")
    lines.append(f"- Cryptographic risk: {score.breakdown.cryptographic_risk:.2f}")
    lines.append(f"- Shelf-life risk: {score.breakdown.shelf_life_risk:.2f}")
    lines.append(f"- Exposure risk: {score.breakdown.exposure_risk:.2f}")
    lines.append(f"- Criticality score: {score.breakdown.criticality_score:.2f}")
    lines.append(f"- Graph-amplified blast radius: {score.breakdown.graph_blast_radius:.2f}")
    lines.append(f"- Deadline pressure: {score.breakdown.deadline_pressure:.2f}")
    lines.append(f"- Effort penalty: {score.breakdown.effort_penalty:.2f}")
    lines.append("")
    lines.append("Explanation:")
    lines.append("")

    for explanation_line in score.explanation:
        lines.append(f"- {explanation_line}")

    if simulations:
        lines.append("")
        lines.append("Simulation warnings:")
        lines.append("")

        for simulation in simulations:
            lines.append(
                f"- Scenario `{simulation.scenario_id}`: estimated handshake "
                f"{simulation.estimated_handshake_bytes} bytes, MTU ratio "
                f"{simulation.mtu_ratio:.2f}, fragmentation risk "
                f"{simulation.fragmentation_risk}, middlebox risk "
                f"{simulation.middlebox_risk}, compatibility risk "
                f"{simulation.compatibility_risk}."
            )

            for warning in simulation.warnings:
                lines.append(f"  - {warning}")

    lines.append("")

    return lines


def _simulation_by_asset(
    simulations: list[ImpactSimulationResult],
) -> dict[str, list[ImpactSimulationResult]]:
    grouped: dict[str, list[ImpactSimulationResult]] = defaultdict(list)

    for simulation in simulations:
        grouped[simulation.asset_id].append(simulation)

    return dict(grouped)
