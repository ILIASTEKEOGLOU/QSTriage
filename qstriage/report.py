from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from qstriage.assessment import AssetAssessment, assess_inventory
from qstriage.graph import build_dependency_graph, render_text_graph
from qstriage.file_output import write_private_text
from qstriage.models import Inventory, load_inventory
from qstriage.presentation import (
    markdown_code_block,
    markdown_code_span,
    markdown_inline,
    markdown_table_cell,
)
from qstriage.review import InventoryContextReview, review_decision_context
from qstriage.simulator import ImpactSimulationResult, simulate_inventory


def generate_markdown_report(inventory: Inventory) -> str:
    graph = build_dependency_graph(inventory)
    assessments = assess_inventory(inventory)
    simulations = simulate_inventory(inventory)
    context_review = review_decision_context(inventory)

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
    highest = assessments[0]
    lines.append(
        "- Highest risk-attention asset: "
        f"{markdown_inline(highest.asset.name)} "
        f"({highest.decision.risk_attention_score})"
    )
    lines.append("")
    lines.append("## Priority Backlog")
    lines.append("")
    lines.append(
        "| Rank | Asset | Risk Attention | Band | Execution | Canonical Action | "
        "Verification | Human Review |"
    )
    lines.append("|---:|---|---:|---|---|---|---|---|")

    for index, assessment in enumerate(assessments, start=1):
        decision = assessment.decision
        lines.append(
            f"| {index} | {markdown_table_cell(assessment.asset.name)} | "
            f"{decision.risk_attention_score:.2f} | "
            f"{decision.risk_attention_band} | {decision.execution_state.value} | "
            f"{decision.action_type.value} | "
            f"{decision.verification_priority.value} | "
            f"{'yes' if decision.human_review_required else 'no'} |"
        )

    lines.append("")
    lines.extend(_render_decision_context_review(context_review))

    lines.append("## Asset-Level Findings")
    lines.append("")

    for assessment in assessments:
        lines.extend(
            _render_asset_finding(
                assessment,
                simulation_by_asset.get(assessment.asset.id, []),
            )
        )

    lines.append("## Dependency Graph Views")
    lines.append("")

    for assessment in assessments[:3]:
        lines.append(f"### {markdown_inline(assessment.asset.name)}")
        lines.append("")
        lines.append(
            markdown_code_block(
                render_text_graph(graph, assessment.asset.id),
                language="text",
            )
        )
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


def write_markdown_report(
    inventory_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool = False,
    protected_paths: tuple[str | Path | None, ...] = (),
) -> Path:
    inventory = load_inventory(inventory_path)
    report = generate_markdown_report(inventory)

    destination = Path(output_path)
    return write_private_text(
        destination,
        report,
        overwrite=overwrite,
        protected_paths=(inventory_path, *protected_paths),
    )


def _render_decision_context_review(review: InventoryContextReview) -> list[str]:
    lines: list[str] = []

    lines.append("## Decision Context Review")
    lines.append("")
    lines.append(f"- Status: {review.status}")
    lines.append(f"- Incomplete assets: {review.incomplete_asset_count}")
    lines.append(f"- Issues: {review.issue_count}")
    lines.append("")

    if review.status == "complete":
        lines.append(
            "No decision-context issues were detected by the current review rules."
        )
        lines.append("")
        return lines

    if review.inventory_issues:
        lines.append("Inventory-level issues:")
        lines.append("")

        for issue in review.inventory_issues:
            lines.append(f"- {issue}")

        lines.append("")

    for asset_review in review.asset_reviews:
        if asset_review.status == "complete":
            continue

        lines.append(f"### {markdown_inline(asset_review.asset_name)}")
        lines.append("")
        lines.append(f"- Asset ID: {markdown_code_span(asset_review.asset_id)}")
        lines.append(f"- Status: {asset_review.status}")
        lines.append("- Missing or defaulted context:")

        for issue in asset_review.issues:
            lines.append(
                f"  - {markdown_code_span(issue.field)}: "
                f"{issue.message}"
            )

        lines.append(
            "- Recommended action: "
            f"{asset_review.recommended_action}"
        )
        lines.append("")

    return lines


def _render_asset_finding(
    assessment: AssetAssessment,
    simulations: list[ImpactSimulationResult],
) -> list[str]:
    lines: list[str] = []
    asset = assessment.asset
    score = assessment.score
    decision = assessment.decision
    classification = assessment.classification

    requirements = ", ".join(
        requirement.value for requirement in decision.verification_requirements
    ) or "none"
    reason_codes = ", ".join(decision.reason_codes) or "none"

    lines.append(f"### {markdown_inline(asset.name)}")
    lines.append("")
    lines.append(f"- Asset ID: {markdown_code_span(asset.id)}")
    lines.append(f"- Risk attention score: **{decision.risk_attention_score:.2f}**")
    lines.append(f"- Risk attention band: **{decision.risk_attention_band}**")
    lines.append(f"- Execution state: **{decision.execution_state.value}**")
    lines.append(f"- Canonical action: **{decision.action_type.value}**")
    lines.append(f"- Verification priority: **{decision.verification_priority.value}**")
    lines.append(f"- Verification requirements: {requirements}")
    lines.append(f"- Decision confidence: {decision.decision_confidence:.2f}")
    lines.append(
        "- Human review required: "
        + ("yes" if decision.human_review_required else "no")
    )
    lines.append(f"- Reason codes: {reason_codes}")
    lines.append("")

    lines.append("Algorithm classification:")
    lines.append("")
    lines.append(
        f"- Input algorithm: {markdown_code_span(classification.input_algorithm)}"
    )
    lines.append(f"- Algorithm family: {classification.algorithm_family}")
    lines.append(
        f"- Identifier resolution: {classification.identifier_resolution}"
    )
    lines.append(f"- Primitive: {classification.primitive}")
    lines.append(f"- Quantum status: {classification.quantum_status}")
    lines.append(f"- Standard status: {classification.standard_status}")
    lines.append(
        f"- Registry action: {classification.recommended_action}"
    )
    lines.append(f"- Registry rationale: {classification.rationale}")
    lines.append(
        "- Registry sources: "
        f"{', '.join(classification.source_ids)}"
    )
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
    lines.append("Score explanation:")
    lines.append("")

    for explanation_line in score.explanation:
        if explanation_line.startswith("Recommended action:"):
            continue
        lines.append(f"- {markdown_inline(explanation_line)}")

    if simulations:
        lines.append("")
        lines.append("Simulation warnings:")
        lines.append("")

        for simulation in simulations:
            lines.append(
                f"- Scenario {markdown_code_span(simulation.scenario_id)}: "
                f"estimated handshake {simulation.estimated_handshake_bytes} bytes, "
                f"MTU ratio {simulation.mtu_ratio:.2f}, fragmentation risk "
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
