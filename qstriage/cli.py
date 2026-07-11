import json
from pathlib import Path

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from qstriage import __version__
from qstriage.assessment import assess_inventory
from qstriage.cbom import import_cbom_inventory, write_imported_inventory
from qstriage.config import QSTriageConfig, load_config
from qstriage.errors import format_inventory_load_error
from qstriage.evidence import review_inventory_evidence
from qstriage.exporters import ExportFormat, export_score_results, export_simulation_results
from qstriage.file_output import UnsafeOutputError, write_private_text
from qstriage.graph import build_dependency_graph, render_text_graph
from qstriage.limits import ResourceLimitError
from qstriage.models import load_inventory
from qstriage.pdr import generate_pdr_document, load_pdr_input
from qstriage.presentation import sanitize_terminal_text
from qstriage.policy import get_policy_pack, list_policy_packs
from qstriage.report import generate_markdown_report
from qstriage.review import review_decision_context

app = typer.Typer(
    help="QSTriage — Cryptographic Policy & Justification Engine",
    no_args_is_help=True,
)

import_app = typer.Typer(
    help="Import external cryptographic inventory formats.",
    no_args_is_help=True,
)

export_app = typer.Typer(
    help="Export QSTriage results as structured JSON or CSV.",
    no_args_is_help=True,
)

review_app = typer.Typer(
    help="Review whether an inventory has enough business context for decision-grade scoring.",
    no_args_is_help=True,
)

pdr_app = typer.Typer(
    help="Generate PQC Decision Records.",
    no_args_is_help=True,
)

policy_app = typer.Typer(
    help="Inspect built-in cryptographic policy packs.",
    no_args_is_help=True,
)

console = Console()


def _safe_text(value: object, *, style: str | None = None) -> Text:
    return Text(sanitize_terminal_text(value), style=style)


def _safe_print(value: object, *, style: str | None = None) -> None:
    console.print(_safe_text(value, style=style))


def _load_inventory_or_exit(inventory_path: Path):
    try:
        return load_inventory(inventory_path)
    except (FileNotFoundError, yaml.YAMLError, ValidationError, ValueError) as error:
        _safe_print(format_inventory_load_error(error, path=inventory_path), style="red")
        raise typer.Exit(code=1) from error


def _load_config_or_exit(config_path: Path | None) -> QSTriageConfig:
    try:
        return load_config(config_path)
    except (FileNotFoundError, yaml.YAMLError, ValidationError, ValueError) as error:
        _safe_print(format_inventory_load_error(error, path=config_path), style="red")
        raise typer.Exit(code=1) from error


def _write_cbom_import_or_exit(
    input_path: Path,
    output_path: Path,
    *,
    overwrite: bool,
) -> Path:
    try:
        return write_imported_inventory(input_path, output_path, overwrite=overwrite)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as error:
        _safe_print(f"CBOM import failed: {error}", style="red")
        raise typer.Exit(code=1) from error


def _load_inventory_for_review_or_exit(
    input_path: Path,
    input_format: str,
):
    try:
        normalized_format = input_format.strip().lower()

        if normalized_format == "inventory":
            return load_inventory(input_path), "qstriage_inventory"
        if normalized_format == "cbom":
            return import_cbom_inventory(input_path), "cyclonedx_cbom"

        raise ValueError("Unsupported evidence review input format. Expected 'inventory' or 'cbom'.")
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        _safe_print(f"Evidence review failed: {error}", style="red")
        raise typer.Exit(code=1) from error


def _write_pdr_document_or_exit(
    input_path: Path,
    output_path: Path,
    input_format: str,
    *,
    overwrite: bool,
) -> Path:
    try:
        captured_input = load_pdr_input(input_path, input_format)

        document = generate_pdr_document(
            captured_input.inventory,
            input_snapshot=captured_input.input_snapshot,
        )

        return write_private_text(
            output_path,
            json.dumps(
                document.model_dump(mode="json"),
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            overwrite=overwrite,
            protected_paths=(input_path,),
        )
    except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError, ValueError) as error:
        _safe_print(f"PDR generation failed: {error}", style="red")
        raise typer.Exit(code=1) from error



@policy_app.command("list")
def list_policy_pack_command() -> None:
    """List available built-in policy packs."""
    table = Table(title="QSTriage Policy Packs")
    table.add_column("Policy Pack ID")
    table.add_column("Version")
    table.add_column("Title")
    table.add_column("Rules", justify="right")

    for policy_pack in list_policy_packs():
        table.add_row(
            _safe_text(policy_pack.policy_pack_id),
            _safe_text(policy_pack.version),
            _safe_text(policy_pack.title),
            str(len(policy_pack.rules)),
        )

    console.print(table)


@policy_app.command("show")
def show_policy_pack_command(
    policy_pack_id: str = typer.Argument(
        ...,
        help="Built-in policy pack id to inspect.",
    ),
) -> None:
    """Show a built-in policy pack as deterministic JSON."""
    try:
        policy_pack = get_policy_pack(policy_pack_id)
    except ValueError as error:
        _safe_print(f"Policy lookup failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    payload = policy_pack.model_dump(mode="json")
    payload["policy_pack_hash"] = policy_pack.policy_pack_hash()

    typer.echo(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        )
    )


@app.callback()
def main() -> None:
    """QSTriage command line interface."""
    pass


@app.command()
def version() -> None:
    """Show QSTriage version."""
    typer.echo(f"QSTriage {__version__}")


@app.command("validate")
def validate_inventory(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Validate an inventory file."""
    inventory = _load_inventory_or_exit(inventory_path)

    console.print("[green]Inventory is valid.[/green]")
    console.print(f"Assets: {len(inventory.assets)}")
    console.print(f"Dependencies: {len(inventory.dependencies)}")
    console.print(f"Scenarios: {len(inventory.scenarios)}")


@app.command("score")
def score(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Print the explainable migration priority backlog."""
    inventory = _load_inventory_or_exit(inventory_path)
    try:
        assessments = assess_inventory(inventory)
    except ResourceLimitError as error:
        _safe_print(f"Scoring failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    table = Table(title="QSTriage Canonical Decision Backlog", box=None)
    table.add_column("Rank", justify="right")
    table.add_column("Asset", max_width=18, overflow="fold")
    table.add_column("Risk Attention", justify="right")
    table.add_column("Canonical Decision", overflow="fold")

    for index, assessment in enumerate(assessments, start=1):
        decision = assessment.decision
        table.add_row(
            str(index),
            _safe_text(assessment.asset.name),
            f"{decision.risk_attention_score:.2f} / "
            f"{decision.risk_attention_band}",
            "\n".join(
                [
                    f"execution={decision.execution_state.value}",
                    f"action={decision.action_type.value}",
                    f"verification={decision.verification_priority.value}",
                    "human_review="
                    + ("yes" if decision.human_review_required else "no"),
                ]
            ),
        )

    console.print(table)


@app.command("graph")
def graph(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    asset_id: str = typer.Argument(
        ...,
        help="Root asset id for the dependency graph view.",
    ),
) -> None:
    """Render a text dependency graph from a selected root asset."""
    inventory = _load_inventory_or_exit(inventory_path)
    dependency_graph = build_dependency_graph(inventory)

    try:
        rendered = render_text_graph(dependency_graph, asset_id)
    except (KeyError, ResourceLimitError) as error:
        _safe_print(f"Graph rendering failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    console.print(rendered, markup=False)


@app.command("report")
def report(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path where the Markdown report will be written.",
    ),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional QSTriage configuration file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Explicitly replace an existing regular output file.",
    ),
) -> None:
    """Generate a narrative Markdown PQC migration report."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_output = output or config.outputs.report_path
    try:
        write_private_text(
            resolved_output,
            generate_markdown_report(inventory),
            overwrite=overwrite,
            protected_paths=(inventory_path, config_path),
        )
    except (ResourceLimitError, UnsafeOutputError, OSError) as error:
        _safe_print(f"Report generation failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    _safe_print(f"Report written: {resolved_output}", style="green")


@import_app.command("cbom")
def import_cbom_command(
    input_path: Path = typer.Argument(
        ...,
        help="Path to a CycloneDX CBOM JSON file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Path where the imported QSTriage YAML inventory will be written.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Explicitly replace an existing regular output file.",
    ),
) -> None:
    """Import CycloneDX CBOM JSON as a partial QSTriage inventory."""
    written_path = _write_cbom_import_or_exit(
        input_path,
        output,
        overwrite=overwrite,
    )

    _safe_print(f"CBOM imported: {written_path}", style="green")
    console.print(
        "CBOM dependencies were not imported as QSTriage blast-radius dependencies.",
        style="yellow",
    )


@review_app.command("context")
def review_context_command(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """Review decision-context completeness for an inventory."""
    inventory = _load_inventory_or_exit(inventory_path)
    review = review_decision_context(inventory)

    console.print(f"Decision context status: {review.status}")
    console.print(f"Incomplete assets: {review.incomplete_asset_count}")
    console.print(f"Issues: {review.issue_count}")

    if review.inventory_issues:
        console.print("")
        console.print("Inventory-level issues:")
        for issue in review.inventory_issues:
            _safe_print(f"- {issue}")

    for asset_review in review.asset_reviews:
        if asset_review.status == "complete":
            continue

        console.print("")
        _safe_print(f"Asset: {asset_review.asset_name} ({asset_review.asset_id})")
        console.print(f"Status: {asset_review.status}")
        console.print("Missing or defaulted context:")

        for issue in asset_review.issues:
            _safe_print(f"- {issue.field}: {issue.message}")

        _safe_print(f"Recommended action: {asset_review.recommended_action}")


@review_app.command("evidence")
def review_evidence_command(
    input_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage inventory YAML file or CycloneDX CBOM JSON file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    input_format: str = typer.Option(
        "inventory",
        "--input-format",
        help="Input format: inventory or cbom.",
    ),
) -> None:
    """Review evidence quality and decision-grade readiness."""
    inventory, source_type = _load_inventory_for_review_or_exit(input_path, input_format)
    reviews = review_inventory_evidence(inventory, source_type=source_type)

    table = Table(title="QSTriage Evidence Quality Review")
    table.add_column("Asset", max_width=18, overflow="fold")
    table.add_column("Decision Grade")
    table.add_column("Evidence", justify="right")
    table.add_column("Confidence Cap", justify="right")
    table.add_column("Human Review")
    table.add_column("Blocking Findings")

    for review in reviews:
        blocking = ", ".join(review.blocking_finding_codes) or "-"
        table.add_row(
            _safe_text(review.asset_id or "-"),
            review.decision_grade.value,
            f"{review.evidence_score:.2f}",
            f"{review.confidence_cap:.2f}",
            "yes" if review.human_review_required else "no",
            blocking,
        )

    console.print(table)

    console.print("")
    console.print("Evidence review details:")
    for review in reviews:
        blocking = ", ".join(review.blocking_finding_codes) or "-"
        _safe_print(
            f"- {review.asset_id or '-'}: "
            f"decision_grade={review.decision_grade.value}; "
            f"evidence_score={review.evidence_score:.2f}; "
            f"confidence_cap={review.confidence_cap:.2f}; "
            f"human_review_required={'yes' if review.human_review_required else 'no'}; "
            f"blocking_findings={blocking}"
        )


@pdr_app.command("generate")
def generate_pdr_command(
    input_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage inventory YAML file or CycloneDX CBOM JSON file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Path where the PDR JSON document will be written.",
    ),
    input_format: str = typer.Option(
        "inventory",
        "--input-format",
        help="Input format: inventory or cbom.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Explicitly replace an existing regular output file.",
    ),
) -> None:
    """Generate a PQC Decision Record JSON document."""
    written_path = _write_pdr_document_or_exit(
        input_path,
        output,
        input_format,
        overwrite=overwrite,
    )

    _safe_print(f"PDR written: {written_path}", style="green")


@export_app.command("scores")
def export_scores_command(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    export_format: ExportFormat | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Export format.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path where exported score results will be written.",
    ),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional QSTriage configuration file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Explicitly replace an existing regular output file.",
    ),
) -> None:
    """Export canonical decision-aware score results as JSON or CSV."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_format = export_format or ExportFormat(config.exports.default_format)
    resolved_output = output or config.outputs.scores_path
    try:
        written_path = export_score_results(
            inventory,
            resolved_output,
            resolved_format,
            overwrite=overwrite,
            protected_paths=(inventory_path, config_path),
        )
    except (ResourceLimitError, UnsafeOutputError, OSError) as error:
        _safe_print(f"Score export failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    _safe_print(f"Scores exported: {written_path}", style="green")


@export_app.command("simulations")
def export_simulations_command(
    inventory_path: Path = typer.Argument(
        ...,
        help="Path to a QSTriage YAML inventory file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    export_format: ExportFormat | None = typer.Option(
        None,
        "--format",
        "-f",
        help="Export format.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Path where exported simulation results will be written.",
    ),
    config_path: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Optional QSTriage configuration file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Explicitly replace an existing regular output file.",
    ),
) -> None:
    """Export simulation results as JSON or CSV."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_format = export_format or ExportFormat(config.exports.default_format)
    resolved_output = output or config.outputs.simulations_path
    try:
        written_path = export_simulation_results(
            inventory,
            resolved_output,
            resolved_format,
            overwrite=overwrite,
            protected_paths=(inventory_path, config_path),
        )
    except (ResourceLimitError, UnsafeOutputError, OSError) as error:
        _safe_print(f"Simulation export failed: {error}", style="red")
        raise typer.Exit(code=1) from error

    _safe_print(f"Simulations exported: {written_path}", style="green")


app.add_typer(import_app, name="import")
app.add_typer(export_app, name="export")
app.add_typer(review_app, name="review")
app.add_typer(pdr_app, name="pdr")

app.add_typer(policy_app, name="policy")


if __name__ == "__main__":
    app()
