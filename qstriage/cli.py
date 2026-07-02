import json
from pathlib import Path

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from qstriage.cbom import write_imported_inventory
from qstriage.config import QSTriageConfig, load_config
from qstriage.errors import format_inventory_load_error
from qstriage.exporters import ExportFormat, export_score_results, export_simulation_results
from qstriage.graph import build_dependency_graph, render_text_graph
from qstriage.models import load_inventory
from qstriage.report import generate_markdown_report
from qstriage.scoring import score_inventory

app = typer.Typer(
    help="QSTriage — Explainable PQC Migration Decision Engine",
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

console = Console()


def _load_inventory_or_exit(inventory_path: Path):
    try:
        return load_inventory(inventory_path)
    except (FileNotFoundError, yaml.YAMLError, ValidationError, ValueError) as error:
        console.print(format_inventory_load_error(error, path=inventory_path), style="red")
        raise typer.Exit(code=1) from error


def _load_config_or_exit(config_path: Path | None) -> QSTriageConfig:
    try:
        return load_config(config_path)
    except (FileNotFoundError, yaml.YAMLError, ValidationError, ValueError) as error:
        console.print(format_inventory_load_error(error, path=config_path), style="red")
        raise typer.Exit(code=1) from error


def _write_cbom_import_or_exit(input_path: Path, output_path: Path) -> Path:
    try:
        return write_imported_inventory(input_path, output_path)
    except (FileNotFoundError, json.JSONDecodeError, ValidationError, ValueError) as error:
        console.print(f"[red]CBOM import failed:[/red] {error}")
        raise typer.Exit(code=1) from error


@app.callback()
def main() -> None:
    """QSTriage command line interface."""
    pass


@app.command()
def version() -> None:
    """Show QSTriage version."""
    typer.echo("QSTriage 0.2.0")


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
    results = score_inventory(inventory)

    table = Table(title="QSTriage Priority Backlog")
    table.add_column("Rank", justify="right")
    table.add_column("Asset")
    table.add_column("Score", justify="right")
    table.add_column("Band")
    table.add_column("Recommended Action")

    for index, result in enumerate(results, start=1):
        table.add_row(
            str(index),
            result.asset_name,
            f"{result.priority_score:.2f}",
            result.priority_band,
            result.recommended_action,
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

    console.print(render_text_graph(dependency_graph, asset_id), markup=False)


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
) -> None:
    """Generate a narrative Markdown PQC migration report."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_output = output or config.outputs.report_path
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    resolved_output.write_text(generate_markdown_report(inventory), encoding="utf-8")

    console.print(f"[green]Report written:[/green] {resolved_output}")


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
) -> None:
    """Import CycloneDX CBOM JSON as a partial QSTriage inventory."""
    written_path = _write_cbom_import_or_exit(input_path, output)

    console.print(f"[green]CBOM imported:[/green] {written_path}")
    console.print(
        "CBOM dependencies were not imported as QSTriage blast-radius dependencies.",
        style="yellow",
    )


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
) -> None:
    """Export score results as JSON or CSV."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_format = export_format or ExportFormat(config.exports.default_format)
    resolved_output = output or config.outputs.scores_path
    written_path = export_score_results(inventory, resolved_output, resolved_format)

    console.print(f"[green]Scores exported:[/green] {written_path}")


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
) -> None:
    """Export simulation results as JSON or CSV."""
    inventory = _load_inventory_or_exit(inventory_path)
    config = _load_config_or_exit(config_path)
    resolved_format = export_format or ExportFormat(config.exports.default_format)
    resolved_output = output or config.outputs.simulations_path
    written_path = export_simulation_results(inventory, resolved_output, resolved_format)

    console.print(f"[green]Simulations exported:[/green] {written_path}")


app.add_typer(import_app, name="import")
app.add_typer(export_app, name="export")


if __name__ == "__main__":
    app()
