from pathlib import Path

from qstriage.models import load_inventory
from qstriage.report import generate_markdown_report, write_markdown_report


def test_generate_markdown_report_contains_main_sections() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    report = generate_markdown_report(inventory)

    assert "# QSTriage PQC Migration Assessment Report" in report
    assert "## Executive Summary" in report
    assert "## Priority Backlog" in report
    assert "## Asset-Level Findings" in report
    assert "## Dependency Graph Views" in report
    assert "## Method Notes" in report


def test_generate_markdown_report_contains_scores_and_simulation_warnings() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    report = generate_markdown_report(inventory)

    assert "Public API Gateway" in report
    assert "Customer Database" in report
    assert "Graph-amplified blast radius" in report
    assert "Simulation warnings" in report
    assert "fragmentation risk" in report
    assert "middlebox risk" in report



def test_generate_markdown_report_uses_canonical_decision_fields() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    report = generate_markdown_report(inventory)

    assert "| Risk Attention | Band | Execution | Canonical Action |" in report
    assert "- Risk attention score: **81.00**" in report
    assert "- Execution state: **justified**" in report
    assert "- Canonical action: **simulate_before_migration**" in report
    assert "- Verification requirements: none" in report
    assert "- Decision confidence: 0.80" in report
    assert "- Human review required: yes" in report
    assert "- Reason codes: classification:quantum_vulnerable" in report
    assert "review soon and include in near-term migration backlog" not in report

def test_generate_markdown_report_contains_text_graph_block() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    report = generate_markdown_report(inventory)

    assert "```text" in report
    assert "[public-api-gateway]" in report
    assert "w=0.90" in report


def test_write_markdown_report_creates_file(tmp_path: Path) -> None:
    output_path = tmp_path / "qstriage-report.md"

    written_path = write_markdown_report(
        Path("examples/sample_inventory.yaml"),
        output_path,
    )

    assert written_path == output_path
    assert written_path.exists()

    content = written_path.read_text(encoding="utf-8")

    assert "QSTriage PQC Migration Assessment Report" in content
