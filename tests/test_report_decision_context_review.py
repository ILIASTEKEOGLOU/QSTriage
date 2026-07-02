from pathlib import Path

from qstriage.cbom import import_cbom_inventory
from qstriage.models import load_inventory
from qstriage.report import generate_markdown_report


def test_report_contains_complete_decision_context_review_for_sample_inventory() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    report = generate_markdown_report(inventory)

    assert "## Decision Context Review" in report
    assert "- Status: complete" in report
    assert "- Incomplete assets: 0" in report
    assert "- Issues: 0" in report
    assert "No decision-context issues were detected" in report


def test_report_contains_incomplete_decision_context_review_for_cbom_import() -> None:
    inventory = import_cbom_inventory(Path("tests/fixtures/sample_cbom.json"))

    report = generate_markdown_report(inventory)

    assert "## Decision Context Review" in report
    assert "- Status: incomplete" in report
    assert "- Incomplete assets: 2" in report
    assert "Inventory-level issues:" in report
    assert "No QSTriage business/security dependencies declared" in report
    assert "crypto-rsa-2048" in report
    assert "`data_class`: data_class is unknown" in report
    assert "`retention_years`: retention_years is 0" in report
    assert "`exposure`: exposure is unknown" in report
    assert "`criticality`: criticality is the CBOM import default medium" in report
    assert "Add business context before treating this asset score as decision-grade" in report
