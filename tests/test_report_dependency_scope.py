from qstriage.cbom import import_cbom_inventory
from qstriage.report import generate_markdown_report


def test_report_warns_when_no_qstriage_business_dependencies_declared() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")

    report = generate_markdown_report(inventory)

    assert "Dependency scope warning" in report
    assert "Graph-amplified blast radius is limited" in report
    assert "no QSTriage business dependencies were declared" in report
    assert "CBOM dependency relationships" in report
    assert "not treated as QSTriage blast-radius dependencies" in report
