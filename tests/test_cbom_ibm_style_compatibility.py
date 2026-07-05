from pathlib import Path

from typer.testing import CliRunner

from qstriage.cbom import import_cbom_inventory, write_imported_inventory
from qstriage.cli import app
from qstriage.evidence import review_inventory_evidence
from qstriage.models import load_inventory


FIXTURE_PATH = Path("tests/fixtures/ibm_style_cbom_minimal.json")


def test_ibm_style_cbom_crypto_asset_components_import() -> None:
    inventory = import_cbom_inventory(FIXTURE_PATH)

    assert len(inventory.assets) == 2
    assert inventory.dependencies == []

    aes_asset = next(asset for asset in inventory.assets if asset.name == "AES")
    tls_asset = next(asset for asset in inventory.assets if asset.name == "tlsv12")

    assert aes_asset.id == "oid-2.16.840.1.101.3.4.1.6"
    assert aes_asset.algorithm == "AES"
    assert aes_asset.protocol == "ae"
    assert "primitive=ae" in aes_asset.notes

    assert tls_asset.id == "oid-1.3.18.0.2.32.104"
    assert tls_asset.protocol == "protocol"
    assert tls_asset.algorithm == "tlsv12"
    assert "CBOM dependency relationships are not imported" in tls_asset.notes


def test_ibm_style_cbom_cli_import_writes_valid_inventory(tmp_path: Path) -> None:
    output_path = tmp_path / "ibm_style_imported.yml"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "import",
            "cbom",
            str(FIXTURE_PATH),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "CBOM imported" in result.output
    assert "dependencies were not imported" in result.output

    inventory = load_inventory(output_path)

    assert len(inventory.assets) == 2
    assert inventory.dependencies == []


def test_ibm_style_cbom_downstream_flow_documents_current_limitations(
    tmp_path: Path,
) -> None:
    inventory = import_cbom_inventory(FIXTURE_PATH)

    evidence_reviews = review_inventory_evidence(
        inventory,
        source_type="cyclonedx_cbom",
    )
    findings_by_asset = {
        review.asset_id: set(review.blocking_finding_codes)
        for review in evidence_reviews
    }

    assert "unknown_algorithm" not in findings_by_asset[
        "oid-2.16.840.1.101.3.4.1.6"
    ]
    assert "unknown_algorithm" in findings_by_asset[
        "oid-1.3.18.0.2.32.104"
    ]

    imported_path = tmp_path / "ibm_style_imported.yml"
    report_path = tmp_path / "ibm_style_report.md"

    write_imported_inventory(FIXTURE_PATH, imported_path)

    result = CliRunner().invoke(
        app,
        [
            "report",
            str(imported_path),
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert report_path.exists()

    report = report_path.read_text(encoding="utf-8")

    assert "Assets analyzed: 2" in report
    assert "CBOM dependency relationships" in report
    assert "Input algorithm: `tlsv12`" in report
    assert "Registry action: manual_review_required" in report
