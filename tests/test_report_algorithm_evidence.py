from qstriage.cbom import import_cbom_inventory
from qstriage.models import CryptographicAsset, Inventory, RiskLevel
from qstriage.report import generate_markdown_report


def test_report_contains_algorithm_classification_evidence_for_cbom_import() -> None:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")

    report = generate_markdown_report(inventory)

    assert "Algorithm classification:" in report
    assert "Input algorithm: `RSA-2048`" in report
    assert "Algorithm family: RSA" in report
    assert "Quantum status: quantum_vulnerable" in report
    assert "Registry action: migrate_to_hybrid_or_pqc_path" in report
    assert "Registry sources: NIST-IR-8547-IPD" in report
    assert "Input algorithm: `ML-KEM-768`" in report
    assert "Algorithm family: ML-KEM" in report
    assert "Quantum status: quantum_resistant" in report
    assert "Registry action: acceptable_pqc_kem" in report
    assert "Registry sources: NIST-FIPS-203" in report


def test_report_contains_manual_review_evidence_for_unknown_algorithm() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unknown-asset",
                name="Unknown Crypto Asset",
                environment="test",
                asset_type="service",
                protocol="custom",
                algorithm="MysteryCrypto-1",
                key_size_bits=None,
                data_class="internal",
                retention_years=1,
                exposure="internal",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.low,
                migration_effort=RiskLevel.medium,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    report = generate_markdown_report(inventory)

    assert "Input algorithm: `MysteryCrypto-1`" in report
    assert "Algorithm family: unknown" in report
    assert "Quantum status: unknown" in report
    assert "Registry action: manual_review_required" in report
    assert "Registry sources: QSTRIAGE-SAFETY-POLICY" in report


def test_report_exposes_unverified_identifier_resolution_and_evidence_warning() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unverified-pqc",
                name="Unverified PQC",
                environment="test",
                asset_type="service",
                protocol="custom",
                algorithm="ML-DSA-17",
                key_size_bits=None,
                data_class="internal",
                retention_years=1,
                exposure="internal",
                criticality=RiskLevel.medium,
                local_blast_radius=RiskLevel.low,
                migration_effort=RiskLevel.medium,
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    report = generate_markdown_report(inventory)

    assert "Input algorithm: `ML-DSA-17`" in report
    assert "Algorithm family: ML-DSA" in report
    assert (
        "Identifier resolution: recognized_family_unverified_parameters"
        in report
    )
    assert "Quantum status: unknown" in report
    assert "Standard status: unknown" in report
    assert "unverified_algorithm_parameters" in report
