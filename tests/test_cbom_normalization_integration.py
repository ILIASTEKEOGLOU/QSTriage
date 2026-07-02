from qstriage.cbom import inventory_from_cbom
from qstriage.report import generate_markdown_report
from qstriage.scoring import score_inventory


def test_normalized_cbom_ml_kem_flows_into_report_registry_evidence() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "split-ml-kem",
                "name": "Split ML-KEM Asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "kem",
                        "algorithmFamily": "ML-KEM",
                        "parameterSetIdentifier": "768",
                        "nistQuantumSecurityLevel": 3,
                    },
                },
            }
        ],
    }

    inventory = inventory_from_cbom(cbom)
    report = generate_markdown_report(inventory)

    assert "Input algorithm: `ML-KEM-768`" in report
    assert "Algorithm family: ML-KEM" in report
    assert "Quantum status: quantum_resistant" in report
    assert "Registry action: acceptable_pqc_kem" in report
    assert "Registry sources: NIST-FIPS-203" in report


def test_normalized_cbom_rsa_flows_into_scoring_registry_evidence() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "split-rsa",
                "name": "Split RSA Asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "signature",
                        "algorithmFamily": "RSA",
                        "keySize": 2048,
                        "classicalSecurityLevel": 112,
                        "nistQuantumSecurityLevel": 0,
                    },
                },
            }
        ],
    }

    inventory = inventory_from_cbom(cbom)
    result = score_inventory(inventory)[0]
    joined = "\n".join(result.explanation)

    assert inventory.assets[0].algorithm == "RSA-2048"
    assert result.breakdown.cryptographic_risk == 9.0
    assert "Algorithm registry classifies RSA as quantum_vulnerable" in joined
    assert "registry action is migrate_to_hybrid_or_pqc_path" in joined
