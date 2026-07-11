from qstriage.cbom import inventory_from_cbom
from qstriage.pdr import generate_pdr_document
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


def test_cdxgen_aes_names_flow_into_canonical_pdr_decisions() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/algorithm/aes256-CBC@2.16.840.1.101.3.4.1.42",
                "name": "aes256-CBC",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "oid": "2.16.840.1.101.3.4.1.42",
                },
            },
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/algorithm/aes256-GCM@2.16.840.1.101.3.4.1.46",
                "name": "aes256-GCM",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "oid": "2.16.840.1.101.3.4.1.46",
                },
            },
        ],
    }

    inventory = inventory_from_cbom(cbom)
    document = generate_pdr_document(
        inventory,
        source_type="cyclonedx_cbom",
        source_version="1.7",
    )

    assert [asset.algorithm for asset in inventory.assets] == [
        "AES-256-CBC",
        "AES-256-GCM",
    ]
    assert [record.observed_state.algorithm_family for record in document.records] == [
        "AES",
        "AES",
    ]
    assert [record.decision.action_type.value for record in document.records] == [
        "key_strength_review",
        "key_strength_review",
    ]
    assert [record.decision.execution_state.value for record in document.records] == [
        "gated",
        "gated",
    ]
