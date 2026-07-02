from pathlib import Path

import yaml

from qstriage.cbom import (
    import_cbom_inventory,
    inventory_from_cbom,
    load_cbom_json,
    write_imported_inventory,
)
from qstriage.models import load_inventory


FIXTURE_PATH = Path("tests/fixtures/sample_cbom.json")


def test_load_cbom_json_reads_cyclonedx_document() -> None:
    cbom = load_cbom_json(FIXTURE_PATH)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"


def test_inventory_from_cbom_imports_only_cryptographic_assets() -> None:
    cbom = load_cbom_json(FIXTURE_PATH)

    inventory = inventory_from_cbom(cbom)

    assert len(inventory.assets) == 2
    assert [asset.id for asset in inventory.assets] == [
        "crypto-rsa-2048",
        "crypto-ml-kem-768",
    ]
    assert inventory.dependencies == []


def test_imported_cbom_assets_keep_crypto_metadata_in_notes() -> None:
    inventory = import_cbom_inventory(FIXTURE_PATH)

    rsa_asset = next(asset for asset in inventory.assets if asset.id == "crypto-rsa-2048")
    kem_asset = next(asset for asset in inventory.assets if asset.id == "crypto-ml-kem-768")

    assert rsa_asset.algorithm == "RSA-2048"
    assert rsa_asset.key_size_bits == 2048
    assert rsa_asset.protocol == "signature"
    assert "business context requires human review" in rsa_asset.notes.lower()
    assert "cbom dependency relationships are not imported" in rsa_asset.notes.lower()

    assert kem_asset.algorithm == "ML-KEM-768"
    assert kem_asset.key_size_bits == 768
    assert kem_asset.protocol == "kem"
    assert "nistQuantumSecurityLevel=3" in kem_asset.notes


def test_write_imported_inventory_outputs_valid_qstriage_yaml(tmp_path: Path) -> None:
    output_path = tmp_path / "imported_inventory.yaml"

    written_path = write_imported_inventory(FIXTURE_PATH, output_path)

    assert written_path == output_path

    exported = yaml.safe_load(output_path.read_text(encoding="utf-8"))
    assert exported["dependencies"] == []

    loaded_inventory = load_inventory(output_path)

    assert len(loaded_inventory.assets) == 2
    assert loaded_inventory.dependencies == []


def test_cbom_import_normalizes_split_ml_kem_metadata_for_registry() -> None:
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

    asset = inventory.assets[0]

    assert asset.algorithm == "ML-KEM-768"
    assert asset.key_size_bits == 768


def test_cbom_import_normalizes_rsa_family_and_key_size_for_registry() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "rsa-family-only",
                "name": "RSA Family Asset",
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

    asset = inventory.assets[0]

    assert asset.algorithm == "RSA-2048"
    assert asset.key_size_bits == 2048


def test_cbom_import_normalizes_aes_family_and_key_size_for_registry() -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "aes-family-only",
                "name": "AES Family Asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "symmetric-encryption",
                        "algorithmFamily": "AES",
                        "keyLength": "256",
                    },
                },
            }
        ],
    }

    inventory = inventory_from_cbom(cbom)

    asset = inventory.assets[0]

    assert asset.algorithm == "AES-256"
    assert asset.key_size_bits == 256
