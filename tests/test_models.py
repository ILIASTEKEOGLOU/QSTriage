from pathlib import Path

import pytest
from pydantic import ValidationError

from qstriage.models import DependencyType, Inventory, RiskLevel, load_inventory


def test_load_sample_inventory() -> None:
    inventory = load_inventory(Path("examples/sample_inventory.yaml"))

    assert len(inventory.assets) == 5
    assert len(inventory.dependencies) == 5
    assert len(inventory.scenarios) == 1

    assets = inventory.asset_by_id()

    assert "public-api-gateway" in assets
    assert assets["customer-db"].criticality == RiskLevel.critical
    assert inventory.dependencies[0].dependency_type == DependencyType.auth
    assert inventory.dependencies[0].weight == 0.90


def test_dependency_cannot_reference_unknown_asset() -> None:
    raw_inventory = {
        "assets": [
            {
                "id": "api",
                "name": "API",
                "environment": "test",
                "asset_type": "api_service",
                "protocol": "TLS1.3",
                "algorithm": "RSA",
                "key_size_bits": 2048,
                "data_class": "test_data",
                "retention_years": 1,
                "exposure": "internal",
                "criticality": "medium",
                "local_blast_radius": "medium",
                "migration_effort": "low",
            }
        ],
        "dependencies": [
            {
                "id": "dep-api-db",
                "source": "api",
                "target": "missing-db",
                "direction": "outbound",
                "dependency_type": "database",
                "protocol": "mTLS",
                "weight": 0.8,
                "criticality": "high",
                "carries_crypto_context": True,
            }
        ],
    }

    with pytest.raises(ValidationError):
        Inventory.model_validate(raw_inventory)


def test_dependency_weight_must_be_between_zero_and_one() -> None:
    raw_dependency = {
        "assets": [
            {
                "id": "api",
                "name": "API",
                "environment": "test",
                "asset_type": "api_service",
                "protocol": "TLS1.3",
                "algorithm": "RSA",
                "key_size_bits": 2048,
                "data_class": "test_data",
                "retention_years": 1,
                "exposure": "internal",
                "criticality": "medium",
                "local_blast_radius": "medium",
                "migration_effort": "low",
            },
            {
                "id": "db",
                "name": "DB",
                "environment": "test",
                "asset_type": "database",
                "protocol": "mTLS",
                "algorithm": "RSA",
                "key_size_bits": 2048,
                "data_class": "test_data",
                "retention_years": 1,
                "exposure": "internal",
                "criticality": "medium",
                "local_blast_radius": "medium",
                "migration_effort": "low",
            },
        ],
        "dependencies": [
            {
                "id": "dep-api-db",
                "source": "api",
                "target": "db",
                "direction": "outbound",
                "dependency_type": "database",
                "protocol": "mTLS",
                "weight": 1.2,
                "criticality": "high",
                "carries_crypto_context": True,
            }
        ],
    }

    with pytest.raises(ValidationError):
        Inventory.model_validate(raw_dependency)
