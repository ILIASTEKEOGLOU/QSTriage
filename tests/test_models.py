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


def _asset(asset_id: str, *, name: str = "Asset") -> dict[str, object]:
    return {
        "id": asset_id,
        "name": name,
        "environment": "test",
        "asset_type": "service",
        "protocol": "TLS1.3",
        "algorithm": "RSA-2048",
        "key_size_bits": 2048,
        "data_class": "test_data",
        "retention_years": 1,
        "exposure": "internal",
        "criticality": "medium",
        "local_blast_radius": "medium",
        "migration_effort": "low",
    }


def test_inventory_requires_at_least_one_asset() -> None:
    with pytest.raises(ValidationError):
        Inventory.model_validate({"assets": []})


def test_inventory_rejects_excessive_asset_count() -> None:
    from qstriage.limits import MAX_ASSETS

    assets = [_asset(f"asset-{index}") for index in range(MAX_ASSETS + 1)]

    with pytest.raises(ValidationError):
        Inventory.model_validate({"assets": assets})


def test_inventory_rejects_overlong_asset_name() -> None:
    from qstriage.limits import MAX_TEXT_LENGTH

    with pytest.raises(ValidationError):
        Inventory.model_validate(
            {"assets": [_asset("asset-1", name="x" * (MAX_TEXT_LENGTH + 1))]}
        )


def test_inventory_rejects_excessive_simulation_cross_product() -> None:
    from qstriage.limits import MAX_SIMULATION_RESULTS

    assets = [_asset(f"asset-{index}") for index in range(201)]
    scenarios = [
        {
            "id": f"scenario-{index}",
            "name": f"Scenario {index}",
            "pqc_profile": "ML-KEM-768 + X25519",
        }
        for index in range(100)
    ]
    assert len(assets) * len(scenarios) > MAX_SIMULATION_RESULTS

    with pytest.raises(ValidationError, match="simulation results"):
        Inventory.model_validate({"assets": assets, "scenarios": scenarios})
