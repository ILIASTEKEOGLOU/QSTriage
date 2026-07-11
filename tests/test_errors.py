import yaml
from pydantic import ValidationError

from qstriage.errors import format_inventory_load_error
from qstriage.models import Inventory


def test_format_validation_error_for_missing_required_field() -> None:
    raw_inventory = {
        "assets": [
            {
                "id": "api",
                "name": "API",
            }
        ]
    }

    try:
        Inventory.model_validate(raw_inventory)
    except ValidationError as error:
        message = format_inventory_load_error(error, path="inventory.yaml")
    else:
        raise AssertionError("Expected validation error")

    assert "Inventory validation failed in inventory.yaml" in message
    assert "Missing required field" in message
    assert "assets[0].environment" in message


def test_format_validation_error_for_unknown_field() -> None:
    raw_inventory = {
        "assets": [],
        "unexpected": True,
    }

    try:
        Inventory.model_validate(raw_inventory)
    except ValidationError as error:
        message = format_inventory_load_error(error)
    else:
        raise AssertionError("Expected validation error")

    assert "Unknown field `unexpected` is not allowed" in message


def test_format_validation_error_for_unknown_dependency_target() -> None:
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

    try:
        Inventory.model_validate(raw_inventory)
    except ValidationError as error:
        message = format_inventory_load_error(error)
    else:
        raise AssertionError("Expected validation error")

    assert "references unknown target asset" in message
    assert "missing-db" in message


def test_format_yaml_error_includes_line_and_column() -> None:
    try:
        yaml.safe_load("assets:\n  - id: api\n    name: [broken\n")
    except yaml.YAMLError as error:
        message = format_inventory_load_error(error, path="broken.yaml")
    else:
        raise AssertionError("Expected YAML error")

    assert "Inventory YAML is malformed in broken.yaml" in message
    assert "line" in message
    assert "column" in message


def test_format_resource_limit_error_as_input_rejection() -> None:
    from qstriage.limits import ResourceLimitError

    message = format_inventory_load_error(
        ResourceLimitError("Inventory file exceeds the supported size limit."),
        path="inventory.yaml",
    )

    assert message == (
        "Input rejected in inventory.yaml: "
        "Inventory file exceeds the supported size limit."
    )
