from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from qstriage.models import CryptographicAsset, Inventory


REVIEW_REQUIRED_NOTE = (
    "Imported from CycloneDX CBOM. Business context requires human review. "
    "CBOM dependency relationships are not imported as QSTriage blast-radius dependencies."
)


def load_cbom_json(path: str | Path) -> dict[str, Any]:
    cbom_path = Path(path)
    return json.loads(cbom_path.read_text(encoding="utf-8"))


def inventory_from_cbom(cbom: dict[str, Any]) -> Inventory:
    assets = [
        _asset_from_component(component)
        for component in cbom.get("components", [])
        if _is_cryptographic_asset(component)
    ]

    return Inventory(assets=assets, dependencies=[], scenarios=[])


def import_cbom_inventory(input_path: str | Path) -> Inventory:
    return inventory_from_cbom(load_cbom_json(input_path))


def write_imported_inventory(input_path: str | Path, output_path: str | Path) -> Path:
    inventory = import_cbom_inventory(input_path)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(
            inventory.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return destination


def _is_cryptographic_asset(component: dict[str, Any]) -> bool:
    return (
        component.get("type") == "cryptographic-asset"
        or "cryptoProperties" in component
    )


def _asset_from_component(component: dict[str, Any]) -> CryptographicAsset:
    crypto_properties = component.get("cryptoProperties") or {}
    algorithm_properties = crypto_properties.get("algorithmProperties") or {}

    algorithm = _first_non_empty(
        algorithm_properties.get("parameterSetIdentifier"),
        algorithm_properties.get("algorithm"),
        algorithm_properties.get("algorithmFamily"),
        component.get("name"),
        "unknown",
    )

    primitive = _first_non_empty(
        algorithm_properties.get("primitive"),
        crypto_properties.get("assetType"),
        "unknown",
    )

    return CryptographicAsset(
        id=_normalize_asset_id(component),
        name=str(component.get("name") or algorithm),
        environment=str(
            _first_non_empty(
                crypto_properties.get("executionEnvironment"),
                algorithm_properties.get("executionEnvironment"),
                "unknown",
            )
        ),
        asset_type="cbom_cryptographic_asset",
        protocol=str(primitive),
        algorithm=str(algorithm),
        key_size_bits=_extract_key_size_bits(algorithm_properties, str(algorithm)),
        data_class="unknown",
        retention_years=0,
        exposure="unknown",
        criticality="medium",
        local_blast_radius="medium",
        migration_effort="medium",
        notes=_build_notes(algorithm_properties),
    )


def _normalize_asset_id(component: dict[str, Any]) -> str:
    raw_id = str(
        _first_non_empty(
            component.get("bom-ref"),
            component.get("name"),
            "cbom-cryptographic-asset",
        )
    )
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw_id.strip().lower())
    return normalized.strip("-") or "cbom-cryptographic-asset"


def _extract_key_size_bits(
    algorithm_properties: dict[str, Any],
    algorithm: str,
) -> int | None:
    for key in ("keySize", "keySizeBits", "keyLength", "publicKeySize"):
        value = algorithm_properties.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)

    match = re.search(r"(\d{3,5})", algorithm)
    if match:
        return int(match.group(1))

    return None


def _build_notes(algorithm_properties: dict[str, Any]) -> str:
    details = []

    for key in (
        "primitive",
        "algorithmFamily",
        "parameterSetIdentifier",
        "classicalSecurityLevel",
        "nistQuantumSecurityLevel",
    ):
        value = algorithm_properties.get(key)
        if value is not None:
            details.append(f"{key}={value}")

    if not details:
        return REVIEW_REQUIRED_NOTE

    return f"{REVIEW_REQUIRED_NOTE} CBOM crypto metadata: {', '.join(details)}."


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None
