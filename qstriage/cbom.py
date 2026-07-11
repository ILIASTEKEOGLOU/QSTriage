from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from qstriage.file_output import write_private_text
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


def write_imported_inventory(
    input_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    inventory = import_cbom_inventory(input_path)
    destination = Path(output_path)
    return write_private_text(
        destination,
        yaml.safe_dump(
            inventory.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ),
        overwrite=overwrite,
        protected_paths=(input_path,),
    )


def _is_cryptographic_asset(component: dict[str, Any]) -> bool:
    return (
        component.get("type") == "cryptographic-asset"
        or "cryptoProperties" in component
    )


def _asset_from_component(component: dict[str, Any]) -> CryptographicAsset:
    crypto_properties = component.get("cryptoProperties") or {}
    algorithm_properties = crypto_properties.get("algorithmProperties") or {}
    protocol_properties = crypto_properties.get("protocolProperties") or {}
    asset_type = _string_or_none(crypto_properties.get("assetType"))

    algorithm = _cbom_algorithm_identifier(
        algorithm_properties,
        component,
        asset_type=asset_type,
    )
    protocol = _cbom_protocol_identifier(
        asset_type,
        protocol_properties,
        algorithm_properties,
        component,
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
        protocol=str(protocol),
        algorithm=str(algorithm),
        key_size_bits=_extract_key_size_bits(algorithm_properties, str(algorithm)),
        data_class="unknown",
        retention_years=0,
        exposure="unknown",
        criticality="medium",
        local_blast_radius="medium",
        migration_effort="medium",
        notes=_build_notes(crypto_properties, algorithm_properties),
    )


def _cbom_algorithm_identifier(
    algorithm_properties: dict[str, Any],
    component: dict[str, Any],
    *,
    asset_type: str | None = None,
) -> str:
    parameter_set = _string_or_none(algorithm_properties.get("parameterSetIdentifier"))
    algorithm = _string_or_none(algorithm_properties.get("algorithm"))
    family = _string_or_none(algorithm_properties.get("algorithmFamily"))
    component_name = _string_or_none(component.get("name"))

    key_size_bits = _extract_key_size_bits(
        algorithm_properties,
        " ".join(value for value in (parameter_set, algorithm, family, component_name) if value),
    )

    for value in (parameter_set, algorithm):
        if value:
            return _normalize_cbom_algorithm_string(value, family, key_size_bits)

    if family:
        return _normalize_cbom_algorithm_string(family, family, key_size_bits)

    if asset_type == "protocol":
        return "unknown"

    if component_name:
        return _normalize_cbom_algorithm_string(component_name, None, key_size_bits)

    return "unknown"


def _cbom_protocol_identifier(
    asset_type: str | None,
    protocol_properties: dict[str, Any],
    algorithm_properties: dict[str, Any],
    component: dict[str, Any],
) -> str:
    if asset_type == "protocol":
        return str(
            _first_non_empty(
                protocol_properties.get("protocol"),
                protocol_properties.get("name"),
                component.get("name"),
                asset_type,
                "protocol",
            )
        )

    return str(
        _first_non_empty(
            algorithm_properties.get("primitive"),
            asset_type,
            "unknown",
        )
    )


def _normalize_cbom_algorithm_string(
    value: str,
    family: str | None,
    key_size_bits: int | None,
) -> str:
    cleaned = value.strip()
    family_cleaned = family.strip() if family else ""
    cleaned_upper = cleaned.upper().replace("_", "-")
    family_upper = family_cleaned.upper().replace("_", "-")

    if family_upper and cleaned_upper.isdigit():
        return f"{family_cleaned}-{cleaned}"

    if family_upper and cleaned_upper.startswith(f"{family_upper}-"):
        return cleaned

    if family_upper == "ML-KEM" and cleaned_upper in {"512", "768", "1024"}:
        return f"ML-KEM-{cleaned}"

    if family_upper == "ML-DSA" and cleaned_upper in {"44", "65", "87"}:
        return f"ML-DSA-{cleaned}"

    if family_upper == "RSA" and key_size_bits is not None and cleaned_upper == "RSA":
        return f"RSA-{key_size_bits}"

    if family_upper == "AES" and key_size_bits is not None and cleaned_upper == "AES":
        return f"AES-{key_size_bits}"

    return cleaned


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None

    cleaned = str(value).strip()
    if not cleaned:
        return None

    return cleaned


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


def _build_notes(
    crypto_properties: dict[str, Any],
    algorithm_properties: dict[str, Any],
) -> str:
    details = []

    asset_type = crypto_properties.get("assetType")
    if asset_type is not None:
        details.append(f"assetType={asset_type}")

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
