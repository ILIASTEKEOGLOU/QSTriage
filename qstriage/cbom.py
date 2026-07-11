from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from qstriage.file_output import write_private_text
from qstriage.limits import (
    MAX_CBOM_COMPONENTS,
    MAX_CBOM_FILE_BYTES,
    ResourceLimitError,
    read_text_limited,
)
from qstriage.models import CryptographicAsset, Inventory


REVIEW_REQUIRED_NOTE = (
    "Imported from CycloneDX CBOM. Business context requires human review. "
    "CBOM dependency relationships are not imported as QSTriage blast-radius dependencies."
)


def parse_cbom_json(text: str) -> dict[str, Any]:
    """Parse one already-captured CycloneDX CBOM text snapshot."""

    try:
        payload = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except RecursionError as error:
        raise ResourceLimitError(
            "CBOM JSON exceeds the supported nesting depth."
        ) from error

    _validate_cbom_document(payload)
    return payload


def load_cbom_json(path: str | Path) -> dict[str, Any]:
    cbom_path = Path(path)
    text = read_text_limited(
        cbom_path,
        max_bytes=MAX_CBOM_FILE_BYTES,
        label="CBOM file",
    )
    return parse_cbom_json(text)


def inventory_from_cbom(cbom: dict[str, Any]) -> Inventory:
    _validate_cbom_document(cbom)
    components = cbom.get("components", [])
    assets = [
        _asset_from_component(component)
        for component in components
        if _is_cryptographic_asset(component)
    ]

    if not assets:
        raise ValueError("CBOM contains no cryptographic asset components.")

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


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"CBOM JSON contains duplicate key '{key}'.")
        result[key] = value
    return result


def _validate_cbom_document(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("CBOM document root must be a JSON object.")

    components = payload.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CBOM field 'components' must be a JSON array.")
    if len(components) > MAX_CBOM_COMPONENTS:
        raise ResourceLimitError(
            f"CBOM contains {len(components)} components; the supported limit is "
            f"{MAX_CBOM_COMPONENTS}."
        )

    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"CBOM components[{index}] must be a JSON object.")

        for field in ("bom-ref", "name", "type"):
            _validate_optional_scalar(
                component.get(field),
                location=f"components[{index}].{field}",
            )

        crypto_properties = component.get("cryptoProperties")
        if crypto_properties is None:
            continue
        if not isinstance(crypto_properties, dict):
            raise ValueError(
                f"CBOM components[{index}].cryptoProperties must be a JSON object."
            )

        for field in ("assetType", "executionEnvironment"):
            _validate_optional_scalar(
                crypto_properties.get(field),
                location=f"components[{index}].cryptoProperties.{field}",
            )

        for field in ("algorithmProperties", "protocolProperties"):
            nested = crypto_properties.get(field)
            if nested is not None and not isinstance(nested, dict):
                raise ValueError(
                    f"CBOM components[{index}].cryptoProperties.{field} "
                    "must be a JSON object."
                )

        algorithm_properties = crypto_properties.get("algorithmProperties") or {}
        for field in (
            "parameterSetIdentifier",
            "algorithm",
            "algorithmFamily",
            "primitive",
            "executionEnvironment",
            "keySize",
            "keySizeBits",
            "keyLength",
            "publicKeySize",
            "classicalSecurityLevel",
            "nistQuantumSecurityLevel",
        ):
            _validate_optional_scalar(
                algorithm_properties.get(field),
                location=(
                    f"components[{index}].cryptoProperties."
                    f"algorithmProperties.{field}"
                ),
            )

        protocol_properties = crypto_properties.get("protocolProperties") or {}
        for field in ("protocol", "name"):
            _validate_optional_scalar(
                protocol_properties.get(field),
                location=(
                    f"components[{index}].cryptoProperties."
                    f"protocolProperties.{field}"
                ),
            )


def _validate_optional_scalar(value: Any, *, location: str) -> None:
    if value is None:
        return
    if isinstance(value, (str, int, float, bool)):
        return
    raise ValueError(f"CBOM {location} must be a JSON scalar value.")


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
    if isinstance(value, (dict, list)):
        raise ValueError("CBOM scalar field cannot be an object or array.")

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
