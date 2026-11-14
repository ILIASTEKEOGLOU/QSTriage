from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from qstriage.algorithm_registry import normalize_identifier
from qstriage.file_output import write_private_text
from qstriage.limits import (
    MAX_CBOM_COMPONENTS,
    MAX_CBOM_FILE_BYTES,
    MAX_JSON_NESTING_DEPTH,
    ResourceLimitError,
    check_json_nesting,
    check_structure,
    read_text_limited,
)
from qstriage.canonical_json import MAX_SAFE_INTEGER
from qstriage.models import CBOM_KEY_SIZE_PROPERTIES, CryptographicAsset, Inventory
from qstriage.standards import classify_algorithm, key_size_affects_score


REVIEW_REQUIRED_NOTE = (
    "Imported from CycloneDX CBOM. Business context requires human review. "
    "CBOM dependency relationships are not imported as QSTriage blast-radius dependencies."
)


def parse_cbom_json(text: str) -> dict[str, Any]:
    """Parse one already-captured CycloneDX CBOM text snapshot."""

    check_json_nesting(text, label="CBOM JSON")
    try:
        payload = json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except RecursionError as error:
        raise ResourceLimitError(
            "CBOM JSON exceeds the supported nesting depth."
        ) from error
    check_structure(payload, label="CBOM JSON", max_depth=MAX_JSON_NESTING_DEPTH)

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


def inventory_from_cbom(
    cbom: dict[str, Any],
    notices: list[str] | None = None,
) -> Inventory:
    """Convert a CBOM into a partial inventory.

    ``notices`` collects one line per CBOM value the import ignored or kept
    in ``cbom_key_sizes``; the caller decides where to show them.
    """

    _validate_cbom_document(cbom)
    components = cbom.get("components", [])
    collected = notices if notices is not None else []
    assets = [
        _asset_from_component(component, collected)
        for component in components
        if _is_cryptographic_asset(component)
    ]

    if not assets:
        raise ValueError("CBOM contains no cryptographic asset components.")

    return Inventory(assets=assets, dependencies=[], scenarios=[])


def import_cbom_inventory(
    input_path: str | Path,
    notices: list[str] | None = None,
) -> Inventory:
    return inventory_from_cbom(load_cbom_json(input_path), notices)


def write_imported_inventory(
    input_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool = False,
    notices: list[str] | None = None,
) -> Path:
    inventory = import_cbom_inventory(input_path, notices)
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


def _asset_from_component(
    component: dict[str, Any],
    notices: list[str],
) -> CryptographicAsset:
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

    asset_id = _normalize_asset_id(component)
    key_size_bits, cbom_key_sizes = _cbom_key_size(
        algorithm_properties,
        algorithm=str(algorithm),
        where=_component_label(component, asset_id),
        notices=notices,
    )

    return CryptographicAsset(
        id=asset_id,
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
        key_size_bits=key_size_bits,
        cbom_key_sizes=cbom_key_sizes,
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
    """Return the algorithm identifier exactly as the source states it.

    Identifiers are never built from a key size field or from digits in a
    name. A bare parameter set is used only through an explicit mapping
    (``_PARAMETER_SET_IDENTIFIERS``); any other bare number is ignored, so it
    cannot replace a full identifier stated elsewhere. A value that only
    repeats the family (``algorithm: ML-KEM`` with ``algorithmFamily:
    ML-KEM``) is not a full identifier, so the mapping still applies.
    """

    parameter_set = _string_or_none(algorithm_properties.get("parameterSetIdentifier"))
    algorithm = _string_or_none(algorithm_properties.get("algorithm"))
    family = _string_or_none(algorithm_properties.get("algorithmFamily"))
    component_name = _string_or_none(component.get("name"))

    # The family may be stated as algorithmFamily or only as algorithm.
    stated_family = family or algorithm
    for value in (parameter_set, algorithm):
        if value and _is_full_identifier(value, stated_family):
            return _normalize_cbom_algorithm_string(value, family)

    mapped = _mapped_parameter_set(stated_family, parameter_set)
    if mapped is not None:
        return mapped

    if algorithm and not algorithm.strip().isdigit():
        return _normalize_cbom_algorithm_string(algorithm, family)

    if family:
        return _normalize_cbom_algorithm_string(family, family)

    if asset_type == "protocol":
        return "unknown"

    if component_name:
        return _normalize_cbom_algorithm_string(component_name, None)

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


# Families whose bare parameterSetIdentifier names exactly one identifier.
# The CycloneDX CBOM guide uses "128" with algorithmFamily AES. A bare number
# with an RSA family is not mapped: in the same guide an RSA signature example
# carries "512", which belongs to SHA-512, not to the RSA modulus.
_PARAMETER_SET_IDENTIFIERS = {
    "ML-KEM": ("ML-KEM", frozenset({"512", "768", "1024"})),
    "ML-DSA": ("ML-DSA", frozenset({"44", "65", "87"})),
    "AES": ("AES", frozenset({"128", "192", "256"})),
}


def _identifier_key(value: str) -> str:
    # The registry's normalization, so "ML KEM", "ml_kem" and "ML-KEM" name
    # the same family here as they do in classification.
    return normalize_identifier(value)


def _is_full_identifier(value: str, family: str | None) -> bool:
    """True unless the value is a bare number or only repeats the family."""

    if value.strip().isdigit():
        return False
    return not (family and _identifier_key(value) == _identifier_key(family))


def _mapped_parameter_set(family: str | None, parameter_set: str | None) -> str | None:
    if not family or not parameter_set:
        return None
    mapping = _PARAMETER_SET_IDENTIFIERS.get(_identifier_key(family))
    if mapping is None:
        return None
    prefix, accepted = mapping
    value = parameter_set.strip()
    return f"{prefix}-{value}" if value in accepted else None


def _normalize_cbom_algorithm_string(value: str, family: str | None) -> str:
    cleaned = value.strip()
    family_cleaned = family.strip() if family else ""
    cleaned_upper = cleaned.upper().replace("_", "-")
    family_upper = family_cleaned.upper().replace("_", "-")

    if family_upper and cleaned_upper.startswith(f"{family_upper}-"):
        return cleaned

    cdxgen_aes = re.fullmatch(r"AES(128|192|256)-(CBC|GCM)", cleaned_upper)
    if cdxgen_aes:
        key_size, mode = cdxgen_aes.groups()
        return f"AES-{key_size}-{mode}"

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


def _component_label(component: dict[str, Any], asset_id: str) -> str:
    name = component.get("name")
    if isinstance(name, str) and name.strip():
        return f"CBOM component '{name}' (asset ID {asset_id})"
    return f"CBOM component with asset ID {asset_id}"


_SHOWN_VALUE_LIMIT = 40


def _shown_value(value: Any) -> str:
    """The value as JSON, shortened so one notice stays one readable line."""

    # Python refuses to write an integer with more than 4,300 digits as text,
    # so a very large integer is described instead of shown.
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            sign = "-" if value < 0 else ""
            return f"an integer beyond {sign}2^53"
    try:
        text = json.dumps(value, ensure_ascii=True)
    except (TypeError, ValueError):
        return f"a {type(value).__name__} value that cannot be shown"
    if len(text) <= _SHOWN_VALUE_LIMIT:
        return text
    return f"{text[:_SHOWN_VALUE_LIMIT]}... ({len(text)} characters)"


def _size_value(value: Any) -> int | None:
    """Return a key size in bits, or None when the value is not one.

    A size is a JSON integer, or a string of ASCII digits (leading zeros
    allowed), from 0 to 2**53 (the integer range QSTriage can write to a
    PDR). Booleans are not sizes.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        bits = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        # Check the length before int(): Python refuses to convert strings
        # longer than 4,300 digits, and such a value is never a key size.
        digits = value.lstrip("0") or "0"
        if len(digits) > len(str(MAX_SAFE_INTEGER)):
            return None
        bits = int(digits)
    else:
        return None
    return bits if 0 <= bits <= MAX_SAFE_INTEGER else None


def _cbom_key_size(
    algorithm_properties: dict[str, Any],
    *,
    algorithm: str,
    where: str,
    notices: list[str],
) -> tuple[int | None, list[dict[str, Any]] | None]:
    """Return ``key_size_bits`` and ``cbom_key_sizes`` for one component.

    Sizes come only from explicit size fields, never from a name. Fields that
    agree give ``key_size_bits``. For RSA, fields that disagree are all kept
    in ``cbom_key_sizes`` and ``key_size_bits`` stays null, so evaluation can
    report the conflict. For other algorithms the first field is kept, as
    before; only RSA sizes are compared.
    """

    stated: list[tuple[str, int]] = []
    for name in CBOM_KEY_SIZE_PROPERTIES:
        if name not in algorithm_properties or algorithm_properties[name] is None:
            continue
        raw = algorithm_properties[name]
        bits = _size_value(raw)
        if bits is None:
            notices.append(
                f"{where}: {name} is {_shown_value(raw)}, which is not a key size "
                f"(a whole number of bits from 0 to {MAX_SAFE_INTEGER}). "
                "QSTriage ignored this field. Correct it in the CBOM if the key "
                "size matters."
            )
            continue
        stated.append((name, bits))

    if not stated:
        return None, None
    if len({bits for _, bits in stated}) == 1:
        return stated[0][1], None

    listed = ", ".join(f"{name} {bits} bits" for name, bits in stated)
    if key_size_affects_score(classify_algorithm(algorithm)):
        notices.append(
            f"{where}: the size fields disagree ({listed}). QSTriage kept all of "
            "them in cbom_key_sizes and left key_size_bits empty; the decision "
            "stays gated until the CBOM states one size."
        )
        return None, [{"property": name, "bits": bits} for name, bits in stated]

    first_name, first_bits = stated[0]
    notices.append(
        f"{where}: the size fields disagree ({listed}). QSTriage compares sizes "
        f"only for RSA and kept {first_name} ({first_bits} bits). Confirm the "
        "size in the CBOM."
    )
    return first_bits, None


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
