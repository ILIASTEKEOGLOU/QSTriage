from __future__ import annotations

import json
from importlib import resources

import pytest
from pydantic import ValidationError

from qstriage.algorithm_registry import AlgorithmRegistry, load_registry
from qstriage.standards import (
    ML_DSA_PARAMETER_SETS,
    ML_KEM_PARAMETER_SETS,
    SLH_DSA_PARAMETER_SETS,
    classify_algorithm,
)


EXPECTED_ENTRY_IDS = {
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
    "ml-kem-family-unverified",
    "ml-dsa-family-unverified",
    "slh-dsa-family-unverified",
    "classical-public-key-composite",
    "rsa",
    "dh",
    "ecc",
    "aes",
    "sha3",
    "sha1-sha2",
    "unknown",
}


def _raw_registry() -> dict[str, object]:
    text = (
        resources.files("qstriage")
        .joinpath("algorithm_registry.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(text)


def test_bundled_registry_loads_with_expected_identity() -> None:
    registry = load_registry()

    assert registry.registry_schema_version == "1"
    assert registry.registry_id == "qstriage-algorithms"
    assert registry.registry_version == "1"
    assert registry.signatures == ()
    assert {entry.entry_id for entry in registry.entries} == EXPECTED_ENTRY_IDS


def test_registry_pqc_identifiers_match_parameter_set_constants() -> None:
    registry = load_registry()

    assert set(registry.entry("ml-kem").identifiers) == {
        f"ML-KEM-{value}" for value in ML_KEM_PARAMETER_SETS
    }
    assert set(registry.entry("ml-dsa").identifiers) == {
        f"ML-DSA-{value}" for value in ML_DSA_PARAMETER_SETS
    }
    assert set(registry.entry("slh-dsa").identifiers) == {
        f"SLH-DSA-{value}" for value in SLH_DSA_PARAMETER_SETS
    }


def test_every_listed_identifier_resolves_to_its_entry() -> None:
    for entry in load_registry().entries:
        for identifier in entry.identifiers:
            classification = classify_algorithm(identifier)
            assert classification.algorithm_family == entry.algorithm_family
            assert classification.identifier_resolution == entry.identifier_resolution
            assert classification.source_ids == entry.source_ids


def test_positive_entries_have_a_final_source() -> None:
    for entry in load_registry().entries:
        if entry.is_positive:
            assert any(source.status.value == "final" for source in entry.sources)


def _with_entry_change(entry_id: str, **changes: object) -> dict[str, object]:
    raw = _raw_registry()
    for entry in raw["entries"]:
        if entry["entry_id"] == entry_id:
            entry.update(changes)
    return raw


def test_positive_entry_with_only_draft_sources_is_rejected() -> None:
    raw = _raw_registry()
    for entry in raw["entries"]:
        if entry["entry_id"] == "ml-kem":
            for source in entry["sources"]:
                source["status"] = "draft"

    with pytest.raises(ValidationError, match="without a final published source"):
        AlgorithmRegistry.model_validate(raw)


def test_positive_entry_with_draft_lifecycle_is_rejected() -> None:
    raw = _with_entry_change("ml-kem", lifecycle="draft")

    with pytest.raises(ValidationError, match="is not published"):
        AlgorithmRegistry.model_validate(raw)


def test_duplicate_identifier_across_entries_is_rejected() -> None:
    raw = _with_entry_change("ml-dsa", identifiers=["ML-KEM-768"])

    with pytest.raises(ValidationError, match="appears in registry entries"):
        AlgorithmRegistry.model_validate(raw)


def test_single_scheme_with_components_is_rejected() -> None:
    raw = _with_entry_change("rsa", components=["ecc", "ml-kem"])

    with pytest.raises(ValidationError, match="single scheme"):
        AlgorithmRegistry.model_validate(raw)


def test_unknown_registry_field_is_rejected() -> None:
    raw = _raw_registry()
    raw["unexpected"] = True

    with pytest.raises(ValidationError):
        AlgorithmRegistry.model_validate(raw)


def test_unsupported_schema_version_is_rejected() -> None:
    raw = _raw_registry()
    raw["registry_schema_version"] = "2"

    with pytest.raises(ValidationError, match="schema version"):
        AlgorithmRegistry.model_validate(raw)
