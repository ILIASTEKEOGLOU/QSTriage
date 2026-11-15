from __future__ import annotations

import json
from importlib import resources

import pytest
from pydantic import ValidationError

from qstriage.algorithm_registry import AlgorithmRegistry, load_registry, registry_hash
from qstriage.canonical_json import canonical_sha256
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
    "tls-group-x25519mlkem768",
    "tls-group-secp256r1mlkem768",
    "tls-group-secp384r1mlkem1024",
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

    assert registry.registry_schema_version == "2"
    assert registry.registry_id == "qstriage-algorithms"
    assert registry.registry_version == "3"
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
    raw["registry_schema_version"] = "1"

    with pytest.raises(ValidationError, match="schema version"):
        AlgorithmRegistry.model_validate(raw)


# Each released registry_version identifies exactly one registry content.
# When entry content changes, increase registry_version in
# qstriage/algorithm_registry.json and add the new pair here.
REGISTRY_HASH_BY_VERSION = {
    "1": "sha256:44a93da463b6a9a0888a67bc23c0e915aa671508fba5c86d6af9c8590a629546",
    "2": "sha256:8ceb8492571aab632b89d5d203e98a15bdf8b4f99f2b0aead8674cff4696b84c",
    "3": "sha256:67a0e6d13363ca78ad69ec5c23d8cfcd68ca0b8be0363dfd2502ac94458db0d3",
}


def test_registry_content_change_requires_a_new_registry_version() -> None:
    version = load_registry().registry_version

    assert version in REGISTRY_HASH_BY_VERSION, (
        f"registry_version {version!r} has no recorded hash"
    )
    assert registry_hash() == REGISTRY_HASH_BY_VERSION[version], (
        "Registry content changed without a new registry_version"
    )


def _hybrid_raw(**changes: object) -> dict[str, object]:
    return _with_entry_change("tls-group-x25519mlkem768", **changes)


def test_hybrid_certification_component_must_be_a_component() -> None:
    raw = _hybrid_raw(certification_component="X448")

    with pytest.raises(ValidationError, match="certification_component"):
        AlgorithmRegistry.model_validate(raw)


def test_hybrid_components_must_not_repeat() -> None:
    raw = _hybrid_raw(components=["ML-KEM-768", "ML-KEM-768"])

    with pytest.raises(ValidationError, match="repeats a component"):
        AlgorithmRegistry.model_validate(raw)


def test_identifiers_are_unique_after_normalization() -> None:
    raw = _with_entry_change("unknown", identifiers=["x25519mlkem768"])

    with pytest.raises(ValidationError, match="appears in registry entries"):
        AlgorithmRegistry.model_validate(raw)


def test_empty_excerpt_is_rejected() -> None:
    raw = _raw_registry()
    raw["entries"][0]["sources"][0]["excerpt"] = ""

    with pytest.raises(ValidationError):
        AlgorithmRegistry.model_validate(raw)


def test_source_ids_are_listed_once_in_first_seen_order() -> None:
    entry = load_registry().entry("tls-group-x25519mlkem768")

    assert entry.source_ids == ("RFC-10024", "NIST-SP-800-227", "NIST-FIPS-203")


# Registry version 3 changes only the NIST IR 8547 source of these four
# entries, from the November 2024 initial public draft to the October 2026
# final publication (docs/standards-and-classification.md, "NIST IR 8547
# source update").
IR_8547_FINAL_SECTIONS = {
    "classical-public-key-composite": "Sections 2.1.1 and 2.1.2",
    "rsa": "Sections 2.1.1 and 2.1.2",
    "dh": "Section 2.1.2",
    "ecc": "Sections 2.1.1 and 2.1.2",
}
IR_8547_DRAFT_SOURCE = {
    "source_id": "NIST-IR-8547-IPD",
    "title": "Transition to Post-Quantum Cryptography Standards (Initial Public Draft)",
    "section": None,
    "status": "draft",
    "date": "2024-11",
    "excerpt": None,
}


def test_ir_8547_source_is_the_final_publication_in_exactly_four_entries() -> None:
    raw = _raw_registry()
    cited = {
        entry["entry_id"]: source
        for entry in raw["entries"]
        for source in entry["sources"]
        if source["source_id"].startswith("NIST-IR-8547")
    }

    assert set(cited) == set(IR_8547_FINAL_SECTIONS)
    for entry_id, section in IR_8547_FINAL_SECTIONS.items():
        assert cited[entry_id] == {
            "source_id": "NIST-IR-8547",
            "title": "Transition to Post-Quantum Cryptography Standards",
            "section": section,
            "status": "final",
            "date": "2026-10",
            "excerpt": None,
        }


def test_registry_version_3_differs_from_version_2_only_in_the_ir_8547_source() -> None:
    # Restoring the draft source and the version number must give back the
    # exact version 2 content, so nothing else in the registry changed.
    raw = _raw_registry()
    raw["registry_version"] = "2"
    for entry in raw["entries"]:
        if entry["entry_id"] in IR_8547_FINAL_SECTIONS:
            [index] = [
                i
                for i, source in enumerate(entry["sources"])
                if source["source_id"] == "NIST-IR-8547"
            ]
            entry["sources"][index] = dict(IR_8547_DRAFT_SOURCE)

    assert canonical_sha256(raw) == REGISTRY_HASH_BY_VERSION["2"]
