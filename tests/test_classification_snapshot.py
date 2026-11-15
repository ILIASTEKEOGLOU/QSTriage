from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from qstriage.standards import classify_algorithm


SNAPSHOT = Path(__file__).parent / "fixtures" / "classification_snapshot.json"
CASES = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["cases"]

# Fields added after the snapshot was pinned. They are checked separately so
# that the pinned fixture stays byte-identical.
ADDED_FIELDS = (
    "scheme_type",
    "components",
    "certification_component",
    "registry_entry_id",
)

# Registry version 2 adds the RFC 10024 hybrid groups. These pinned inputs are
# their exact names and are the only intended changes; every other pinned
# input must keep its version 1 classification.
INTENDED_CHANGES = {
    "X25519MLKEM768": (
        "tls-group-x25519mlkem768",
        ("ML-KEM-768", "X25519"),
        "ML-KEM-768",
    ),
    "SecP256r1MLKEM768": (
        "tls-group-secp256r1mlkem768",
        ("secp256r1", "ML-KEM-768"),
        "secp256r1",
    ),
    "SecP384r1MLKEM1024": (
        "tls-group-secp384r1mlkem1024",
        ("secp384r1", "ML-KEM-1024"),
        "secp384r1",
    ),
}


# Registry version 3 cites the final NIST IR 8547 instead of its initial public
# draft in the four classical public-key entries. For inputs classified by
# those entries the pinned source ID is replaced by the final one; every other
# field, and every other input, keeps its pinned value.
SOURCE_ID_MIGRATION = {"NIST-IR-8547-IPD": "NIST-IR-8547"}
MIGRATED_ENTRY_IDS = {"classical-public-key-composite", "rsa", "dh", "ecc"}


def _expected(case: dict[str, object]) -> dict[str, object]:
    expected = dict(case["classification"])
    expected["source_ids"] = [
        SOURCE_ID_MIGRATION.get(source_id, source_id)
        for source_id in expected["source_ids"]
    ]
    return expected


def test_snapshot_covers_every_classification_outcome() -> None:
    families = {case["classification"]["algorithm_family"] for case in CASES}
    resolutions = {case["classification"]["identifier_resolution"] for case in CASES}

    assert {
        "ML-KEM",
        "ML-DSA",
        "SLH-DSA",
        "classical_public_key_composite",
        "RSA",
        "DH",
        "ECC",
        "AES",
        "SHA-3",
        "SHA-1/SHA-2",
        "unknown",
    } <= families
    assert resolutions == {
        "exact_identifier",
        "recognized_family_unverified_parameters",
        "unrecognized_identifier",
    }


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[repr(case["input"]) for case in CASES],
)
def test_classification_matches_pinned_snapshot(case: dict[str, object]) -> None:
    if case["input"] in INTENDED_CHANGES:
        pytest.skip("Intended change, checked by test_intended_changes_only")
    actual = dataclasses.asdict(classify_algorithm(case["input"]))
    actual["source_ids"] = list(actual["source_ids"])
    added = {key: actual.pop(key) for key in ADDED_FIELDS}

    assert actual == _expected(case)
    migrated = actual["source_ids"] != case["classification"]["source_ids"]
    assert migrated == (added["registry_entry_id"] in MIGRATED_ENTRY_IDS)
    assert added["scheme_type"] == "single"
    assert added["components"] == ()
    assert added["certification_component"] is None


def test_intended_changes_are_pinned_inputs_that_were_unknown() -> None:
    pinned = {case["input"]: case["classification"] for case in CASES}

    for name in INTENDED_CHANGES:
        assert pinned[name]["algorithm_family"] == "unknown"


@pytest.mark.parametrize("name", sorted(INTENDED_CHANGES))
def test_intended_changes_only(name: str) -> None:
    entry_id, components, certification = INTENDED_CHANGES[name]
    actual = classify_algorithm(name)

    assert actual.registry_entry_id == entry_id
    assert actual.algorithm_family == "pq_t_hybrid_kem"
    assert actual.quantum_status == "quantum_resistant"
    assert actual.standard_status == "standardized_pq_t_hybrid"
    assert actual.scheme_type == "pq_t_hybrid"
    assert actual.components == components
    assert actual.certification_component == certification


def test_source_id_migration_covers_exactly_the_four_classical_entries() -> None:
    migrated_entries = set()
    for case in CASES:
        if case["input"] in INTENDED_CHANGES:
            continue
        pinned = case["classification"]["source_ids"]
        actual = classify_algorithm(case["input"])
        if "NIST-IR-8547-IPD" in pinned:
            assert pinned == ["NIST-IR-8547-IPD"]
            assert actual.source_ids == ("NIST-IR-8547",)
            migrated_entries.add(actual.registry_entry_id)
        else:
            assert "NIST-IR-8547" not in actual.source_ids

    assert migrated_entries == MIGRATED_ENTRY_IDS
