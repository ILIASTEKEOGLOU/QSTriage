from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from qstriage.standards import classify_algorithm


SNAPSHOT = Path(__file__).parent / "fixtures" / "classification_snapshot.json"
CASES = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["cases"]


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
    actual = dataclasses.asdict(classify_algorithm(case["input"]))
    actual["source_ids"] = list(actual["source_ids"])

    assert actual == case["classification"]
