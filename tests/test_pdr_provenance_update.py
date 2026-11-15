"""Registry 3 and policy pack 0.5 change provenance only.

The baseline PDR in ``fixtures/pdr_registry_2`` was generated from the
inventory next to it by the code at fb87568 (registry 2, policy pack 0.4).
A PDR generated now from the same input must keep every decision, observed
value, and identifier, and may differ only in the provenance fields listed
below and in the hashes and run IDs that depend on them.
"""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage.cli import app
from qstriage.models import CryptographicAsset, load_inventory
from qstriage.pdr import _target_state_suggestions, generate_pdr_document
from qstriage.pdr_verify import verify_pdr_file
from qstriage.standards import classify_algorithm


FIXTURES = Path(__file__).parent / "fixtures" / "pdr_registry_2"
INVENTORY = FIXTURES / "inventory.yaml"
BASELINE = FIXTURES / "baseline.pdr.json"

OLD_ID = "NIST-IR-8547-IPD"
NEW_ID = "NIST-IR-8547"
REGISTRY_2_HASH = "sha256:8ceb8492571aab632b89d5d203e98a15bdf8b4f99f2b0aead8674cff4696b84c"
REGISTRY_3_HASH = "sha256:67a0e6d13363ca78ad69ec5c23d8cfcd68ca0b8be0363dfd2502ac94458db0d3"
PACK_0_4_HASH = "sha256:c39286db56036c5d82118c6e135bc63477d508d0607952ad5077450e4708a639"
PACK_0_5_HASH = "sha256:488598e4c831135d815d7a3ec5f46a66785edfaaba1950c10d19410c1e348fc0"

# Generalized leaf paths ("[]" for any list index) and the change allowed.
VALUE_CHANGES = {
    ".policy_context.policy_pack_version": ("0.4", "0.5"),
    ".records[].policy_context.policy_pack_version": ("0.4", "0.5"),
    ".records[].policy_evaluation.policy_pack_version": ("0.4", "0.5"),
    ".policy_context.policy_pack_hash": (PACK_0_4_HASH, PACK_0_5_HASH),
    ".records[].policy_context.policy_pack_hash": (PACK_0_4_HASH, PACK_0_5_HASH),
    ".records[].policy_evaluation.policy_pack_hash": (PACK_0_4_HASH, PACK_0_5_HASH),
    ".registry_context.registry_version": ("2", "3"),
    ".records[].registry_context.registry_version": ("2", "3"),
    ".registry_context.registry_hash": (REGISTRY_2_HASH, REGISTRY_3_HASH),
    ".records[].registry_context.registry_hash": (REGISTRY_2_HASH, REGISTRY_3_HASH),
    ".policy_context.standards_applied[]": (OLD_ID, NEW_ID),
    ".records[].policy_context.standards_applied[]": (OLD_ID, NEW_ID),
    ".records[].policy_evaluation.standards_applied[]": (OLD_ID, NEW_ID),
    ".records[].policy_evaluation.findings[].standards_applied[]": (OLD_ID, NEW_ID),
    ".records[].target_state_suggestion[].standards[]": (OLD_ID, NEW_ID),
}
# Derived from the provenance above; any new value is allowed.
DERIVED_CHANGES = {
    ".run_id",
    ".records[].run_id",
    ".records[].record_integrity.record_hash",
    ".document_hash",
}


def _leaves(old: object, new: object, path: str = ""):
    if isinstance(old, dict) and isinstance(new, dict):
        assert old.keys() == new.keys(), path
        for key in old:
            yield from _leaves(old[key], new[key], f"{path}.{key}")
    elif isinstance(old, list) and isinstance(new, list):
        assert len(old) == len(new), path
        for index, (a, b) in enumerate(zip(old, new)):
            yield from _leaves(a, b, f"{path}[{index}]")
    elif old != new:
        yield path, old, new


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _candidate() -> dict:
    # Hash the inventory bytes on disk, so a change to the fixture shows up as
    # a different source hash instead of reusing the baseline snapshot.
    return generate_pdr_document(
        load_inventory(INVENTORY), source_path=INVENTORY
    ).model_dump(mode="json")


def test_baseline_pdr_is_the_registry_2_policy_0_4_record_and_still_verifies() -> None:
    baseline = _baseline()

    assert baseline["registry_context"]["registry_version"] == "2"
    assert baseline["registry_context"]["registry_hash"] == REGISTRY_2_HASH
    assert baseline["policy_context"]["policy_pack_version"] == "0.4"
    assert baseline["policy_context"]["policy_pack_hash"] == PACK_0_4_HASH
    assert verify_pdr_file(BASELINE).passed


def test_new_pdr_differs_from_the_baseline_only_in_provenance(tmp_path: Path) -> None:
    baseline = _baseline()
    candidate = _candidate()
    seen: set[str] = set()

    for path, old, new in _leaves(baseline, candidate):
        general = re.sub(r"\[\d+\]", "[]", path)
        seen.add(general)
        if general in DERIVED_CHANGES:
            continue
        assert general in VALUE_CHANGES, f"unexpected change at {path}: {old!r} -> {new!r}"
        assert (old, new) == VALUE_CHANGES[general], path

    # Both identities and the source ID are visible in the new record.
    assert {
        ".registry_context.registry_version",
        ".policy_context.policy_pack_version",
        ".records[].policy_evaluation.findings[].standards_applied[]",
        ".document_hash",
    } <= seen

    output = tmp_path / "candidate.json"
    output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    assert verify_pdr_file(output).passed


def test_new_pdr_keeps_inputs_identifiers_and_decisions() -> None:
    baseline = _baseline()
    candidate = _candidate()

    assert candidate["input_snapshot"] == baseline["input_snapshot"]
    for old, new in zip(baseline["records"], candidate["records"], strict=True):
        for field in (
            "record_id",
            "lineage_id",
            "sequence_number",
            "observed_state",
            "evidence_quality",
            "evidence_review",
            "decision_confidence",
            "mission_context",
            "tradeoffs",
            "decision",
            "assumptions_made",
        ):
            assert new[field] == old[field], (old["record_id"], field)
        for name in ("applied_rule_ids", "thresholds_applied"):
            assert new["policy_evaluation"][name] == old["policy_evaluation"][name]
        for old_option, new_option in zip(
            old["target_state_suggestion"], new["target_state_suggestion"], strict=True
        ):
            for name in ("option", "rationale", "operational_risk", "requires_human_review"):
                assert new_option[name] == old_option[name]


def test_new_pdr_generation_is_deterministic() -> None:
    first = _candidate()
    second = _candidate()

    assert first == second
    assert first["document_hash"] != _baseline()["document_hash"]


def test_cli_pdr_uses_registry_3_and_policy_pack_0_5_by_default(tmp_path: Path) -> None:
    output = tmp_path / "pdr.json"
    result = CliRunner().invoke(
        app, ["pdr", "generate", str(INVENTORY), "--output", str(output)]
    )

    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["policy_context"]["policy_pack_version"] == "0.5"
    assert document["policy_context"]["policy_pack_hash"] == PACK_0_5_HASH
    assert document["registry_context"]["registry_version"] == "3"
    assert document["registry_context"]["registry_hash"] == REGISTRY_3_HASH
    assert OLD_ID not in output.read_text(encoding="utf-8")
    assert verify_pdr_file(output).passed


def test_explicit_request_for_policy_pack_0_4_is_refused() -> None:
    with pytest.raises(ValueError, match="requested 0.4, available 0.5"):
        generate_pdr_document(load_inventory(INVENTORY), policy_pack_version="0.4")


@pytest.mark.parametrize(
    ("section", "field", "old_value"),
    [
        ("registry_context", "registry_hash", REGISTRY_2_HASH),
        ("policy_context", "policy_pack_hash", PACK_0_4_HASH),
    ],
)
def test_restoring_an_old_identity_without_integrity_data_fails(
    tmp_path: Path, section: str, field: str, old_value: str
) -> None:
    document = _candidate()
    document[section][field] = old_value
    output = tmp_path / "tampered.json"
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    assert not verify_pdr_file(output).passed


def test_manual_target_selection_cites_the_final_ir_8547() -> None:
    # No registry entry reaches this fallback today: every quantum-vulnerable
    # entry has a primitive containing "key". The classification is changed
    # here so the fallback runs and its standard can be checked.
    classification = dataclasses.replace(
        classify_algorithm("DH"), primitive="unspecified"
    )
    asset = CryptographicAsset(
        id="manual-target",
        name="Manual target",
        environment="production",
        asset_type="service",
        protocol="custom",
        algorithm="DH",
        key_size_bits=2048,
        data_class="customer_pii",
        retention_years=10,
        exposure="internal",
        criticality="high",
        local_blast_radius="medium",
        migration_effort="medium",
    )

    [suggestion] = _target_state_suggestions(asset, classification)

    assert suggestion.option == "manual_pqc_target_selection"
    assert suggestion.standards == [NEW_ID]
