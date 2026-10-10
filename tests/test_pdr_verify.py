from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import qstriage.pdr as pdr_module
from qstriage.algorithm_registry import (
    RegistryLoadError,
    _object_without_duplicate_keys,
    load_registry,
    registry_hash,
)
from qstriage.canonical_json import CanonicalizationError, canonical_sha256
from qstriage.cli import app
from qstriage.limits import MAX_PDR_FILE_BYTES
from qstriage.models import load_inventory
from qstriage.pdr import InputSnapshot, _hash_object, generate_pdr_document
from qstriage.pdr_verify import (
    PDRVerificationInputError,
    pdr_v0_2_hash,
    verify_pdr_document,
    verify_pdr_file,
    verify_pdr_text,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_inventory.yaml"
REGISTRY_FILE = ROOT / "qstriage" / "algorithm_registry.json"
# Generated from examples/sample_inventory.yaml by QSTriage 1.3.0 plus the
# pdr verify change, before the PDR 0.3 contract. It must keep verifying.
V0_2_FIXTURE = ROOT / "tests" / "fixtures" / "pdr_v0_2_sample.json"


def _document() -> dict[str, object]:
    return generate_pdr_document(load_inventory(SAMPLE)).model_dump(mode="json")


def _failed(result) -> set[tuple[str, str]]:
    return {(check.check, check.subject) for check in result.checks if not check.passed}


def test_generated_document_passes_every_check() -> None:
    document = _document()
    result = verify_pdr_document(document)

    assert result.passed
    assert result.pdr_version == "0.3"
    record_checks = [check for check in result.checks if check.check == "record_hash"]
    assert len(record_checks) == len(document["records"])
    registry_checks = [
        check
        for check in result.checks
        if check.check == "record_registry_context_matches_document"
    ]
    assert len(registry_checks) == len(document["records"])


def test_v0_2_document_from_the_previous_generator_still_verifies() -> None:
    document = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    result = verify_pdr_document(document)

    assert document["pdr_version"] == "0.2"
    assert "registry_context" not in document
    assert result.passed
    assert len(result.checks) == 2 + 5 * len(document["records"])


def test_v0_2_document_tampering_is_still_detected() -> None:
    document = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    record = document["records"][0]
    record["decision"]["action_type"] = "retain_monitor"

    failed = _failed(verify_pdr_document(document))

    assert ("record_hash", record["record_id"]) in failed
    assert ("document_hash", "document") in failed


def test_generator_hashes_under_rfc8785_not_the_v0_2_rule() -> None:
    document = _document()

    assert _hash_object(document) == canonical_sha256(document)
    # The document contains floats such as 81.0, which the two rules
    # serialize differently, so the hashes must differ.
    assert _hash_object(document) != pdr_v0_2_hash(document)


def test_registry_context_records_the_bundled_registry() -> None:
    document = _document()
    registry = load_registry()

    assert document["registry_context"] == {
        "registry_id": registry.registry_id,
        "registry_version": registry.registry_version,
        "registry_hash": registry_hash(),
    }
    assert all(
        record["registry_context"] == document["registry_context"]
        for record in document["records"]
    )


def test_registry_hash_is_rfc8785_hash_of_the_registry_file_data() -> None:
    data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))

    assert registry_hash() == canonical_sha256(data)


def test_different_registry_hash_gives_different_run_id(monkeypatch) -> None:
    original = _document()
    monkeypatch.setattr(pdr_module, "registry_hash", lambda: "sha256:" + "1" * 64)
    changed = _document()

    assert changed["registry_context"]["registry_hash"] == "sha256:" + "1" * 64
    assert changed["run_id"] != original["run_id"]
    assert verify_pdr_document(changed).passed


def test_altered_registry_context_fails_hash_run_id_and_record_consistency() -> None:
    document = _document()
    document["registry_context"]["registry_hash"] = "sha256:" + "0" * 64

    failed = _failed(verify_pdr_document(document))

    assert ("document_hash", "document") in failed
    assert ("run_id", "document") in failed
    first = document["records"][0]["record_id"]
    assert ("record_registry_context_matches_document", first) in failed


def test_v0_3_document_without_registry_context_is_rejected() -> None:
    document = _document()
    del document["registry_context"]

    with pytest.raises(PDRVerificationInputError, match="registry_context"):
        verify_pdr_document(document)


def test_observed_state_reports_scheme_fields() -> None:
    observed = _document()["records"][0]["observed_state"]

    assert observed["scheme_type"] == "single"
    assert observed["components"] == []
    assert observed["certification_component"] is None


def test_value_outside_rfc8785_range_stops_generation() -> None:
    inventory = load_inventory(SAMPLE)
    asset = inventory.assets[0].model_copy(update={"key_size_bits": 2**60})
    inventory = inventory.model_copy(update={"assets": [asset, *inventory.assets[1:]]})

    with pytest.raises(CanonicalizationError):
        generate_pdr_document(inventory)


def test_altered_record_field_fails_record_and_document_hash() -> None:
    document = _document()
    record = document["records"][0]
    record["decision"]["action_type"] = "retain_monitor"

    failed = _failed(verify_pdr_document(document))

    assert ("record_hash", record["record_id"]) in failed
    assert ("document_hash", "document") in failed


def test_altered_document_provenance_fails_hash_run_id_and_record_consistency() -> None:
    document = _document()
    document["policy_context"]["policy_pack_hash"] = "sha256:" + "0" * 64

    failed = _failed(verify_pdr_document(document))

    assert ("document_hash", "document") in failed
    assert ("run_id", "document") in failed
    first = document["records"][0]["record_id"]
    assert ("record_policy_context_matches_document", first) in failed


def test_replaced_record_hash_is_detected() -> None:
    document = _document()
    record = document["records"][1]
    record["record_integrity"]["record_hash"] = "sha256:" + "f" * 64

    failed = _failed(verify_pdr_document(document))

    assert ("record_hash", record["record_id"]) in failed


def test_duplicate_json_key_is_rejected() -> None:
    with pytest.raises(PDRVerificationInputError, match="duplicate key"):
        verify_pdr_text('{"pdr_version":"0.2","pdr_version":"0.2"}')


def test_non_finite_number_is_rejected() -> None:
    with pytest.raises(PDRVerificationInputError, match="non-finite"):
        verify_pdr_text('{"pdr_version":"0.2","value":NaN}')


def test_unsupported_version_is_rejected() -> None:
    document = _document()
    document["pdr_version"] = "9.9"

    with pytest.raises(PDRVerificationInputError, match="Unsupported PDR version"):
        verify_pdr_document(document)


def test_missing_field_is_rejected() -> None:
    document = _document()
    del document["records"]

    with pytest.raises(PDRVerificationInputError, match="records"):
        verify_pdr_document(document)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    with path.open("wb") as file:
        file.truncate(MAX_PDR_FILE_BYTES + 1)

    with pytest.raises(PDRVerificationInputError, match="size limit"):
        verify_pdr_file(path)


def test_cli_verify_pass_and_fail(tmp_path: Path) -> None:
    runner = CliRunner()
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_document(), indent=2), encoding="utf-8")

    passed = runner.invoke(app, ["pdr", "verify", str(good)])
    assert passed.exit_code == 0
    assert "PDR verification: PASS" in passed.output

    document = _document()
    document["records"][0]["decision"]["confidence_score"] = 0.0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(document, indent=2), encoding="utf-8")

    failed = runner.invoke(app, ["pdr", "verify", str(bad)])
    assert failed.exit_code == 1
    assert "PDR verification: FAIL" in failed.output
    assert "record_hash" in failed.output


def test_cli_verify_json_output(tmp_path: Path) -> None:
    path = tmp_path / "good.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    result = CliRunner().invoke(app, ["pdr", "verify", str(path), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["passed"] is True
    assert payload["pdr_version"] == "0.3"


def test_cli_verify_rejects_unknown_format(tmp_path: Path) -> None:
    path = tmp_path / "good.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    result = CliRunner().invoke(app, ["pdr", "verify", str(path), "--format", "xml"])

    assert result.exit_code == 2


def test_cli_verify_does_not_modify_the_input(tmp_path: Path) -> None:
    path = tmp_path / "good.json"
    path.write_text(json.dumps(_document(), indent=2), encoding="utf-8")
    before = path.read_bytes()

    CliRunner().invoke(app, ["pdr", "verify", str(path)])

    assert path.read_bytes() == before


def test_cli_generate_stops_on_value_outside_rfc8785_range(tmp_path: Path) -> None:
    text = SAMPLE.read_text(encoding="utf-8")
    source = tmp_path / "inventory.yaml"
    source.write_text(
        text.replace("key_size_bits: 2048", f"key_size_bits: {2**60}", 1),
        encoding="utf-8",
    )
    assert str(2**60) in source.read_text(encoding="utf-8")
    output = tmp_path / "pdr.json"

    result = CliRunner().invoke(
        app, ["pdr", "generate", str(source), "--output", str(output)]
    )

    assert result.exit_code == 1
    assert "PDR generation failed" in result.output
    assert not output.exists()


def test_registry_reader_rejects_duplicate_keys() -> None:
    with pytest.raises(RegistryLoadError, match="duplicate key"):
        json.loads(
            '{"registry_id":"a","registry_id":"b"}',
            object_pairs_hook=_object_without_duplicate_keys,
        )


def test_decisions_for_sample_inventory_are_unchanged_since_v0_2() -> None:
    before = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    # Reuse the snapshot recorded in the fixture. A file-backed snapshot
    # hashes the bytes on disk, which differ when a checkout uses CRLF line
    # endings; the parsed inventory does not.
    after = generate_pdr_document(
        load_inventory(SAMPLE),
        input_snapshot=InputSnapshot(**before["input_snapshot"]),
    ).model_dump(mode="json")
    # Fields that identify the contract, engine, registry, or policy pack.
    # The sample inventory has no PQ/T hybrid asset, so the policy pack 0.3
    # rule does not apply and every decision field must be unchanged.
    provenance_fields = {
        "pdr_version",
        "run_id",
        "registry_context",
        "engine",
        "policy_context",
        "record_integrity",
    }
    scheme_fields = {"scheme_type", "components", "certification_component"}
    policy_identity = {"policy_pack_version", "policy_pack_hash", "standards_applied"}

    assert after["input_snapshot"] == before["input_snapshot"]
    assert len(after["records"]) == len(before["records"])
    for old, new in zip(before["records"], after["records"]):
        old_rest = {k: v for k, v in old.items() if k not in provenance_fields}
        new_rest = {k: v for k, v in new.items() if k not in provenance_fields}
        new_rest["observed_state"] = {
            k: v for k, v in new_rest["observed_state"].items() if k not in scheme_fields
        }
        for rest in (old_rest, new_rest):
            rest["policy_evaluation"] = {
                k: v
                for k, v in rest["policy_evaluation"].items()
                if k not in policy_identity
            }
        assert new_rest == old_rest
