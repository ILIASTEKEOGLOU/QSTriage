from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage.cli import app
from qstriage.limits import MAX_PDR_FILE_BYTES
from qstriage.models import load_inventory
from qstriage.pdr import _hash_object, generate_pdr_document
from qstriage.pdr_verify import (
    PDRVerificationInputError,
    pdr_v0_2_hash,
    verify_pdr_document,
    verify_pdr_file,
    verify_pdr_text,
)


SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample_inventory.yaml"


def _document() -> dict[str, object]:
    return generate_pdr_document(load_inventory(SAMPLE)).model_dump(mode="json")


def _failed(result) -> set[tuple[str, str]]:
    return {(check.check, check.subject) for check in result.checks if not check.passed}


def test_generated_document_passes_every_check() -> None:
    document = _document()
    result = verify_pdr_document(document)

    assert result.passed
    assert result.pdr_version == "0.2"
    record_checks = [check for check in result.checks if check.check == "record_hash"]
    assert len(record_checks) == len(document["records"])


def test_frozen_v0_2_hash_matches_the_generator() -> None:
    document = _document()

    assert pdr_v0_2_hash(document) == _hash_object(document)


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
    assert payload["pdr_version"] == "0.2"


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
