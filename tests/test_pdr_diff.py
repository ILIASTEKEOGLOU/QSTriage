from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage.cli import app
from qstriage.models import load_inventory
from qstriage.pdr import generate_pdr_document
from qstriage.pdr_diff import (
    MULTIPLE_CAUSES_TEXT,
    PDRDiffError,
    diff_pdr_files,
    render_markdown,
    to_dict,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_inventory.yaml"
V0_2_FIXTURE = ROOT / "tests" / "fixtures" / "pdr_v0_2_sample.json"


def _write_pdr(path: Path, inventory_text: str) -> Path:
    source = path.with_suffix(".yaml")
    source.write_text(inventory_text, encoding="utf-8")
    document = generate_pdr_document(load_inventory(source))
    path.write_text(json.dumps(document.model_dump(mode="json"), indent=2), encoding="utf-8")
    return path


def _sample_text() -> str:
    return SAMPLE.read_text(encoding="utf-8")


def _hybrid_text() -> str:
    text = _sample_text()
    assert "algorithm: ECDHE_RSA" in text
    return text.replace("algorithm: ECDHE_RSA", "algorithm: X25519MLKEM768")


def test_identical_documents_have_no_changes(tmp_path: Path) -> None:
    path = _write_pdr(tmp_path / "a.json", _sample_text())

    diff = diff_pdr_files(path, path)
    text = render_markdown(diff)

    assert not diff.has_changes
    assert "0 of 5 decisions changed. 0 records were added. 0 records were removed." in text
    assert "None of these changed." in text
    assert "## Decisions that changed" not in text
    assert "## Field details" not in text


def test_single_input_change_is_attributed_to_that_input(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())

    diff = diff_pdr_files(before, after)
    text = render_markdown(diff)

    assert [item.key for item in diff.changed_provenance] == ["input"]
    assert "- Input file: changed." in text
    assert "Only one of these changed: Input file." in text
    assert "2 of 5 decisions changed." in text


def test_changed_decision_is_described_in_plain_lines(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())

    text = render_markdown(diff_pdr_files(before, after))

    assert "### Public API Gateway (pdr:public-api-gateway)" in text
    assert "- Action: migration\\_planning -> retain\\_monitor" in text
    assert (
        "- Algorithm status: classical\\_public\\_key -> standardized\\_pq\\_t\\_hybrid"
        in text
    )
    assert "- Human review: required before; required after." in text
    assert "Reason codes after: classification:standardized\\_pq\\_t\\_hybrid" in text
    assert "| pdr:public-api-gateway | decision.action\\_type | migration\\_planning | retain\\_monitor |" in text


def test_v0_2_to_v0_3_reports_format_differences_and_multiple_causes(tmp_path: Path) -> None:
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())

    diff = diff_pdr_files(V0_2_FIXTURE, after)
    text = render_markdown(diff)

    assert diff.format_differences == (
        "observed_state.certification_component",
        "observed_state.components",
        "observed_state.scheme_type",
        "registry_context",
    )
    assert "## Format differences (not decision changes)" in text
    assert (
        "PDR 0.3 records fields that PDR 0.2 does not have. They are listed here so "
        "they are not mistaken for decision changes:"
    ) in text
    assert "- Policy pack: changed (nist-pqc-basic 0.2 -> 0.3)." in text
    assert "- Algorithm registry: changed (not recorded in PDR 0.2 -> version 2)." in text
    assert "- PDR format: changed (0.2 -> 0.3)." in text
    assert MULTIPLE_CAUSES_TEXT in text
    for change in diff.changed:
        assert all(not item.field.endswith(("scheme_type", "components")) for item in change.changes)


def test_v0_3_to_v0_2_reports_fields_missing_from_the_later_document(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())

    text = render_markdown(diff_pdr_files(before, V0_2_FIXTURE))

    assert (
        "PDR 0.3 records fields that PDR 0.2 does not have. They are listed here so "
        "they are not mistaken for decision changes:"
    ) in text


def test_added_and_removed_records_are_listed(tmp_path: Path) -> None:
    text = _sample_text()
    before = _write_pdr(tmp_path / "before.json", text)
    renamed = _write_pdr(
        tmp_path / "after.json",
        text.replace("public-api-gateway", "edge-gateway"),
    )

    diff = diff_pdr_files(before, renamed)
    rendered = render_markdown(diff)

    assert [record["record_id"] for record in diff.added] == ["pdr:edge-gateway"]
    assert [record["record_id"] for record in diff.removed] == ["pdr:public-api-gateway"]
    assert "1 record was added. 1 record was removed." in rendered
    assert "## Records added" in rendered
    assert "- Public API Gateway (pdr:edge-gateway): action migration\\_planning" in rendered


def test_tampered_document_is_refused(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    tampered = tmp_path / "tampered.json"
    data = json.loads(before.read_text(encoding="utf-8"))
    data["records"][0]["decision"]["action_type"] = "retain_monitor"
    tampered.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PDRDiffError, match="After file failed integrity verification"):
        diff_pdr_files(before, tampered)


def test_duplicate_record_id_is_refused(tmp_path: Path) -> None:
    from qstriage.pdr_diff import diff_pdr_documents
    from qstriage.pdr_verify import verify_pdr_document

    document = json.loads(
        _write_pdr(tmp_path / "a.json", _sample_text()).read_text(encoding="utf-8")
    )
    result = verify_pdr_document(document)
    document["records"].append(document["records"][0])

    with pytest.raises(PDRDiffError, match="repeats record_id"):
        diff_pdr_documents(
            document,
            document,
            before_path="a",
            after_path="b",
            before_verification=result,
            after_verification=result,
        )


def test_untrusted_text_is_escaped_in_markdown(tmp_path: Path) -> None:
    text = _sample_text().replace(
        "name: Public API Gateway", 'name: "Gate | *bold* <b>x</b>"'
    )
    before = _write_pdr(tmp_path / "before.json", text)
    after = _write_pdr(
        tmp_path / "after.json",
        text.replace("algorithm: ECDHE_RSA", "algorithm: X25519MLKEM768"),
    )

    rendered = render_markdown(diff_pdr_files(before, after))

    assert "### Gate \\| \\*bold\\* &lt;b&gt;x&lt;/b&gt; (pdr:public-api-gateway)" in rendered
    assert "<b>" not in rendered


def test_json_output_carries_hashes_and_counts(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())

    data = to_dict(diff_pdr_files(before, after))

    assert data["changed"] is True
    assert data["counts"] == {
        "matched": 5,
        "decisions_changed": 2,
        "records_changed": 2,
        "added": 0,
        "removed": 0,
    }
    assert data["attribution"] == {"changed_items": ["input"], "single_cause": True}
    assert data["before"]["document_hash"].startswith("sha256:")
    assert data["before"]["verification"]["passed"] is True
    provenance = {item["item"]: item for item in data["provenance"]}
    assert provenance["registry"]["after"]["registry_hash"].startswith("sha256:")


def test_cli_diff_exit_codes_and_outputs(tmp_path: Path) -> None:
    runner = CliRunner()
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())

    shown = runner.invoke(app, ["pdr", "diff", str(before), str(after)])
    assert shown.exit_code == 0
    assert shown.output.startswith("# PDR comparison\n")

    as_json = runner.invoke(app, ["pdr", "diff", str(before), str(after), "--format", "json"])
    assert as_json.exit_code == 0
    assert json.loads(as_json.output)["changed"] is True

    bad_format = runner.invoke(app, ["pdr", "diff", str(before), str(after), "--format", "xml"])
    assert bad_format.exit_code == 2

    data = json.loads(after.read_text(encoding="utf-8"))
    data["document_hash"] = "sha256:" + "0" * 64
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(data), encoding="utf-8")
    refused = runner.invoke(app, ["pdr", "diff", str(before), str(tampered)])
    assert refused.exit_code == 1
    assert "No comparison was produced." in refused.output


def test_cli_diff_writes_file_without_overwriting(tmp_path: Path) -> None:
    runner = CliRunner()
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())
    output = tmp_path / "diff.md"

    first = runner.invoke(app, ["pdr", "diff", str(before), str(after), "-o", str(output)])
    assert first.exit_code == 0
    assert output.read_text(encoding="utf-8").startswith("# PDR comparison\n")

    second = runner.invoke(app, ["pdr", "diff", str(before), str(after), "-o", str(output)])
    assert second.exit_code == 1

    protected = runner.invoke(app, ["pdr", "diff", str(before), str(after), "-o", str(after), "--overwrite"])
    assert protected.exit_code == 1


def test_cli_diff_does_not_modify_inputs(tmp_path: Path) -> None:
    before = _write_pdr(tmp_path / "before.json", _sample_text())
    after = _write_pdr(tmp_path / "after.json", _hybrid_text())
    snapshot = (before.read_bytes(), after.read_bytes())

    CliRunner().invoke(app, ["pdr", "diff", str(before), str(after)])

    assert (before.read_bytes(), after.read_bytes()) == snapshot
