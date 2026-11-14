"""Common structure checks for untrusted JSON and YAML input.

Every entry point rejects nesting beyond the documented depth and unpaired
surrogate code points with a controlled message, before verification,
hashing, or decision logic runs. The checks are iterative, so they cannot
exhaust the interpreter stack themselves.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from qstriage import mcp_server
from qstriage.cli import app
from qstriage.config import load_config
from qstriage.enrichment import load_enrichment_patch
from qstriage.limits import (
    MAX_JSON_NESTING_DEPTH,
    MAX_NOTES_LENGTH,
    MAX_TEXT_LENGTH,
    MAX_YAML_NESTING_DEPTH,
    InputStructureError,
    NonStringKey,
    ResourceLimitError,
    check_json_nesting,
    check_structure,
    load_yaml_limited,
)
from qstriage.models import load_inventory
from qstriage.pdr import generate_pdr_document
from qstriage.pdr_verify import PDRVerificationInputError, load_pdr_file


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_inventory.yaml"
DEMO = ROOT / "examples" / "evidence-closure"
CBOM = ROOT / "tests" / "fixtures" / "sample_cbom.json"
V0_2_FIXTURE = ROOT / "tests" / "fixtures" / "pdr_v0_2_sample.json"
REGISTRY = ROOT / "qstriage" / "algorithm_registry.json"

runner = CliRunner()


def _flat(output: str) -> str:
    """Join lines so assertions do not depend on the console width."""
    return " ".join(output.split())


def _nested_list(depth: int) -> list:
    value: list = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _v0_3_document() -> dict:
    return generate_pdr_document(load_inventory(SAMPLE)).model_dump(mode="json")


def _write_with_deep_member(path: Path, document: dict, depth: int) -> Path:
    """Add a member nested ``depth`` levels deep without recursive serialization."""
    text = json.dumps(document)
    assert text.endswith("}")
    path.write_text(
        text[:-1] + ', "extra": ' + "[" * depth + "]" * depth + "}", encoding="utf-8"
    )
    return path


def _inventory_text_with_surrogate() -> str:
    text = SAMPLE.read_text(encoding="utf-8")
    original = "    name: Public API Gateway\n"
    assert text.count(original) == 1
    return text.replace(original, '    name: "Public\\ud800API Gateway"\n')


# Scanner and walker


def test_json_scan_accepts_the_limit_and_rejects_one_more() -> None:
    at_limit = "[" * MAX_JSON_NESTING_DEPTH + "]" * MAX_JSON_NESTING_DEPTH
    beyond = "[" + at_limit + "]"

    check_json_nesting(at_limit, label="JSON")
    with pytest.raises(ResourceLimitError, match="JSON nesting depth of 64"):
        check_json_nesting(beyond, label="JSON")


def test_json_scan_ignores_brackets_inside_strings_and_escapes() -> None:
    text = json.dumps({'a[\\"{': ["]]]" * 100, {"b": "\\"}, "[" * 500]})

    check_json_nesting(text, label="JSON", max_depth=3)
    with pytest.raises(ResourceLimitError):
        check_json_nesting(text, label="JSON", max_depth=2)


def test_json_scan_handles_extreme_nesting_without_recursion() -> None:
    with pytest.raises(ResourceLimitError, match="near character 64"):
        check_json_nesting("[" * 1_000_000, label="JSON")


def test_walk_handles_extreme_nesting_without_recursion() -> None:
    check_structure(_nested_list(MAX_JSON_NESTING_DEPTH), label="Input", max_depth=64)
    with pytest.raises(ResourceLimitError, match="nesting depth of 64"):
        check_structure(_nested_list(100_000), label="Input", max_depth=64)


def test_walk_reports_surrogate_value_with_location() -> None:
    with pytest.raises(InputStructureError) as error:
        check_structure({"records": [{"note": "a\udc00b"}]}, label="PDR JSON", max_depth=64)

    message = str(error.value)
    assert message == (
        "PDR JSON has invalid text in a value at $.records[0].note: \\udc00 is half "
        "of a two-part character escape (an unpaired surrogate) and is not a "
        "character. Replace it with the intended character."
    )


def test_walk_reports_surrogate_key() -> None:
    with pytest.raises(InputStructureError, match=r"invalid text in a key at \$\.records: \\ud800"):
        check_structure({"records": {"\ud800": 1}}, label="Input", max_depth=64)


def test_walk_reports_the_first_problem_in_document_order() -> None:
    value = {"first": ["ok", "\ud801"], "second": {"\ud802": "\ud803"}}

    with pytest.raises(InputStructureError, match=r"in a value at \$\.first\[1\]: \\ud801"):
        check_structure(value, label="Input", max_depth=64)


def test_paired_surrogate_escapes_are_valid_text() -> None:
    parsed = json.loads('{"emoji": "\\ud83d\\ude00"}')
    yaml_parsed = load_yaml_limited('emoji: "\\U0001F600"\n', label="YAML")

    check_structure(parsed, label="JSON", max_depth=64)
    assert parsed["emoji"] == yaml_parsed["emoji"] == "\U0001F600"


def test_bundled_registry_passes_the_structure_check() -> None:
    check_structure(
        json.loads(REGISTRY.read_text(encoding="utf-8")),
        label="Registry",
        max_depth=MAX_JSON_NESTING_DEPTH,
    )


def test_bundled_json_inputs_are_well_within_the_depth_limit() -> None:
    for path in (CBOM, V0_2_FIXTURE, DEMO / "sample_cbom.json"):
        check_json_nesting(path.read_text(encoding="utf-8"), label=path.name, max_depth=8)
    check_json_nesting(json.dumps(_v0_3_document()), label="PDR 0.3", max_depth=8)


# PDR verify and diff


@pytest.mark.parametrize("depth", [MAX_JSON_NESTING_DEPTH + 1, 600, 5_000])
def test_pdr_verify_rejects_deep_documents_without_traceback(tmp_path: Path, depth: int) -> None:
    document = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    path = _write_with_deep_member(tmp_path / "deep.json", document, depth)

    with pytest.raises(PDRVerificationInputError, match="nesting depth"):
        load_pdr_file(path)
    result = runner.invoke(app, ["pdr", "verify", str(path)])

    assert result.exit_code == 1
    assert "PDR verification failed" in _flat(result.output)
    assert "nesting depth of 64" in _flat(result.output)
    assert result.exception is None or isinstance(result.exception, SystemExit)


@pytest.mark.parametrize("version", ["0.2", "0.3"])
def test_pdr_verify_rejects_unpaired_surrogates_in_both_versions(
    tmp_path: Path, version: str
) -> None:
    if version == "0.2":
        document = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    else:
        document = _v0_3_document()
    document["note"] = "x\ud800"
    path = tmp_path / f"surrogate-{version}.json"
    path.write_text(json.dumps(document, ensure_ascii=True), encoding="utf-8")

    result = runner.invoke(app, ["pdr", "verify", str(path)])

    assert result.exit_code == 1
    assert "invalid text in a value at $.note: \\ud800" in _flat(result.output)
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_pdr_diff_rejects_either_input(tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_bytes(V0_2_FIXTURE.read_bytes())
    document = json.loads(V0_2_FIXTURE.read_text(encoding="utf-8"))
    deep = _write_with_deep_member(tmp_path / "deep.json", document, 600)

    for before, after in ((deep, good), (good, deep)):
        result = runner.invoke(app, ["pdr", "diff", str(before), str(after)])
        assert result.exit_code == 1
        assert "nesting depth of 64" in _flat(result.output)


# CBOM import


def test_cbom_import_rejects_deep_json_and_writes_nothing(tmp_path: Path) -> None:
    cbom = json.loads(CBOM.read_text(encoding="utf-8"))
    path = _write_with_deep_member(tmp_path / "deep.cbom.json", cbom, 600)
    output = tmp_path / "inventory.yaml"

    result = runner.invoke(app, ["import", "cbom", str(path), "-o", str(output)])

    assert result.exit_code == 1
    assert "CBOM JSON exceeds the supported JSON nesting depth of 64" in _flat(result.output)
    assert not output.exists()


def test_cbom_import_rejects_surrogate_with_location(tmp_path: Path) -> None:
    cbom = json.loads(CBOM.read_text(encoding="utf-8"))
    cbom["components"][0]["description"] = "\ud800"
    path = tmp_path / "surrogate.cbom.json"
    path.write_text(json.dumps(cbom, ensure_ascii=True), encoding="utf-8")
    output = tmp_path / "inventory.yaml"

    result = runner.invoke(app, ["import", "cbom", str(path), "-o", str(output)])

    assert result.exit_code == 1
    assert "at $.components[0].description" in _flat(result.output)
    assert not output.exists()


# YAML inputs


def test_inventory_rejects_surrogate_with_location(tmp_path: Path) -> None:
    path = tmp_path / "inventory.yaml"
    path.write_text(_inventory_text_with_surrogate(), encoding="utf-8")

    for command in (["score", str(path)], ["pdr", "generate", str(path), "-o", str(tmp_path / "p.json")]):
        result = runner.invoke(app, command)
        assert result.exit_code == 1
        assert "Inventory YAML has invalid text in a value" in _flat(
            result.output
        )
        assert "at $.assets[0].name" in _flat(result.output)
    assert not (tmp_path / "p.json").exists()


def test_configuration_rejects_surrogate(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text('output:\n  reports_dir: "out\\ud800"\n', encoding="utf-8")

    with pytest.raises(InputStructureError, match=r"Configuration YAML .* at \$\.output\.reports_dir"):
        load_config(path)


def test_enrichment_patch_rejects_surrogate(tmp_path: Path) -> None:
    text = (DEMO / "approved_enrichment.patch.yaml").read_text(encoding="utf-8")
    original = "  source_reference: architecture-review-AR-27\n"
    path = tmp_path / "patch.yaml"
    path.write_text(text.replace(original, '  source_reference: "AR\\ud800"\n', 1), encoding="utf-8")

    result = runner.invoke(app, ["closure", "validate", str(DEMO / "imported.yaml"), str(path)])

    assert result.exit_code == 1
    assert "at $.assertions[0].source_reference" in _flat(result.output)


def test_yaml_walk_depth_matches_the_yaml_event_limit() -> None:
    assert MAX_YAML_NESTING_DEPTH == MAX_JSON_NESTING_DEPTH


# MCP tools


@pytest.mark.parametrize(
    "call",
    [
        lambda: mcp_server.inspect_evidence_gaps("inventory.yaml"),
        lambda: mcp_server.generate_patch_template("inventory.yaml"),
        lambda: mcp_server.validate_enrichment_patch("inventory.yaml", "patch.yaml"),
        lambda: mcp_server.compare_inventories("inventory.yaml", "inventory.yaml"),
    ],
    ids=["inspect", "template", "validate", "compare"],
)
def test_mcp_tools_reject_surrogate_inventory(tmp_path: Path, monkeypatch, call) -> None:
    (tmp_path / "inventory.yaml").write_text(_inventory_text_with_surrogate(), encoding="utf-8")
    (tmp_path / "patch.yaml").write_bytes((DEMO / "approved_enrichment.patch.yaml").read_bytes())
    monkeypatch.chdir(tmp_path)

    with pytest.raises(mcp_server.ToolError, match=r"in a value at \$\.assets\[0\]\.name: \\ud800"):
        call()


# Evidence assertion text limits


def _patch_with(**changes: str) -> dict:
    patch = yaml.safe_load((DEMO / "approved_enrichment.patch.yaml").read_text(encoding="utf-8"))
    patch["assertions"][0].update(changes)
    return patch


@pytest.mark.parametrize(
    ("field", "limit"),
    [("source_reference", MAX_TEXT_LENGTH), ("rationale", MAX_NOTES_LENGTH)],
)
def test_patch_assertion_text_is_bounded(tmp_path: Path, field: str, limit: int) -> None:
    path = tmp_path / "patch.yaml"
    path.write_text(yaml.safe_dump(_patch_with(**{field: "x" * limit})), encoding="utf-8")
    load_enrichment_patch(path)

    path.write_text(yaml.safe_dump(_patch_with(**{field: "x" * (limit + 1)})), encoding="utf-8")
    with pytest.raises(ValidationError, match=field):
        load_enrichment_patch(path)


def test_inventory_evidence_assertion_text_is_bounded(tmp_path: Path) -> None:
    text = (DEMO / "expected" / "enriched.yaml").read_text(encoding="utf-8")
    original = "        source_reference: architecture-review-AR-27\n"
    assert original in text
    path = tmp_path / "enriched.yaml"
    path.write_text(
        text.replace(original, f"        source_reference: {'x' * (MAX_TEXT_LENGTH + 1)}\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="source_reference"):
        load_inventory(path)


@pytest.mark.parametrize(
    ("path", "rendered"),
    [
        (("records", 0, "note"), "$.records[0].note"),
        (("a", "b"), "$.a.b"),
        (("a.b",), "$['a.b']"),
        (("x y",), "$['x y']"),
        (("it's",), "$['it\\'s']"),
        (("back\\slash",), "$['back\\\\slash']"),
        (("line\nbreak",), "$['line\\nbreak']"),
        (("\x01",), "$['\\u0001']"),
        (("",), "$['']"),
        (("9lives",), "$['9lives']"),
        ((NonStringKey(None),), "$[YAML key null]"),
        ((NonStringKey(7), 7), "$[YAML key 7][7]"),
        ((NonStringKey(False),), "$[YAML key false]"),
    ],
)
def test_input_path_names_exactly_one_location(path: tuple, rendered: str) -> None:
    # NonStringKey cases cover YAML keys that are not strings.
    from qstriage.limits import format_input_path

    assert format_input_path(path) == rendered


@pytest.mark.parametrize(
    ("key", "shown"),
    [
        ("null", "[YAML key null]"),
        ("~", "[YAML key null]"),
        ("1.5", "[YAML key 1.5]"),
        ("7", "[YAML key 7]"),
        ("true", "[YAML key true]"),
        ("2026-11-14", "[YAML key 2026-11-14]"),
        ("2026-11-14 10:00:00", "[YAML key 2026-11-14 10:00:00]"),
        ('"7"', "['7']"),
    ],
)
def test_validate_locates_a_problem_under_a_yaml_key_that_is_not_a_string(
    tmp_path: Path, key: str, shown: str
) -> None:
    # YAML keys may be null, numbers, booleans, or dates. The location must
    # render without an error and keep a key 7 apart from the list index [7].
    path = tmp_path / "inventory.yaml"
    path.write_text(
        "assets:\n- id: a\n  " + key + ': "\\ud800"\ndependencies: []\nscenarios: []\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate", str(path)])

    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert (
        "Inventory YAML has invalid text in a value at $.assets[0]" + shown + ": "
        "\\ud800 is half of a two-part character escape"
    ) in _flat(result.output)


def test_non_finite_number_under_a_non_string_key_is_located() -> None:
    from qstriage.pdr_verify import verify_pdr_document

    with pytest.raises(PDRVerificationInputError, match=r"at \$\[YAML key 7\]: inf is not"):
        verify_pdr_document({7: float("inf")})
