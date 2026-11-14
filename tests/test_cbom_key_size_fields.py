"""CBOM size fields that disagree are kept and reported, never silently dropped.

The importer reads sizes only from explicit CBOM size fields. For RSA, fields
that disagree are all kept in ``cbom_key_sizes``; ``key_size_bits`` stays
null, and the shared key size resolver reports ``conflicting_key_size`` and
scores the smallest stated size. Inventories without the new field keep their
hash, so bound Evidence Closure patches and PDR source hashes stay valid.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from qstriage.assessment import assess_inventory, evaluate_evidence_quality
from qstriage.cbom import _size_value, inventory_from_cbom
from qstriage.cli import app
from qstriage.closure import inventory_hash
from qstriage.exporters import export_score_results
from qstriage.models import CryptographicAsset, Inventory, load_inventory
from qstriage.pdr import generate_pdr_document, load_pdr_input
from qstriage.standards import classify_algorithm

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "evidence-closure"
DEMO_CBOM = DEMO / "sample_cbom.json"
SAMPLE = ROOT / "examples" / "sample_inventory.yaml"

runner = CliRunner()


def _flat(output: str) -> str:
    """Join lines so assertions do not depend on the console width."""
    return " ".join(output.split())


def _cbom(properties: dict, *, base: dict | None = None) -> dict:
    """The demo CBOM with its one component's algorithmProperties updated."""

    document = copy.deepcopy(base or json.loads(DEMO_CBOM.read_text(encoding="utf-8")))
    document["components"][0]["cryptoProperties"]["algorithmProperties"].update(properties)
    return document


def _bare_rsa_cbom(properties: dict) -> dict:
    """A CBOM whose RSA identifier states no size (family only)."""

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "signing-key",
                "name": "Signing key",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "algorithm": "RSA",
                        "primitive": "signature",
                        **properties,
                    },
                },
            }
        ],
    }


def _write(path: Path, document: dict) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _import(tmp_path: Path, document: dict, name: str = "variant") -> Path:
    source = _write(tmp_path / f"{name}.json", document)
    output = tmp_path / f"{name}.yaml"
    result = runner.invoke(app, ["import", "cbom", str(source), "--output", str(output)])
    assert result.exit_code == 0, result.output
    return output


def _assess(inventory: Inventory, source_type: str):
    return assess_inventory(inventory, source_type=source_type)[0]


# --- importer ---------------------------------------------------------------


def test_disagreeing_rsa_fields_are_kept_and_the_size_left_empty(tmp_path: Path) -> None:
    notices: list[str] = []
    inventory = inventory_from_cbom(
        _bare_rsa_cbom({"keySize": 2048, "keySizeBits": 4096}), notices
    )
    asset = inventory.assets[0]

    assert asset.key_size_bits is None
    assert [(e.property, e.bits) for e in asset.cbom_key_sizes] == [
        ("keySize", 2048),
        ("keySizeBits", 4096),
    ]
    assert notices == [
        "CBOM component 'Signing key' (asset ID signing-key): the size fields "
        "disagree (keySize 2048 bits, keySizeBits 4096 bits). QSTriage kept all "
        "of them in cbom_key_sizes and left key_size_bits empty; the decision "
        "stays gated until the CBOM states one size."
    ]


def test_agreeing_fields_give_key_size_bits_without_the_new_field(tmp_path: Path) -> None:
    output = _import(tmp_path, _bare_rsa_cbom({"keySize": 2048, "keyLength": "2048"}))
    asset = yaml.safe_load(output.read_text(encoding="utf-8"))["assets"][0]

    assert asset["key_size_bits"] == 2048
    assert "cbom_key_sizes" not in asset


def test_disagreement_outside_rsa_keeps_the_first_field_and_says_so() -> None:
    notices: list[str] = []
    document = _bare_rsa_cbom({"keySize": 128, "keyLength": 256})
    document["components"][0]["cryptoProperties"]["algorithmProperties"]["algorithm"] = "AES"
    asset = inventory_from_cbom(document, notices).assets[0]

    assert asset.key_size_bits == 128
    assert asset.cbom_key_sizes is None
    assert notices == [
        "CBOM component 'Signing key' (asset ID signing-key): the size fields "
        "disagree (keySize 128 bits, keyLength 256 bits). QSTriage compares sizes "
        "only for RSA and kept keySize (128 bits). Confirm the size in the CBOM."
    ]


def test_boolean_size_is_ignored_and_the_valid_field_is_used() -> None:
    notices: list[str] = []
    asset = inventory_from_cbom(
        _bare_rsa_cbom({"keySize": True, "keySizeBits": 3072}), notices
    ).assets[0]

    assert asset.key_size_bits == 3072
    assert asset.cbom_key_sizes is None
    assert notices == [
        "CBOM component 'Signing key' (asset ID signing-key): keySize is true, "
        "which is not a key size (a whole number of bits from 0 to "
        "9007199254740992). QSTriage ignored this field. Correct it in the CBOM "
        "if the key size matters."
    ]


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        -1,
        2**53 + 1,
        2048.0,
        "\u00b2",
        "2048 bits",
        "",
        "\uff12\uff10\uff14\uff18",
        "9007199254740993",
        "9" * 4301,
    ],
)
def test_values_that_are_not_sizes_are_rejected(value) -> None:
    assert _size_value(value) is None


@pytest.mark.parametrize(
    "value, bits",
    [
        (0, 0),
        (2048, 2048),
        ("4096", 4096),
        (2**53, 2**53),
        ("9007199254740992", 2**53),
        ("0" * 5000 + "2048", 2048),
        ("0000", 0),
    ],
)
def test_values_that_are_sizes(value, bits) -> None:
    assert _size_value(value) == bits


def test_superscript_digit_does_not_crash_the_import() -> None:
    notices: list[str] = []
    asset = inventory_from_cbom(_bare_rsa_cbom({"keySize": "\u00b2"}), notices).assets[0]

    assert asset.key_size_bits is None
    assert len(notices) == 1 and "keySize is" in notices[0]


@pytest.mark.parametrize(
    "command",
    [
        ["import", "cbom", "{source}", "--output", "{out}/c.yaml"],
        ["review", "evidence", "{source}", "--input-format", "cbom"],
        ["pdr", "generate", "{source}", "--input-format", "cbom", "--output", "{out}/p.json"],
    ],
    ids=["import", "review", "pdr"],
)
def test_oversized_second_field_is_ignored_and_the_import_continues(
    tmp_path: Path, command: list[str]
) -> None:
    # 83b743c kept keySize 2048 here; an oversized string must not stop the
    # import (Python refuses int() on more than 4,300 digits).
    source = _write(
        tmp_path / "c.json", _bare_rsa_cbom({"keySize": 2048, "keySizeBits": "9" * 4301})
    )
    args = [part.format(source=source, out=tmp_path) for part in command]
    result = runner.invoke(app, args)
    output = _flat(result.output)

    assert result.exit_code == 0, output[:400]
    assert "Traceback" not in result.output
    notice = (
        "CBOM component 'Signing key' (asset ID signing-key): keySizeBits is "
        '"999999999999999999999999999999999999999... (4303 characters), which is '
        "not a key size"
    )
    assert notice in output
    assert "9" * 100 not in output
    if command[0] == "import":
        asset = yaml.safe_load((tmp_path / "c.yaml").read_text(encoding="utf-8"))["assets"][0]
        assert asset["key_size_bits"] == 2048
        assert "cbom_key_sizes" not in asset


@pytest.mark.parametrize(
    "value, shown",
    [
        (10**4301 - 1, "an integer beyond 2^53"),
        (-(10**4301), "an integer beyond -2^53"),
        (2**53 + 1, "an integer beyond 2^53"),
    ],
    ids=["4301_digits", "negative_4302_digits", "2_53_plus_1"],
)
@pytest.mark.parametrize("collect", [True, False], ids=["notices", "no_notices"])
def test_huge_integer_from_the_python_api_is_ignored_with_a_notice(
    value: int, shown: str, collect: bool
) -> None:
    # Python refuses str() on integers with more than 4,300 digits; preparing
    # the notice must not stop the import. 83b743c kept keySize 2048 here.
    document = _bare_rsa_cbom({"keySize": 2048, "keySizeBits": value})
    notices: list[str] | None = [] if collect else None
    asset = inventory_from_cbom(document, notices).assets[0]

    assert asset.key_size_bits == 2048
    assert asset.cbom_key_sizes is None
    if collect:
        assert notices == [
            f"CBOM component 'Signing key' (asset ID signing-key): keySizeBits is "
            f"{shown}, which is not a key size (a whole number of bits from 0 to "
            "9007199254740992). QSTriage ignored this field. Correct it in the "
            "CBOM if the key size matters."
        ]


def test_leading_zeros_give_the_same_size_as_the_plain_number() -> None:
    asset = inventory_from_cbom(
        _bare_rsa_cbom({"keySize": "0" * 400 + "2048", "keySizeBits": 2048})
    ).assets[0]

    assert asset.key_size_bits == 2048
    assert asset.cbom_key_sizes is None


def test_null_size_field_is_absent_without_a_notice() -> None:
    notices: list[str] = []
    asset = inventory_from_cbom(
        _bare_rsa_cbom({"keySize": None, "keySizeBits": 4096}), notices
    ).assets[0]

    assert asset.key_size_bits == 4096
    assert notices == []


@pytest.mark.parametrize("value", [[2048], {"bits": 2048}])
def test_array_or_object_size_field_still_stops_the_import(value) -> None:
    with pytest.raises(ValueError, match="keySize must be a JSON scalar value"):
        inventory_from_cbom(_bare_rsa_cbom({"keySize": value}))


def test_import_command_prints_the_notices(tmp_path: Path) -> None:
    source = _write(tmp_path / "c.json", _bare_rsa_cbom({"keySize": True, "keySizeBits": 4096}))
    result = runner.invoke(
        app, ["import", "cbom", str(source), "--output", str(tmp_path / "c.yaml")]
    )

    assert result.exit_code == 0
    assert "CBOM component 'Signing key' (asset ID signing-key): keySize is true" in _flat(
        result.output
    )
    assert "Traceback" not in result.output


# --- model --------------------------------------------------------------------


def _asset_with(sizes) -> dict:
    asset = load_inventory(SAMPLE).assets[0].model_dump(mode="json")
    asset.update(algorithm="RSA", key_size_bits=None, cbom_key_sizes=sizes)
    return asset


@pytest.mark.parametrize(
    "sizes, message",
    [
        ([{"property": "keySize", "bits": 2048}], "at least 2 items"),
        (
            [{"property": "keySize", "bits": 2048}, {"property": "keySize", "bits": 4096}],
            "cbom_key_sizes lists keySize more than once. List each CBOM size field once.",
        ),
        (
            [{"property": "keySize", "bits": 2048}, {"property": "keyLength", "bits": 2048}],
            "every listed value is 2048 bits. Remove cbom_key_sizes and set "
            "key_size_bits to 2048.",
        ),
        (
            [{"property": "size", "bits": 2048}, {"property": "keyLength", "bits": 4096}],
            "keySize",
        ),
        (
            [{"property": "keySize", "bits": True}, {"property": "keyLength", "bits": 4096}],
            "valid integer",
        ),
        (
            [{"property": "keySize", "bits": 2**53 + 1}, {"property": "keyLength", "bits": 4096}],
            "less than or equal to 9007199254740992",
        ),
    ],
)
def test_invalid_cbom_key_sizes_are_rejected(sizes, message) -> None:
    with pytest.raises(ValidationError, match=message):
        CryptographicAsset.model_validate(_asset_with(sizes))


def test_output_schema_keeps_every_field() -> None:
    # A wrap serializer annotated to return Any empties the serialization
    # schema; the model's own schema must survive, alone and inside Inventory.
    fields = set(CryptographicAsset.model_fields)
    for mode in ("serialization", "validation"):
        schema = CryptographicAsset.model_json_schema(mode=mode)
        assert set(schema["properties"]) == fields, mode
        nested = Inventory.model_json_schema(mode=mode)["$defs"]["CryptographicAsset"]
        assert set(nested["properties"]) == fields, mode


# --- hashes ---------------------------------------------------------------------


def test_absent_field_is_omitted_from_every_dump() -> None:
    inventory = load_inventory(SAMPLE)

    assert all("cbom_key_sizes" not in asset for asset in inventory.model_dump()["assets"])
    assert all(
        "cbom_key_sizes" not in asset for asset in inventory.model_dump(mode="json")["assets"]
    )
    assert "cbom_key_sizes" not in json.loads(inventory.model_dump_json())["assets"][0]
    # Only the new field is omitted: other None values are still written.
    asset = CryptographicAsset.model_validate(_asset_with(None))
    assert asset.model_dump()["key_size_bits"] is None
    assert "cbom_key_sizes" not in asset.model_dump()


def test_present_field_is_written() -> None:
    sizes = [{"property": "keySize", "bits": 2048}, {"property": "keySizeBits", "bits": 4096}]
    asset = CryptographicAsset.model_validate(_asset_with(sizes))

    assert asset.model_dump(mode="json")["cbom_key_sizes"] == sizes


def test_existing_inventory_hashes_are_unchanged() -> None:
    assert inventory_hash(load_inventory(SAMPLE)) == (
        "sha256:14fcf5c20d9db7cb91632a1309a26c289b9837278130ae56d5e0433d64fcebce"
    )
    assert inventory_hash(load_inventory(DEMO / "imported.yaml")) == (
        "sha256:3490a15a8131728dc1c6b3b46a3a4afdc112ef7de3e197e3d089ff7fa0aa5d68"
    )


def test_bound_evidence_closure_patch_still_validates() -> None:
    result = runner.invoke(
        app,
        [
            "closure",
            "validate",
            str(DEMO / "imported.yaml"),
            str(DEMO / "approved_enrichment.patch.yaml"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Enrichment patch is valid." in _flat(result.output)


def test_pdr_source_hashes_are_unchanged() -> None:
    from_file = load_pdr_input(DEMO_CBOM, "cbom")
    assert from_file.input_snapshot.source_hash == (
        "sha256:0565c4868f369277ab9447c845f97d0a90793658cfb0a3471de51f96ac381847"
    )

    from_object = generate_pdr_document(load_inventory(DEMO / "imported.yaml"))
    assert from_object.input_snapshot.source_hash == (
        "sha256:3490a15a8131728dc1c6b3b46a3a4afdc112ef7de3e197e3d089ff7fa0aa5d68"
    )


# --- evaluation: direct CBOM and import -> YAML -> reload ---------------------


def _both_paths(tmp_path: Path, document: dict, name: str):
    """(direct CBOM assessment, reloaded YAML assessment) for one document."""

    direct = _assess(inventory_from_cbom(document), "cyclonedx_cbom")
    reloaded = _assess(load_inventory(_import(tmp_path, document, name)), "cyclonedx_cbom")
    return direct, reloaded


def _requirements(assessment) -> set[str]:
    return {r.value for r in assessment.decision.verification_requirements}


def _finding_codes(assessment) -> list[str]:
    return [f.code for f in assessment.evidence_review.findings]


@pytest.mark.parametrize("path_index", [0, 1], ids=["direct_cbom", "import_reload"])
def test_conflict_adds_its_finding_and_requirement_on_both_paths(
    tmp_path: Path, path_index: int
) -> None:
    baseline = _both_paths(tmp_path, _cbom({}), "baseline")[path_index]
    conflict = _both_paths(
        tmp_path, _cbom({"keySize": 2048, "keySizeBits": 4096}), "conflict"
    )[path_index]
    corrected = _both_paths(
        tmp_path, _cbom({"keySize": 2048, "keySizeBits": 2048}), "corrected"
    )[path_index]

    # The demo is already gated for other reasons; the conflict must add its own.
    assert baseline.decision.execution_state.value == "gated"
    assert "conflicting_key_size" not in _finding_codes(baseline)
    assert "cryptographic_parameters" not in _requirements(baseline)

    assert conflict.decision.execution_state.value == "gated"
    assert _finding_codes(conflict).count("conflicting_key_size") == 1
    assert "missing_key_size_bits" not in _finding_codes(conflict)
    assert _requirements(conflict) == _requirements(baseline) | {"cryptographic_parameters"}
    assert conflict.score.key_size_bits_scored == 2048
    assert conflict.score.key_size_source == "conflict_smaller"
    assert [e.bits for e in conflict.asset.cbom_key_sizes] == [2048, 4096]

    # Correcting the source removes exactly what the conflict added.
    assert "conflicting_key_size" not in _finding_codes(corrected)
    assert _requirements(corrected) == _requirements(baseline)


def test_both_paths_give_the_same_decision(tmp_path: Path) -> None:
    direct, reloaded = _both_paths(
        tmp_path, _bare_rsa_cbom({"keySize": 4096, "keySizeBits": 1024}), "pair"
    )

    for field in ("execution_state", "verification_requirements", "risk_attention_score"):
        assert getattr(direct.decision, field) == getattr(reloaded.decision, field)
    assert direct.score.key_size_bits_scored == reloaded.score.key_size_bits_scored == 1024
    assert _finding_codes(direct) == _finding_codes(reloaded)


def _context_complete(inventory: Inventory) -> Inventory:
    """Give the asset full business context so the score is not saturated."""

    asset = inventory.assets[0].model_copy(
        update={
            "data_class": "customer_pii",
            "retention_years": 2,
            "exposure": "internal",
            "criticality": "medium",
            "local_blast_radius": "low",
            "migration_effort": "medium",
        }
    )
    return Inventory(assets=[asset], dependencies=[], scenarios=[])


def test_score_uses_the_smallest_stated_size(tmp_path: Path) -> None:
    conflict = _context_complete(
        load_inventory(_import(tmp_path, _bare_rsa_cbom({"keySize": 4096, "keySizeBits": 2048})))
    )
    smallest = Inventory(
        assets=[
            conflict.assets[0].model_copy(update={"cbom_key_sizes": None, "key_size_bits": 2048})
        ],
        dependencies=[],
        scenarios=[],
    )
    largest = Inventory(
        assets=[
            conflict.assets[0].model_copy(update={"cbom_key_sizes": None, "key_size_bits": 4096})
        ],
        dependencies=[],
        scenarios=[],
    )

    scored = _assess(conflict, "qstriage_inventory").score
    assert scored.priority_score == _assess(smallest, "qstriage_inventory").score.priority_score
    assert scored.priority_score > _assess(largest, "qstriage_inventory").score.priority_score
    assert scored.breakdown.deadline_pressure == (
        _assess(smallest, "qstriage_inventory").score.breakdown.deadline_pressure
    )
    assert scored.score_basis == "worst_case"


def test_missing_size_is_not_reported_when_cbom_sizes_exist(tmp_path: Path) -> None:
    asset = load_inventory(
        _import(tmp_path, _bare_rsa_cbom({"keySize": 2048, "keySizeBits": 4096}))
    ).assets[0]
    quality = evaluate_evidence_quality(asset, classify_algorithm(asset.algorithm))

    assert "key_size_bits" not in quality.missing_evidence


def test_cbom_key_sizes_do_not_hide_a_missing_size_outside_rsa(tmp_path: Path) -> None:
    # DH needs key_size_bits. cbom_key_sizes is used only for an RSA
    # conflict, so here the size is still missing and must be reported.
    base = _asset_with(None)
    base["algorithm"] = "DH"
    with_sizes = dict(
        base,
        cbom_key_sizes=[
            {"property": "keySize", "bits": 2048},
            {"property": "keyLength", "bits": 4096},
        ],
    )
    records = {}
    for name, asset in (("without", base), ("with", with_sizes)):
        path = tmp_path / f"dh-{name}.yaml"
        path.write_text(
            yaml.safe_dump({"assets": [asset], "dependencies": [], "scenarios": []}),
            encoding="utf-8",
        )
        pdr_path = tmp_path / f"dh-{name}.json"
        result = runner.invoke(app, ["pdr", "generate", str(path), "--output", str(pdr_path)])
        assert result.exit_code == 0, result.output
        records[name] = json.loads(pdr_path.read_text(encoding="utf-8"))["records"][0]

    for record in records.values():
        codes = [f["code"] for f in record["evidence_review"]["findings"]]
        assert "missing_key_size_bits" in codes
        assert "conflicting_key_size" not in codes
        assert "key_size_bits" in record["evidence_quality"]["missing_evidence"]
        assert "cryptographic_parameters" in record["decision"]["verification_requirements"]
    assert (
        records["with"]["decision"]["verification_requirements"]
        == records["without"]["decision"]["verification_requirements"]
    )


# --- messages and surfaces ---------------------------------------------------------


CBOM_MESSAGE = (
    "The CBOM gives different sizes for this RSA key: keySize says 2048 bits, "
    "keySizeBits says 4096 bits. The planning score uses 2048 bits as a "
    "precaution. Confirm the RSA modulus size in the original CBOM, correct it "
    "there, and import it again."
)


def test_finding_points_to_cbom_key_sizes_and_asks_for_reimport(tmp_path: Path) -> None:
    assessment = _assess(
        inventory_from_cbom(_bare_rsa_cbom({"keySize": 2048, "keySizeBits": 4096})),
        "cyclonedx_cbom",
    )
    finding = next(
        f for f in assessment.evidence_review.findings if f.code == "conflicting_key_size"
    )

    assert finding.message == CBOM_MESSAGE
    assert finding.field_path == "assets[signing-key].cbom_key_sizes"
    assert finding.human_action.field_path == "assets[signing-key].cbom_key_sizes"
    assert finding.human_action.description == (
        "Confirm the RSA modulus size of asset 'signing-key' in the original CBOM, "
        "correct the size fields there, and import the CBOM again."
    )


def test_message_names_every_stated_size(tmp_path: Path) -> None:
    path = _import(tmp_path, _cbom({"keySize": 2048, "keySizeBits": 4096}))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["assets"][0]["key_size_bits"] = 3072
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    assessment = _assess(load_inventory(path), "qstriage_inventory")
    finding = next(
        f for f in assessment.evidence_review.findings if f.code == "conflicting_key_size"
    )

    assert finding.message == (
        "The algorithm identifier says 2048 bits. The CBOM gives different sizes for "
        "this RSA key: keySize says 2048 bits, keySizeBits says 4096 bits. "
        '"key_size_bits" says 3072 bits. The planning score uses 2048 bits as a '
        "precaution. Confirm the RSA modulus size in the original CBOM, correct it "
        "there, and import it again."
    )
    assumption = assessment.score.scoring_assumptions[-1]
    assert assumption.field == "cbom_key_sizes"
    assert assumption.inventory_value == "keySize=2048, keySizeBits=4096, key_size_bits=3072"
    assert assumption.problem == (
        "the CBOM size fields disagree; the algorithm identifier says 2048 bits"
    )


def test_identifier_conflict_message_is_unchanged() -> None:
    inventory = load_inventory(SAMPLE)
    asset = inventory.assets[0].model_copy(
        update={"algorithm": "RSA-2048", "key_size_bits": 4096}
    )
    assessment = _assess(
        Inventory(assets=[asset], dependencies=[], scenarios=[]), "qstriage_inventory"
    )
    finding = next(
        f for f in assessment.evidence_review.findings if f.code == "conflicting_key_size"
    )

    assert finding.message == (
        "The algorithm identifier says 2048 bits. \"key_size_bits\" says 4096 bits. "
        "The planning score uses 2048 bits as a precaution. Verify the RSA modulus "
        "size against the source record before proceeding."
    )
    assert finding.field_path == f"assets[{asset.id}].key_size_bits"


def test_every_surface_shows_the_cbom_conflict(tmp_path: Path) -> None:
    path = _import(tmp_path, _bare_rsa_cbom({"keySize": 2048, "keySizeBits": 4096}))

    score = runner.invoke(app, ["score", str(path)])
    assert score.exit_code == 0
    assert CBOM_MESSAGE in _flat(score.output)

    report_path = tmp_path / "report.md"
    report = runner.invoke(app, ["report", str(path), "--output", str(report_path)])
    assert report.exit_code == 0
    report_text = report_path.read_text(encoding="utf-8")
    assert f"- Conflicting key size: {CBOM_MESSAGE}" in report_text
    assert (
        "- Key size used for scoring: 2048 bits, the smallest of the conflicting "
        "stated sizes (provisional)"
    ) in report_text

    export = json.loads(
        export_score_results(load_inventory(path), tmp_path / "s.json", "json").read_text(
            encoding="utf-8"
        )
    )
    records = export["ranked"] + export["verification_first"]
    assert records[0]["key_size_source"] == "conflict_smaller"
    assert records[0]["key_size_bits_scored"] == 2048
    assert records[0]["scoring_assumptions"][-1]["field"] == "cbom_key_sizes"

    pdr_path = tmp_path / "p.json"
    pdr = runner.invoke(app, ["pdr", "generate", str(path), "--output", str(pdr_path)])
    assert pdr.exit_code == 0
    record = json.loads(pdr_path.read_text(encoding="utf-8"))["records"][0]
    assert CBOM_MESSAGE in record["assumptions_made"]
    assert record["observed_state"]["key_size_bits"] is None
    assert "cbom_key_sizes" not in record["observed_state"]
    finding = next(
        f for f in record["evidence_review"]["findings"] if f["code"] == "conflicting_key_size"
    )
    assert finding["field_path"] == "assets[signing-key].cbom_key_sizes"
    assert "missing_key_size_bits" not in [
        f["code"] for f in record["evidence_review"]["findings"]
    ]
    assert runner.invoke(app, ["pdr", "verify", str(pdr_path)]).exit_code == 0

    evidence = runner.invoke(app, ["review", "evidence", str(path)])
    assert evidence.exit_code == 0
    assert "conflicting_key_size" in _flat(evidence.output)
    assert "missing_key_size_bits" not in _flat(evidence.output)


def test_direct_cbom_commands_print_the_notices(tmp_path: Path) -> None:
    source = _write(
        tmp_path / "c.json", _bare_rsa_cbom({"keySize": 2048, "keySizeBits": 4096})
    )

    review = runner.invoke(app, ["review", "evidence", str(source), "--input-format", "cbom"])
    assert review.exit_code == 0
    assert "the size fields disagree (keySize 2048 bits, keySizeBits 4096 bits)" in _flat(
        review.output
    )

    pdr_path = tmp_path / "p.json"
    pdr = runner.invoke(
        app,
        ["pdr", "generate", str(source), "--input-format", "cbom", "--output", str(pdr_path)],
    )
    assert pdr.exit_code == 0
    assert "the size fields disagree" in _flat(pdr.output)
    record = json.loads(pdr_path.read_text(encoding="utf-8"))["records"][0]
    assert CBOM_MESSAGE in record["assumptions_made"]
