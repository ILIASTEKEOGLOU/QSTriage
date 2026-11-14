"""One RSA key size rule for scoring, evidence review, and every output.

``resolve_key_size`` decides the size scoring uses. Evidence review calls the
same function, so the provisional score and the ``conflicting_key_size``
finding always describe the same conflict. The CBOM importer takes a key
size only from explicit size fields and keeps the identifier the source
states.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from qstriage.assessment import assess_inventory
from qstriage.cbom import inventory_from_cbom, write_imported_inventory
from qstriage.cli import app
from qstriage.evidence import review_asset_evidence
from qstriage.exporters import export_score_results
from qstriage.models import Inventory, load_inventory
from qstriage.pdr import generate_pdr_document
from qstriage.pdr_verify import verify_pdr_file
from qstriage.report import generate_markdown_report
from qstriage.scoring import score_inventory
from qstriage.standards import (
    KeySizeSource,
    classify_algorithm,
    conflicting_key_size_message,
    resolve_key_size,
)


runner = CliRunner()

D2_MESSAGE = (
    'The algorithm identifier says 2048 bits. "key_size_bits" says 4096 bits. '
    "The planning score uses 2048 bits as a precaution. Verify the RSA modulus "
    "size against the source record before proceeding."
)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _inventory(algorithm: str, key_size_bits: int | None = None, **context: object) -> Inventory:
    asset: dict[str, object] = {
        "id": "signer",
        "name": "Signing service",
        "environment": "production",
        "asset_type": "signature_service",
        "protocol": "document signature",
        "algorithm": algorithm,
        "data_class": "public",
        "retention_years": 10,
        "exposure": "internal",
        "criticality": "medium",
        "local_blast_radius": "medium",
        "migration_effort": "medium",
    }
    if key_size_bits is not None:
        asset["key_size_bits"] = key_size_bits
    asset.update(context)
    return Inventory.model_validate({"assets": [asset], "dependencies": [], "scenarios": []})


def _write(tmp_path: Path, inventory: Inventory, name: str = "inventory.yaml") -> Path:
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump(inventory.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )
    return path


# The resolver


@pytest.mark.parametrize(
    ("algorithm", "declared", "scored", "source", "identifier"),
    [
        ("RSA-2048", None, 2048, KeySizeSource.algorithm_identifier, 2048),
        ("RSA4096", None, 4096, KeySizeSource.algorithm_identifier, 4096),
        ("RSA-2048", 2048, 2048, KeySizeSource.declared, 2048),
        ("RSA-2048", 4096, 2048, KeySizeSource.conflict_smaller, 2048),
        ("RSA-4096", 2048, 2048, KeySizeSource.conflict_smaller, 4096),
        ("RSA-4096", 8192, 4096, KeySizeSource.conflict_smaller, 4096),
        ("RSA-2048", 0, 0, KeySizeSource.conflict_smaller, 2048),
        ("RSA", 4096, 4096, KeySizeSource.declared, None),
        ("RSA", None, None, None, None),
        ("RSA-PSS", 3072, 3072, KeySizeSource.declared, None),
        # The score does not use a key size for these families, so no size
        # is reported as used, even when one is declared.
        ("AES-256-GCM", 256, None, None, None),
        ("ML-KEM-768", None, None, None, None),
        ("ML-KEM-768", 768, None, None, None),
        ("SHA-256", 256, None, None, None),
        ("FFDHE2048", 2048, None, None, None),
        ("P-256", 256, None, None, None),
    ],
)
def test_resolver_selects_one_size(
    algorithm: str,
    declared: int | None,
    scored: int | None,
    source: KeySizeSource | None,
    identifier: int | None,
) -> None:
    resolution = resolve_key_size(classify_algorithm(algorithm), declared)

    assert resolution.declared_bits == declared
    assert resolution.identifier_bits == identifier
    assert resolution.scored_bits == scored
    assert resolution.source == source
    assert resolution.conflict is (source == KeySizeSource.conflict_smaller)


@pytest.mark.parametrize(
    "algorithm",
    [
        "RSA", "RSA-2048", "RSA-PSS", "RSA-OAEP", "sha256WithRSAEncryption",
        "AES-256-GCM", "AES", "ML-KEM-768", "ML-DSA-65", "X25519MLKEM768",
        "SHA-256", "FFDHE2048", "DH", "P-256", "ECDSA", "X25519", "unknown-cipher",
    ],
)
def test_size_is_reported_as_used_exactly_when_it_changes_the_score(algorithm: str) -> None:
    from qstriage.scoring import _cryptographic_risk
    from qstriage.standards import key_size_affects_score

    classification = classify_algorithm(algorithm)
    risk_changes = _cryptographic_risk(algorithm, 1024, classification) != _cryptographic_risk(
        algorithm, 8192, classification
    )

    assert key_size_affects_score(classification) is risk_changes
    assert (resolve_key_size(classification, 1024).scored_bits is not None) is risk_changes


@pytest.mark.parametrize(
    ("algorithm", "declared"),
    [("SHA-256", 256), ("ML-KEM-768", 768), ("AES-256-GCM", 256), ("FFDHE2048", 2048)],
)
def test_declared_size_outside_rsa_is_kept_but_not_reported_as_scored(
    algorithm: str, declared: int, tmp_path: Path
) -> None:
    inventory = _inventory(algorithm, declared)
    [with_size] = score_inventory(inventory)
    [without_size] = score_inventory(_inventory(algorithm))
    [record] = json.loads(
        export_score_results(inventory, tmp_path / "s.json", "json").read_text(encoding="utf-8")
    )["ranked"]
    [pdr_record] = generate_pdr_document(inventory).model_dump(mode="json")["records"]

    assert with_size.breakdown == without_size.breakdown
    assert record["key_size_bits_scored"] is None
    assert record["key_size_source"] is None
    assert "Key size used for scoring" not in generate_markdown_report(inventory)
    assert pdr_record["observed_state"]["key_size_bits"] == declared
    assert not [line for line in pdr_record["assumptions_made"] if line.startswith("Key size")]


def test_conflict_message_is_the_approved_text() -> None:
    resolution = resolve_key_size(classify_algorithm("RSA-2048"), 4096)

    assert conflicting_key_size_message(resolution) == D2_MESSAGE


# Scoring: risk and deadline pressure read the same size


@pytest.mark.parametrize(
    ("algorithm", "declared", "risk", "deadline", "basis", "source"),
    [
        # Values on main c39127d/0f258c3 for comparison:
        # RSA-4096 without the field 8.0 / 5.0; RSA-2048 + 4096 7.0 / 1.0.
        ("RSA-4096", None, 7.0, 1.0, "confirmed", "algorithm_identifier"),
        ("RSA-2048", 4096, 9.0, 5.0, "worst_case", "conflict_smaller"),
        ("RSA-4096", 2048, 9.0, 5.0, "worst_case", "conflict_smaller"),
        ("RSA-2048", None, 9.0, 5.0, "confirmed", "algorithm_identifier"),
        ("RSA-2048", 2048, 9.0, 5.0, "confirmed", "declared"),
        ("RSA-4096", 8192, 7.0, 1.0, "worst_case", "conflict_smaller"),
        ("RSA-2048", 0, 9.0, 5.0, "worst_case", "conflict_smaller"),
        ("RSA", 4096, 7.0, 1.0, "confirmed", "declared"),
    ],
)
def test_long_retention_scores_risk_and_deadline_from_one_size(
    algorithm: str,
    declared: int | None,
    risk: float,
    deadline: float,
    basis: str,
    source: str,
) -> None:
    [score] = score_inventory(_inventory(algorithm, declared))

    assert score.breakdown.cryptographic_risk == risk
    assert score.breakdown.deadline_pressure == deadline
    assert score.score_basis == basis
    assert score.key_size_source == source


@pytest.mark.parametrize(
    ("algorithm", "risk"),
    [
        ("ML-KEM-768", 1.5),
        ("X25519MLKEM768", 1.5),
        ("SecP384r1MLKEM1024", 1.5),
        ("SHA-256", 2.0),
        ("AES-256-GCM", 2.0),
    ],
)
def test_other_families_are_unchanged(algorithm: str, risk: float) -> None:
    # Values pinned from main 0f258c3.
    [score] = score_inventory(_inventory(algorithm))
    [assessment] = assess_inventory(_inventory(algorithm))

    assert score.breakdown.cryptographic_risk == risk
    assert score.score_basis == "confirmed"
    assert not score.scoring_assumptions
    assert "conflicting_key_size" not in {f.code for f in assessment.evidence_review.findings}


# Decision and evidence review


@pytest.mark.parametrize(
    ("algorithm", "declared"),
    [("RSA-2048", 4096), ("RSA-4096", 2048), ("RSA-4096", 8192), ("RSA-2048", 0)],
)
def test_every_conflict_gates_the_decision(algorithm: str, declared: int) -> None:
    [assessment] = assess_inventory(_inventory(algorithm, declared))
    decision = assessment.decision
    findings = {f.code: f for f in assessment.evidence_review.findings}

    assert "conflicting_key_size" in findings
    finding = findings["conflicting_key_size"]
    assert finding.field_path == "assets[signer].key_size_bits"
    assert {effect.value for effect in finding.effects} == {
        "decision_grade_blocked",
        "human_review_required",
    }
    assert decision.execution_state.value == "gated"
    assert "cryptographic_parameters" in {r.value for r in decision.verification_requirements}
    assert decision.human_review_required
    assert decision.decision_confidence <= 0.5
    # Both declarations are kept as stated.
    assert assessment.asset.algorithm == algorithm
    assert assessment.asset.key_size_bits == declared


def test_size_from_identifier_alone_does_not_gate() -> None:
    [assessment] = assess_inventory(_inventory("RSA-2048"))

    assert "conflicting_key_size" not in {f.code for f in assessment.evidence_review.findings}
    assert "missing_key_size_bits" not in {f.code for f in assessment.evidence_review.findings}
    assert assessment.decision.execution_state.value == "justified"


def test_evidence_review_and_scoring_use_the_same_resolution() -> None:
    inventory = _inventory("RSA-4096", 2048)
    asset = inventory.assets[0]
    [score] = score_inventory(inventory)
    review = review_asset_evidence(asset)
    [finding] = [f for f in review.findings if f.code == "conflicting_key_size"]
    [assumption] = score.scoring_assumptions

    assert finding.message == assumption.message
    assert score.key_size_bits_scored == 2048
    assert "2048 bits as a precaution" in finding.message


# Every output shows the conflict


def test_cli_score_shows_the_conflict(tmp_path: Path) -> None:
    path = _write(tmp_path, _inventory("RSA-2048", 4096))

    result = runner.invoke(app, ["score", str(path)])

    assert result.exit_code == 0
    output = _flat(result.output)
    assert "Worst case fields for Signing service (asset ID signer): key_size_bits" in output
    assert f"Asset ID signer: {D2_MESSAGE}" in output
    assert "execution=gated" in output


def test_cli_score_names_the_asset_id_when_names_repeat(tmp_path: Path) -> None:
    conflict = _inventory("RSA-2048", 4096).assets[0]
    clean = conflict.model_copy(update={"id": "signer-b", "key_size_bits": 2048})
    inventory = Inventory(assets=[conflict, clean], dependencies=[], scenarios=[])
    path = _write(tmp_path, inventory)

    result = runner.invoke(app, ["score", str(path)])

    assert result.exit_code == 0
    output = _flat(result.output)
    assert f"Asset ID signer: {D2_MESSAGE}" in output
    assert "(asset ID signer): key_size_bits" in output
    assert "signer-b" not in output.split("Worst case fields", 1)[1]


def test_report_shows_size_used_and_the_conflict() -> None:
    report = generate_markdown_report(_inventory("RSA-2048", 4096))

    assert (
        "- Ranked assets scored at worst case: 1 of 1 "
        "(missing or unusable context: 0; conflicting key size: 1)"
    ) in report
    assert (
        "- Key size used for scoring: 2048 bits, the smaller of two conflicting "
        "sizes (provisional)"
    ) in report
    assert "- Conflicting key size: The algorithm identifier says 2048 bits." in report
    assert (
        "| key_size_bits | `4096` | differs from the algorithm identifier, which "
        "says 2048 bits | 2048 bits |"
    ) in report


def test_report_states_size_taken_from_identifier() -> None:
    report = generate_markdown_report(_inventory("RSA-2048"))

    assert (
        "- Key size used for scoring: 2048 bits, taken from the algorithm "
        "identifier RSA-2048"
    ) in report
    assert "conflicting key size: 0" in report


def test_json_and_csv_exports_carry_size_and_source(tmp_path: Path) -> None:
    conflict = _inventory("RSA-2048", 4096)
    derived = _inventory("RSA-2048")

    [record] = json.loads(
        export_score_results(conflict, tmp_path / "c.json", "json").read_text(encoding="utf-8")
    )["ranked"]
    assert record["key_size_bits_scored"] == 2048
    assert record["key_size_source"] == "conflict_smaller"
    assert record["score_basis"] == "worst_case"
    assert record["scoring_assumptions"] == [
        {
            "field": "key_size_bits",
            "inventory_value": "4096",
            "problem": "differs from the algorithm identifier, which says 2048 bits",
            "scored_as": "2048 bits",
            "kind": "conflicting_key_size",
            "message": D2_MESSAGE,
        }
    ]

    [record] = json.loads(
        export_score_results(derived, tmp_path / "d.json", "json").read_text(encoding="utf-8")
    )["ranked"]
    assert record["key_size_bits_scored"] == 2048
    assert record["key_size_source"] == "algorithm_identifier"
    assert record["score_basis"] == "confirmed"
    assert record["scoring_assumptions"] == []

    [row] = list(
        csv.DictReader(
            io.StringIO(
                export_score_results(conflict, tmp_path / "c.csv", "csv").read_text(encoding="utf-8")
            )
        )
    )
    assert row["key_size_bits_scored"] == "2048"
    assert row["key_size_source"] == "conflict_smaller"
    assert row["cryptographic_risk"] == "9.0"
    assert row["deadline_pressure"] == "5.0"

    [row] = list(
        csv.DictReader(
            io.StringIO(
                export_score_results(
                    _inventory("ML-KEM-768"), tmp_path / "k.csv", "csv"
                ).read_text(encoding="utf-8")
            )
        )
    )
    assert row["key_size_bits_scored"] == ""
    assert row["key_size_source"] == ""


def test_pdr_records_the_conflict_and_verifies(tmp_path: Path) -> None:
    document = generate_pdr_document(_inventory("RSA-2048", 4096)).model_dump(mode="json")
    [record] = document["records"]

    assert record["observed_state"]["key_size_bits"] == 4096
    assert D2_MESSAGE in record["assumptions_made"]
    assert "conflicting_key_size" in record["evidence_review"]["blocking_finding_codes"]
    assert record["decision"]["execution_state"] == "gated"
    assert "cryptographic_parameters" in record["decision"]["verification_requirements"]

    path = tmp_path / "new.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    result = verify_pdr_file(path)
    assert result.passed
    assert result.pdr_version == "0.3"


def test_pdr_keeps_declared_null_and_states_identifier_source() -> None:
    document = generate_pdr_document(_inventory("RSA-2048")).model_dump(mode="json")
    [record] = document["records"]

    assert record["observed_state"]["key_size_bits"] is None
    assert (
        "Key size 2048 bits taken from the algorithm identifier RSA-2048."
        in record["assumptions_made"]
    )
    assert "conflicting_key_size" not in record["evidence_review"]["blocking_finding_codes"]


# CBOM import


def _cbom(properties: dict[str, object], name: str = "Component") -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "component",
                "name": name,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": properties},
            }
        ],
    }


@pytest.mark.parametrize(
    ("properties", "name", "algorithm", "key_size_bits"),
    [
        ({"algorithm": "X25519MLKEM768"}, "Component", "X25519MLKEM768", None),
        ({"algorithm": "SecP384r1MLKEM1024"}, "Component", "SecP384r1MLKEM1024", None),
        ({"parameterSetIdentifier": "ML-KEM-768"}, "Component", "ML-KEM-768", None),
        ({"algorithmFamily": "ML-KEM", "parameterSetIdentifier": "768"}, "Component", "ML-KEM-768", None),
        ({"algorithmFamily": "ML-DSA", "parameterSetIdentifier": "65"}, "Component", "ML-DSA-65", None),
        ({"algorithmFamily": "AES", "parameterSetIdentifier": "128"}, "Component", "AES-128", None),
        ({"algorithm": "SHA-256"}, "Component", "SHA-256", None),
        ({"algorithmFamily": "RSA"}, "billing-api-v202", "RSA", None),
        ({"algorithmFamily": "RSA"}, "Signing key 4096 service", "RSA", None),
        ({"algorithmFamily": "RSA", "keySize": 4096}, "Component", "RSA", 4096),
        ({"algorithmFamily": "RSA", "parameterSetIdentifier": "512"}, "Component", "RSA", None),
        (
            {"algorithmFamily": "RSA", "parameterSetIdentifier": "512", "algorithm": "RSA-2048"},
            "Component",
            "RSA-2048",
            None,
        ),
        ({"parameterSetIdentifier": "RSA-2048", "keySizeBits": "4096"}, "Component", "RSA-2048", 4096),
        ({"algorithmFamily": "AES", "keyLength": "256"}, "Component", "AES", 256),
        # algorithm repeating only the family is not a full identifier.
        (
            {"algorithmFamily": "ML-KEM", "algorithm": "ML-KEM", "parameterSetIdentifier": "768"},
            "Component",
            "ML-KEM-768",
            None,
        ),
        (
            {"algorithmFamily": "ML-DSA", "algorithm": "ML-DSA", "parameterSetIdentifier": "65"},
            "Component",
            "ML-DSA-65",
            None,
        ),
        (
            {"algorithmFamily": "AES", "algorithm": "AES", "parameterSetIdentifier": "128"},
            "Component",
            "AES-128",
            None,
        ),
        ({"algorithm": "ML-KEM", "parameterSetIdentifier": "768"}, "Component", "ML-KEM-768", None),
        # The same family written with a space or an underscore.
        (
            {"algorithmFamily": "ML-KEM", "algorithm": "ML KEM", "parameterSetIdentifier": "768"},
            "Component",
            "ML-KEM-768",
            None,
        ),
        (
            {"algorithmFamily": "ML-DSA", "algorithm": "ML DSA", "parameterSetIdentifier": "65"},
            "Component",
            "ML-DSA-65",
            None,
        ),
        ({"algorithm": "ML KEM", "parameterSetIdentifier": "768"}, "Component", "ML-KEM-768", None),
        ({"algorithm": "ML DSA", "parameterSetIdentifier": "65"}, "Component", "ML-DSA-65", None),
        ({"algorithmFamily": "ML KEM", "parameterSetIdentifier": "768"}, "Component", "ML-KEM-768", None),
        (
            {"algorithmFamily": "ml_kem", "algorithm": "ML-KEM", "parameterSetIdentifier": "1024"},
            "Component",
            "ML-KEM-1024",
            None,
        ),
        (
            {"algorithmFamily": "RSA", "algorithm": "RSA-2048", "parameterSetIdentifier": "512"},
            "Component",
            "RSA-2048",
            None,
        ),
        (
            {"algorithmFamily": "RSA", "algorithm": "RSA", "parameterSetIdentifier": "512"},
            "Component",
            "RSA",
            None,
        ),
        ({"algorithm": "RSA-2048", "parameterSetIdentifier": "RSA-2048"}, "Component", "RSA-2048", None),
    ],
)
def test_importer_keeps_source_identifiers_and_explicit_sizes(
    properties: dict[str, object],
    name: str,
    algorithm: str,
    key_size_bits: int | None,
) -> None:
    [asset] = inventory_from_cbom(_cbom(properties, name)).assets

    assert asset.algorithm == algorithm
    assert asset.key_size_bits == key_size_bits


@pytest.mark.parametrize(
    ("properties", "risk"),
    [
        ({"algorithmFamily": "ML-KEM", "algorithm": "ML-KEM", "parameterSetIdentifier": "768"}, 1.5),
        ({"algorithmFamily": "ML-DSA", "algorithm": "ML-DSA", "parameterSetIdentifier": "65"}, 1.5),
        ({"algorithmFamily": "AES", "algorithm": "AES", "parameterSetIdentifier": "128"}, 2.0),
        ({"algorithmFamily": "ML-KEM", "algorithm": "ML KEM", "parameterSetIdentifier": "768"}, 1.5),
        ({"algorithmFamily": "ML-DSA", "algorithm": "ML DSA", "parameterSetIdentifier": "65"}, 1.5),
        ({"algorithm": "ML KEM", "parameterSetIdentifier": "768"}, 1.5),
        ({"algorithm": "ML DSA", "parameterSetIdentifier": "65"}, 1.5),
    ],
)
def test_family_repeated_in_algorithm_keeps_the_exact_identifier(
    properties: dict[str, object], risk: float
) -> None:
    inventory = inventory_from_cbom(_cbom(properties))
    [score] = score_inventory(inventory)
    [assessment] = assess_inventory(inventory)
    codes = {finding.code for finding in assessment.evidence_review.findings}

    assert score.breakdown.cryptographic_risk == risk
    assert assessment.decision.execution_state.value != "verification_first"
    assert "missing_key_size_bits" not in codes
    assert "unverified_algorithm_parameters" not in codes


CONFLICT_CBOM = _cbom(
    {"primitive": "signature", "parameterSetIdentifier": "RSA-2048", "keySize": 4096},
    "Customer API RSA Signing Key",
)


def test_native_yaml_direct_cbom_and_imported_yaml_agree(tmp_path: Path) -> None:
    cbom_path = tmp_path / "conflict.cbom.json"
    cbom_path.write_text(json.dumps(CONFLICT_CBOM), encoding="utf-8")
    imported_path = tmp_path / "imported.yaml"
    write_imported_inventory(cbom_path, imported_path)
    imported = load_inventory(imported_path)
    [imported_asset] = imported.assets
    # Native YAML with the same fields and business context as the import.
    native_path = _write(tmp_path, imported, "native.yaml")

    assert (imported_asset.algorithm, imported_asset.key_size_bits) == ("RSA-2048", 4096)

    records = {}
    for label, command in {
        "direct_cbom": ["pdr", "generate", str(cbom_path), "--input-format", "cbom"],
        "imported_yaml": ["pdr", "generate", str(imported_path)],
        "native_yaml": ["pdr", "generate", str(native_path)],
    }.items():
        output = tmp_path / f"{label}.pdr.json"
        result = runner.invoke(app, [*command, "-o", str(output)])
        assert result.exit_code == 0, result.output
        assert verify_pdr_file(output).passed
        [records[label]] = json.loads(output.read_text(encoding="utf-8"))["records"]

    for label, record in records.items():
        assert record["observed_state"]["algorithm"] == "RSA-2048", label
        assert record["observed_state"]["key_size_bits"] == 4096, label
        assert record["decision"]["execution_state"] == "gated", label
        assert "cryptographic_parameters" in record["decision"]["verification_requirements"], label
        assert "conflicting_key_size" in record["evidence_review"]["blocking_finding_codes"], label
        assert D2_MESSAGE in record["assumptions_made"], label
    assert records["imported_yaml"]["decision"] == records["native_yaml"]["decision"]

    for label, command in {
        "direct_cbom": ["review", "evidence", str(cbom_path), "--input-format", "cbom"],
        "imported_yaml": ["review", "evidence", str(imported_path)],
        "native_yaml": ["review", "evidence", str(native_path)],
    }.items():
        result = runner.invoke(app, command)
        assert "conflicting_key_size" in _flat(result.output), label

    scores = {}
    for label, path in {"imported_yaml": imported_path, "native_yaml": native_path}.items():
        [scores[label]] = json.loads(
            export_score_results(load_inventory(path), tmp_path / f"{label}.json", "json").read_text(
                encoding="utf-8"
            )
        )["ranked"]
    for record in scores.values():
        assert record["key_size_bits_scored"] == 2048
        assert record["key_size_source"] == "conflict_smaller"
        assert record["breakdown"]["cryptographic_risk"] == 9.0
    assert scores["imported_yaml"]["breakdown"] == scores["native_yaml"]["breakdown"]


@pytest.mark.parametrize(
    ("properties", "algorithm"),
    [
        ({"algorithmFamily": "ML-KEM", "algorithm": "ML KEM", "parameterSetIdentifier": "768"}, "ML-KEM-768"),
        ({"algorithmFamily": "ML-DSA", "algorithm": "ML DSA", "parameterSetIdentifier": "65"}, "ML-DSA-65"),
        ({"algorithm": "ML KEM", "parameterSetIdentifier": "768"}, "ML-KEM-768"),
    ],
)
def test_pdr_from_cbom_keeps_the_parameter_set_for_spaced_family(
    properties: dict[str, object], algorithm: str, tmp_path: Path
) -> None:
    cbom_path = tmp_path / "spaced.cbom.json"
    cbom_path.write_text(json.dumps(_cbom(properties)), encoding="utf-8")
    output = tmp_path / "spaced.pdr.json"

    result = runner.invoke(
        app, ["pdr", "generate", str(cbom_path), "--input-format", "cbom", "-o", str(output)]
    )

    assert result.exit_code == 0, result.output
    [record] = json.loads(output.read_text(encoding="utf-8"))["records"]
    assert record["observed_state"]["algorithm"] == algorithm
    assert record["observed_state"]["quantum_status"] == "quantum_resistant"
    assert record["decision"]["execution_state"] != "verification_first"
    assert verify_pdr_file(output).passed
