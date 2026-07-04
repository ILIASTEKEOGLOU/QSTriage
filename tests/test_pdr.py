from pathlib import Path

from qstriage import __version__
from qstriage.cbom import import_cbom_inventory
from qstriage.evidence import DecisionGrade
from qstriage.models import CryptographicAsset, Inventory, load_inventory
from qstriage.pdr import generate_pdr_document


SAMPLE_INVENTORY = Path("examples/sample_inventory.yaml")
SAMPLE_CBOM = Path("tests/fixtures/sample_cbom.json")


def test_generate_pdr_document_creates_one_record_per_asset() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_INVENTORY,
        source_type="qstriage_inventory",
        source_version="0.6.0",
    )

    assert len(document.records) == len(inventory.assets)
    assert document.input_snapshot.source_hash.startswith("sha256:")
    assert document.policy_context.policy_pack_id == "nist-pqc-basic"
    assert document.document_hash.startswith("sha256:")


def test_pdr_engine_version_uses_package_version() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)

    assert document.records[0].engine.version == __version__


def test_pdr_record_hash_is_deterministic_for_same_input() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    first = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    second = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)

    first_hashes = [record.record_integrity.record_hash for record in first.records]
    second_hashes = [record.record_integrity.record_hash for record in second.records]

    assert first_hashes == second_hashes
    assert first.document_hash == second.document_hash


def test_quantum_vulnerable_tls_asset_gets_pqc_target_state_suggestion() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    gateway_record = record_by_asset["public-api-gateway"]
    options = {suggestion.option for suggestion in gateway_record.target_state_suggestion}

    assert "hybrid_key_establishment_with_ml_kem_768" in options
    assert gateway_record.decision.human_review_required is True


def test_cbom_imported_assets_have_low_evidence_and_human_review() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    rsa_record = record_by_asset["crypto-rsa-2048"]

    assert rsa_record.input_snapshot.source_type == "cyclonedx_cbom"
    assert rsa_record.evidence_quality.score < 0.75
    assert "data_class" in rsa_record.evidence_quality.missing_evidence
    assert rsa_record.evidence_review.decision_grade == DecisionGrade.not_decision_grade
    assert "missing_data_class" in rsa_record.evidence_review.blocking_finding_codes
    assert rsa_record.decision_confidence.score <= rsa_record.evidence_review.confidence_cap
    assert rsa_record.decision.human_review_required is True


def test_standardized_ml_kem_cbom_asset_is_marked_as_existing_pqc_target() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    ml_kem_record = record_by_asset["crypto-ml-kem-768"]
    options = {suggestion.option for suggestion in ml_kem_record.target_state_suggestion}

    assert ml_kem_record.observed_state.quantum_status == "quantum_resistant"
    assert "retain_ml_kem" in options


def test_unknown_algorithm_pdr_generates_manual_review_record() -> None:
    inventory = Inventory(
        assets=[
            CryptographicAsset(
                id="unknown-crypto",
                name="Unknown Crypto Asset",
                environment="production",
                asset_type="service",
                protocol="tls",
                algorithm="MysteryCrypto",
                key_size_bits=None,
                data_class="customer_pii",
                retention_years=10,
                exposure="public",
                criticality="high",
                local_blast_radius="high",
                migration_effort="low",
            )
        ],
        dependencies=[],
        scenarios=[],
    )

    document = generate_pdr_document(inventory)

    assert document is not None
    assert len(document.records) == 1
    record = document.records[0]
    assert record.observed_state.algorithm == "MysteryCrypto"
    assert record.decision.human_review_required is True
    assert record.target_state_suggestion[0].option == (
        "manual_cryptographic_review_required"
    )


def test_pdr_records_include_structured_evidence_review() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    gateway_record = record_by_asset["public-api-gateway"]

    assert gateway_record.evidence_review.review_version == "0.1"
    assert 0.0 <= gateway_record.evidence_review.evidence_score <= 1.0
    assert 0.0 <= gateway_record.evidence_review.confidence_cap <= 1.0
    assert gateway_record.decision_confidence.score <= gateway_record.evidence_review.confidence_cap
    assert gateway_record.evidence_review.asset_id == "public-api-gateway"


def test_pdr_policy_context_comes_from_builtin_policy_pack() -> None:
    from qstriage.policy import get_policy_pack

    inventory = load_inventory(SAMPLE_INVENTORY)
    policy_pack = get_policy_pack("nist-pqc-basic")

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)

    assert document.policy_context.policy_pack_id == policy_pack.policy_pack_id
    assert document.policy_context.policy_pack_version == policy_pack.version
    assert document.policy_context.policy_pack_hash == policy_pack.policy_pack_hash()
    assert document.policy_context.standards_applied == policy_pack.standards_applied()
    assert document.records[0].policy_context == document.policy_context


def test_pdr_rejects_policy_pack_version_mismatch() -> None:
    import pytest

    inventory = load_inventory(SAMPLE_INVENTORY)

    with pytest.raises(ValueError, match="version mismatch"):
        generate_pdr_document(
            inventory,
            source_path=SAMPLE_INVENTORY,
            policy_pack_id="nist-pqc-basic",
            policy_pack_version="999.0",
        )

def test_pdr_hashes_are_stable_for_relative_and_absolute_source_paths() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    relative = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    absolute = generate_pdr_document(
        inventory,
        source_path=SAMPLE_INVENTORY.resolve(),
    )

    assert relative.run_id == absolute.run_id
    assert relative.document_hash == absolute.document_hash
    assert relative.records[0].record_integrity.record_hash == (
        absolute.records[0].record_integrity.record_hash
    )
    assert relative.input_snapshot.source_path == SAMPLE_INVENTORY.name
    assert absolute.input_snapshot.source_path == SAMPLE_INVENTORY.name
