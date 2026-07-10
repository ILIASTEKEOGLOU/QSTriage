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


def test_cbom_pdr_includes_evidence_review_policy_target_findings() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )

    for record in document.records:
        assert {
            "cbom_defaulted_context_blocks_decision_grade",
            "unknown_dependency_completeness_blocks_decision_grade",
        }.issubset(record.policy_evaluation.applied_rule_ids)
        assert {
            "cbom_defaulted_context_blocks_decision_grade",
            "unknown_dependency_completeness_blocks_decision_grade",
        }.issubset(record.policy_evaluation.blocking_rule_ids)


def test_cbom_pdr_policy_target_evaluation_is_deterministic() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    first = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )
    second = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )

    assert first.run_id == second.run_id
    assert first.document_hash == second.document_hash
    assert [record.record_integrity.record_hash for record in first.records] == [
        record.record_integrity.record_hash for record in second.records
    ]


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


def test_pdr_records_include_policy_evaluation_metadata_from_policy_context() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)

    for record in document.records:
        assert record.policy_evaluation.policy_pack_id == (
            document.policy_context.policy_pack_id
        )
        assert record.policy_evaluation.policy_pack_version == (
            document.policy_context.policy_pack_version
        )
        assert record.policy_evaluation.policy_pack_hash == (
            document.policy_context.policy_pack_hash
        )


def test_public_api_gateway_pdr_includes_asset_level_policy_rules() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    gateway_record = record_by_asset["public-api-gateway"]

    assert {
        "quantum_vulnerable_public_key_requires_pqc_migration_review",
        "long_retention_sensitive_data_raises_priority",
        "public_or_partner_exposed_quantum_vulnerable_crypto_raises_priority",
    }.issubset(gateway_record.policy_evaluation.applied_rule_ids)
    assert "long_retention_years" in gateway_record.policy_evaluation.thresholds_applied


def test_ml_kem_cbom_pdr_includes_asset_level_policy_rules() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )
    record_by_asset = {record.observed_state.asset_id: record for record in document.records}

    ml_kem_record = record_by_asset["crypto-ml-kem-768"]

    assert {
        "standardized_pqc_can_be_retained_with_operational_review",
        "ml_kem_usage_requires_key_establishment_context",
    }.issubset(ml_kem_record.policy_evaluation.applied_rule_ids)


def test_unknown_algorithm_pdr_includes_manual_review_policy_evaluation() -> None:
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
    record = document.records[0]

    assert "unknown_algorithm_requires_manual_crypto_review" in (
        record.policy_evaluation.applied_rule_ids
    )
    assert record.policy_evaluation.human_review_required is True


def test_pdr_policy_evaluation_findings_are_scoped_to_record_asset() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)

    for record in document.records:
        assert record.policy_evaluation.findings
        for finding in record.policy_evaluation.findings:
            assert finding.asset_id == record.observed_state.asset_id

def test_pdr_policy_context_remains_document_level_provenance_only() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    policy_context_fields = type(document.policy_context).model_fields

    assert document.records[0].policy_context == document.policy_context
    assert "applied_rule_ids" not in policy_context_fields
    assert "policy_findings" not in policy_context_fields


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


def test_pdr_projects_canonical_decision_for_score_action_divergence() -> None:
    inventory = load_inventory(SAMPLE_INVENTORY)

    document = generate_pdr_document(inventory, source_path=SAMPLE_INVENTORY)
    record_by_asset = {
        record.observed_state.asset_id: record for record in document.records
    }

    payments = record_by_asset["payments-api"]
    ot_gateway = record_by_asset["ot-gateway"]

    assert document.pdr_version == "0.2"
    assert payments.pdr_version == "0.2"
    assert payments.decision.risk_attention_score == 81.0
    assert payments.decision.risk_attention_band == "high"
    assert payments.decision.execution_state.value == "justified"
    assert payments.decision.action_type.value == "simulate_before_migration"
    assert payments.decision.verification_priority.value == "none"
    assert payments.decision.verification_requirements == []
    assert "migration:simulation_required" in payments.decision.reason_codes

    assert ot_gateway.decision.risk_attention_band == "medium"
    assert ot_gateway.decision.action_type.value == "simulate_before_migration"
    assert ot_gateway.decision.human_review_required is True

    serialized = payments.decision.model_dump(mode="json")
    assert "priority_score" not in serialized
    assert "priority_band" not in serialized
    assert "recommended_action" not in serialized


def test_cbom_pdr_projects_canonical_gating_and_verification() -> None:
    inventory = import_cbom_inventory(SAMPLE_CBOM)

    document = generate_pdr_document(
        inventory,
        source_path=SAMPLE_CBOM,
        source_type="cyclonedx_cbom",
        source_version="1.6",
    )
    record_by_asset = {
        record.observed_state.asset_id: record for record in document.records
    }

    rsa_record = record_by_asset["crypto-rsa-2048"]

    assert rsa_record.decision.execution_state.value == "gated"
    assert rsa_record.decision.action_type.value == "migration_planning"
    assert rsa_record.decision.verification_priority.value == "high"
    assert {
        requirement.value
        for requirement in rsa_record.decision.verification_requirements
    } == {
        "business_context",
        "dependency_context",
        "operational_context",
        "supply_chain_context",
        "policy_resolution",
    }
    assert rsa_record.decision.confidence_score == 0.0
    assert rsa_record.decision.human_review_required is True
    assert "confidence:below_decision_grade_threshold" in (
        rsa_record.decision.reason_codes
    )
