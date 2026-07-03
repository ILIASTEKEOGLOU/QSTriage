from pydantic import ValidationError
import pytest

from qstriage.policy import (
    POLICY_PACK_SCHEMA_VERSION,
    PolicyApplicability,
    PolicyApplicabilityTarget,
    PolicyEvaluationResult,
    PolicyFinding,
    PolicyPack,
    PolicyReference,
    PolicyRule,
    PolicyRuleEffect,
    PolicySeverity,
    PolicyThreshold,
)


def _reference(reference_id: str = "NIST-FIPS-203") -> PolicyReference:
    return PolicyReference(
        reference_id=reference_id,
        title="NIST FIPS 203 — ML-KEM",
        version="final",
        notes="Referenced as a standards source for PQC key establishment.",
    )


def _threshold(
    threshold_id: str = "minimum_decision_grade_confidence",
) -> PolicyThreshold:
    return PolicyThreshold(
        threshold_id=threshold_id,
        title="Minimum decision-grade confidence",
        value=0.75,
        rationale=(
            "PDR decisions below this confidence require review before they are "
            "treated as decision-grade."
        ),
    )


def _rule(
    rule_id: str = "quantum_vulnerable_public_key_requires_pqc_migration_review",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        title="Quantum-vulnerable public-key crypto requires PQC migration review",
        description=(
            "Flags quantum-vulnerable public-key cryptography for migration review."
        ),
        applicability=PolicyApplicability(
            target=PolicyApplicabilityTarget.asset,
            conditions={
                "primitive": "public_key",
                "quantum_status": "quantum_vulnerable",
            },
        ),
        severity=PolicySeverity.high,
        effects=[
            PolicyRuleEffect.raises_priority,
            PolicyRuleEffect.requires_human_review,
            PolicyRuleEffect.adds_policy_context,
        ],
        rationale=(
            "RSA, finite-field DH, and ECC are not safe against a "
            "cryptographically relevant quantum computer."
        ),
        recommendation="Review the asset for hybrid or PQC migration planning.",
        references=["NIST-FIPS-203"],
    )


def _policy_pack() -> PolicyPack:
    return PolicyPack(
        policy_pack_id="nist-pqc-basic",
        version="0.1",
        title="NIST PQC Basic",
        description="Baseline standards-backed policy pack for PQC migration triage.",
        standards_references=[_reference()],
        thresholds=[_threshold()],
        rules=[_rule()],
        notes="Local-first QSTriage policy pack for deterministic PDR policy context.",
    )


def test_policy_pack_is_explicit_versioned_and_serializable() -> None:
    pack = _policy_pack()

    dumped = pack.model_dump(mode="json")

    assert dumped["policy_pack_id"] == "nist-pqc-basic"
    assert dumped["version"] == "0.1"
    assert dumped["title"] == "NIST PQC Basic"
    assert dumped["schema_version"] == POLICY_PACK_SCHEMA_VERSION
    assert dumped["standards_references"][0]["reference_id"] == "NIST-FIPS-203"
    assert dumped["thresholds"][0]["threshold_id"] == (
        "minimum_decision_grade_confidence"
    )
    assert dumped["rules"][0]["rule_id"] == (
        "quantum_vulnerable_public_key_requires_pqc_migration_review"
    )


def test_policy_pack_hash_is_deterministic() -> None:
    pack_a = _policy_pack()
    pack_b = PolicyPack.model_validate(pack_a.model_dump(mode="json"))

    assert pack_a.canonical_json() == pack_b.canonical_json()
    assert pack_a.policy_pack_hash() == pack_b.policy_pack_hash()
    assert pack_a.policy_pack_hash().startswith("sha256:")
    assert len(pack_a.policy_pack_hash()) == 71


def test_policy_pack_hash_changes_when_policy_changes() -> None:
    original = _policy_pack()
    changed = original.model_copy(
        update={
            "thresholds": [
                _threshold().model_copy(update={"value": 0.80})
            ]
        }
    )

    assert original.policy_pack_hash() != changed.policy_pack_hash()


def test_policy_pack_exposes_context_inputs_for_future_pdr_integration() -> None:
    pack = _policy_pack()

    assert pack.rule_ids() == [
        "quantum_vulnerable_public_key_requires_pqc_migration_review"
    ]
    assert pack.standards_applied() == ["NIST-FIPS-203"]
    assert pack.threshold_ids() == ["minimum_decision_grade_confidence"]


def test_policy_finding_marks_human_review_and_blocking_rules() -> None:
    finding = PolicyFinding(
        rule_id="missing_business_context_requires_human_review",
        severity=PolicySeverity.high,
        message="Business context is missing.",
        effects=[
            PolicyRuleEffect.caps_confidence,
            PolicyRuleEffect.blocks_decision_grade,
            PolicyRuleEffect.requires_human_review,
        ],
        asset_id="public-api-gateway",
        field_path="assets[public-api-gateway].data_class",
        recommendation="Add data_class before treating the PDR as decision-grade.",
    )

    result = PolicyEvaluationResult(
        policy_pack_id="nist-pqc-basic",
        policy_pack_version="0.1",
        policy_pack_hash="sha256:" + "0" * 64,
        applied_rule_ids=["missing_business_context_requires_human_review"],
        standards_applied=["QSTRIAGE-SAFETY-POLICY"],
        thresholds_applied=["minimum_decision_grade_confidence"],
        findings=[finding],
    )

    assert finding.blocks_decision_grade is True
    assert finding.requires_human_review is True
    assert result.blocking_rule_ids == ["missing_business_context_requires_human_review"]
    assert result.human_review_required is True


def test_policy_pack_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(ValidationError, match="Duplicate policy rule id"):
        PolicyPack(
            policy_pack_id="nist-pqc-basic",
            version="0.1",
            title="NIST PQC Basic",
            description="Baseline standards-backed policy pack for PQC migration triage.",
            standards_references=[_reference()],
            rules=[
                _rule("duplicate-rule"),
                _rule("duplicate-rule"),
            ],
        )


def test_policy_pack_rejects_unknown_rule_reference() -> None:
    with pytest.raises(ValidationError, match="references unknown policy reference"):
        PolicyPack(
            policy_pack_id="nist-pqc-basic",
            version="0.1",
            title="NIST PQC Basic",
            description="Baseline standards-backed policy pack for PQC migration triage.",
            standards_references=[_reference("NIST-FIPS-203")],
            rules=[
                _rule().model_copy(update={"references": ["NIST-FIPS-999"]}),
            ],
        )


def test_policy_models_reject_unexpected_fields() -> None:
    with pytest.raises(ValidationError):
        PolicyRule.model_validate(
            {
                "rule_id": "bad-rule",
                "title": "Bad rule",
                "description": "Unexpected field should be rejected.",
                "applicability": {
                    "target": "asset",
                    "conditions": {},
                },
                "severity": "low",
                "rationale": "Strict models prevent silent policy drift.",
                "recommendation": "Remove unexpected fields.",
                "unexpected": True,
            }
        )


def test_builtin_policy_registry_lists_nist_pqc_basic() -> None:
    from qstriage.policy import list_policy_packs

    packs = list_policy_packs()

    assert [pack.policy_pack_id for pack in packs] == ["nist-pqc-basic"]
    assert packs[0].version == "0.1"
    assert packs[0].title == "NIST PQC Basic"


def test_builtin_policy_pack_contains_expected_references_thresholds_and_rules() -> None:
    from qstriage.policy import get_policy_pack

    pack = get_policy_pack("nist-pqc-basic")

    assert pack.policy_pack_id == "nist-pqc-basic"
    assert "NIST-FIPS-203" in pack.standards_applied()
    assert "NIST-SP-800-131A-REV3-IPD" in pack.standards_applied()
    assert "CISA-PQC-DISCOVERY-INVENTORY" in pack.standards_applied()
    assert "QSTRIAGE-SAFETY-POLICY" in pack.standards_applied()
    assert "minimum_decision_grade_confidence" in pack.threshold_ids()
    assert "cbom_default_confidence_cap" in pack.threshold_ids()
    assert "long_retention_years" in pack.threshold_ids()
    assert (
        "quantum_vulnerable_public_key_requires_pqc_migration_review"
        in pack.rule_ids()
    )
    assert "missing_business_context_requires_human_review" in pack.rule_ids()
    assert "ml_kem_usage_requires_key_establishment_context" in pack.rule_ids()


def test_builtin_policy_pack_hash_is_deterministic_across_loads() -> None:
    from qstriage.policy import get_policy_pack

    pack_a = get_policy_pack("nist-pqc-basic")
    pack_b = get_policy_pack("nist-pqc-basic")

    assert pack_a.canonical_json() == pack_b.canonical_json()
    assert pack_a.policy_pack_hash() == pack_b.policy_pack_hash()
    assert pack_a.policy_pack_hash().startswith("sha256:")


def test_builtin_policy_pack_is_returned_as_fresh_instance() -> None:
    from qstriage.policy import get_policy_pack

    pack_a = get_policy_pack("nist-pqc-basic")
    pack_b = get_policy_pack("nist-pqc-basic")

    assert pack_a is not pack_b
    assert pack_a == pack_b


def test_unknown_policy_pack_is_rejected() -> None:
    from qstriage.policy import get_policy_pack

    with pytest.raises(ValueError, match="Unknown policy pack"):
        get_policy_pack("unknown-pack")
