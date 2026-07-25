import json
from pathlib import Path

import pytest

from qstriage.standards import (
    SOURCE_FIPS_180_4,
    SOURCE_FIPS_197,
    SOURCE_FIPS_202,
    SOURCE_FIPS_203,
    SOURCE_FIPS_204,
    SOURCE_FIPS_205,
    SOURCE_NIST_IR_8547,
    SOURCE_QSTRIAGE_SAFETY_POLICY,
    SOURCE_SP_800_57,
    classify_algorithm,
)


COMPATIBILITY_CORPUS_PATH = (
    Path(__file__).parent / "fixtures" / "algorithm_identifier_compatibility.json"
)


def _load_compatibility_corpus() -> dict[str, object]:
    return json.loads(COMPATIBILITY_CORPUS_PATH.read_text(encoding="utf-8"))


def test_classifies_rsa_as_quantum_vulnerable_public_key_crypto() -> None:
    classification = classify_algorithm("RSA-2048")

    assert classification.algorithm_family == "RSA"
    assert classification.quantum_status == "quantum_vulnerable"
    assert classification.standard_status == "classical_public_key"
    assert classification.recommended_action == "migrate_to_hybrid_or_pqc_path"
    assert classification.source_ids == (SOURCE_NIST_IR_8547,)


def test_classifies_diffie_hellman_as_quantum_vulnerable_key_establishment() -> None:
    classification = classify_algorithm("finite-field DH")

    assert classification.algorithm_family == "DH"
    assert classification.primitive == "key_establishment"
    assert classification.quantum_status == "quantum_vulnerable"
    assert classification.source_ids == (SOURCE_NIST_IR_8547,)


def test_classifies_ecc_family_as_quantum_vulnerable() -> None:
    for algorithm in ("ECDSA P-256", "ECDH", "X25519", "Ed25519"):
        classification = classify_algorithm(algorithm)

        assert classification.algorithm_family == "ECC"
        assert classification.quantum_status == "quantum_vulnerable"
        assert classification.source_ids == (SOURCE_NIST_IR_8547,)


def test_classifies_ml_kem_as_standardized_pqc_kem() -> None:
    classification = classify_algorithm("ML-KEM-768")

    assert classification.algorithm_family == "ML-KEM"
    assert classification.primitive == "key_encapsulation"
    assert classification.quantum_status == "quantum_resistant"
    assert classification.standard_status == "standardized_pqc"
    assert classification.source_ids == (SOURCE_FIPS_203,)


def test_classifies_ml_dsa_as_standardized_pqc_signature() -> None:
    classification = classify_algorithm("ML-DSA-65")

    assert classification.algorithm_family == "ML-DSA"
    assert classification.primitive == "digital_signature"
    assert classification.quantum_status == "quantum_resistant"
    assert classification.source_ids == (SOURCE_FIPS_204,)


def test_classifies_slh_dsa_as_standardized_pqc_signature_with_operational_review() -> None:
    classification = classify_algorithm("SLH-DSA-SHA2-128S")

    assert classification.algorithm_family == "SLH-DSA"
    assert classification.primitive == "digital_signature"
    assert classification.quantum_status == "quantum_resistant"
    assert classification.recommended_action == "acceptable_pqc_signature_with_operational_review"
    assert classification.source_ids == (SOURCE_FIPS_205,)


def test_classifies_aes_as_symmetric_not_public_key_migration_target() -> None:
    classification = classify_algorithm("AES-256")

    assert classification.algorithm_family == "AES"
    assert classification.primitive == "symmetric_encryption"
    assert classification.quantum_status == "symmetric_grover_affected"
    assert classification.recommended_action == "review_key_strength_not_public_key_migration"
    assert classification.source_ids == (SOURCE_FIPS_197, SOURCE_SP_800_57)


def test_classifies_sha2_family_as_hash_not_key_migration_target() -> None:
    classification = classify_algorithm("SHA-256")

    assert classification.algorithm_family == "SHA-1/SHA-2"
    assert classification.primitive == "hash"
    assert classification.quantum_status == "not_public_key"
    assert classification.source_ids == (SOURCE_FIPS_180_4,)


def test_classifies_sha3_and_shake_as_hash_or_xof() -> None:
    for algorithm in ("SHA3-256", "SHA-3-512", "SHAKE256"):
        classification = classify_algorithm(algorithm)

        assert classification.algorithm_family == "SHA-3"
        assert classification.primitive == "hash_or_xof"
        assert classification.quantum_status == "not_public_key"
        assert classification.source_ids == (SOURCE_FIPS_202,)


def test_unknown_algorithm_requires_manual_review() -> None:
    classification = classify_algorithm("MysteryCrypto-1")

    assert classification.algorithm_family == "unknown"
    assert classification.quantum_status == "unknown"
    assert classification.recommended_action == "manual_review_required"
    assert classification.source_ids == (SOURCE_QSTRIAGE_SAFETY_POLICY,)


def test_blank_algorithm_requires_manual_review() -> None:
    classification = classify_algorithm(" ")

    assert classification.algorithm_family == "unknown"
    assert classification.recommended_action == "manual_review_required"
    assert classification.source_ids == (SOURCE_QSTRIAGE_SAFETY_POLICY,)


def test_normalizes_case_underscores_and_spaces() -> None:
    classification = classify_algorithm("ml_kem 768")

    assert classification.algorithm_family == "ML-KEM"
    assert classification.source_ids == (SOURCE_FIPS_203,)


def test_classifies_compound_tls_public_key_identifier_as_quantum_vulnerable() -> None:
    classification = classify_algorithm("ECDHE_RSA")

    assert classification.algorithm_family == "classical_public_key_composite"
    assert classification.primitive == "key_establishment_and_signature"
    assert classification.quantum_status == "quantum_vulnerable"
    assert classification.recommended_action == "migrate_to_hybrid_or_pqc_path"
    assert classification.source_ids == (SOURCE_NIST_IR_8547,)


@pytest.mark.parametrize(
    "algorithm",
    (
        "universal-cipher",
        "MARSALA",
        "TORSA-HASH",
        "APP-256",
        "ECCENTRIC-V2",
        "NOT-DIFFIE-HELLMANISH",
        "FFDHELIUM",
        "SHAKEWEIGHT",
    ),
)
def test_adversarial_lookalikes_remain_unrecognized(algorithm: str) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == "unknown"
    assert classification.identifier_resolution == "unrecognized_identifier"
    assert classification.quantum_status == "unknown"
    assert classification.standard_status == "unknown"
    assert classification.recommended_action == "manual_review_required"


@pytest.mark.parametrize(
    ("algorithm", "family", "source_id"),
    (
        ("ML-KEM-512", "ML-KEM", SOURCE_FIPS_203),
        ("ML-KEM-768", "ML-KEM", SOURCE_FIPS_203),
        ("ML-KEM-1024", "ML-KEM", SOURCE_FIPS_203),
        ("ML-DSA-44", "ML-DSA", SOURCE_FIPS_204),
        ("ML-DSA-65", "ML-DSA", SOURCE_FIPS_204),
        ("ML-DSA-87", "ML-DSA", SOURCE_FIPS_204),
        ("SLH-DSA-SHA2-128S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHA2-128F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHA2-192S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHA2-192F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHA2-256S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHA2-256F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-128S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-128F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-192S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-192F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-256S", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-SHAKE-256F", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH_DSA_SHA2_128S", "SLH-DSA", SOURCE_FIPS_205),
    ),
)
def test_only_exact_pqc_parameter_sets_receive_standardized_status(
    algorithm: str,
    family: str,
    source_id: str,
) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == family
    assert classification.identifier_resolution == "exact_identifier"
    assert classification.quantum_status == "quantum_resistant"
    assert classification.standard_status == "standardized_pqc"
    assert source_id in classification.source_ids


@pytest.mark.parametrize(
    ("algorithm", "family", "family_source"),
    (
        ("ML-KEM", "ML-KEM", SOURCE_FIPS_203),
        ("ML-KEM-9999", "ML-KEM", SOURCE_FIPS_203),
        ("ML-DSA", "ML-DSA", SOURCE_FIPS_204),
        ("ML-DSA-17", "ML-DSA", SOURCE_FIPS_204),
        ("SLH-DSA", "SLH-DSA", SOURCE_FIPS_205),
        ("SLH-DSA-BANANA", "SLH-DSA", SOURCE_FIPS_205),
    ),
)
def test_pqc_family_with_unverified_parameters_preserves_family_without_approval(
    algorithm: str,
    family: str,
    family_source: str,
) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == family
    assert (
        classification.identifier_resolution
        == "recognized_family_unverified_parameters"
    )
    assert classification.quantum_status == "unknown"
    assert classification.standard_status == "unknown"
    assert (
        classification.recommended_action
        == "verify_exact_parameter_set_before_classification"
    )
    assert classification.source_ids == (
        family_source,
        SOURCE_QSTRIAGE_SAFETY_POLICY,
    )


@pytest.mark.parametrize(
    ("algorithm", "family"),
    (
        ("RSA-OAEP", "RSA"),
        ("RSASSA-PSS", "RSA"),
        ("SHA256withRSA", "RSA"),
        ("RSA2048", "RSA"),
        ("ECDHE-RSA-AES128-GCM-SHA256", "classical_public_key_composite"),
        ("ECDHE_RSA", "classical_public_key_composite"),
        ("finite-field DH", "DH"),
        ("ECDSA P-256", "ECC"),
        ("X25519", "ECC"),
        ("Ed25519", "ECC"),
        ("SHA3-256", "SHA-3"),
        ("SHAKE256", "SHA-3"),
    ),
)
def test_existing_enterprise_identifier_forms_remain_exact_matches(
    algorithm: str,
    family: str,
) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == family
    assert classification.identifier_resolution == "exact_identifier"


def test_separator_runs_normalize_without_splitting_alphabetic_tokens() -> None:
    classification = classify_algorithm("  ml__kem / 768  ")

    assert classification.algorithm_family == "ML-KEM"
    assert classification.identifier_resolution == "exact_identifier"
    assert classification.standard_status == "standardized_pqc"


@pytest.mark.parametrize(
    "algorithm",
    ("secp256r1", "prime256v1", "brainpoolP256r1", "X448", "Ed448"),
)
def test_deferred_curve_aliases_remain_outside_the_hotfix(algorithm: str) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == "unknown"
    assert classification.identifier_resolution == "unrecognized_identifier"
    assert classification.standard_status == "unknown"


@pytest.mark.parametrize(
    "case",
    _load_compatibility_corpus()["entries"],
    ids=lambda case: case["identifier"],
)
def test_source_backed_identifier_compatibility_corpus(
    case: dict[str, object],
) -> None:
    classification = classify_algorithm(str(case["identifier"]))

    assert classification.algorithm_family == case["expected_family"]
    assert classification.identifier_resolution == case["expected_resolution"]
    assert classification.quantum_status == "quantum_vulnerable"
    assert classification.standard_status == "classical_public_key"


def test_compatibility_corpus_has_resolvable_provenance() -> None:
    corpus = _load_compatibility_corpus()
    sources = corpus["sources"]
    entries = corpus["entries"]

    assert corpus["schema_version"] == "1.0"
    assert sources
    assert all(str(url).startswith("https://") for url in sources.values())
    assert len({case["identifier"] for case in entries}) == len(entries)
    assert {
        case["identifier"]
        for case in entries
        if case["change_kind"] == "new_bounded_alias"
    } == {"DHE", "EDH"}

    for case in entries:
        assert case["reviewed_in"] == "v1.2.1"
        assert case["change_kind"] in {
            "compatibility_restoration",
            "new_bounded_alias",
        }
        assert case["source_ids"]
        assert set(case["source_ids"]) <= set(sources)


@pytest.mark.parametrize(
    "algorithm",
    (
        "DHELIUM",
        "EDHELP",
        "RSA-PSSX",
        "rsaEncryptionExtra",
        "id-RSASSA-PSS-EXTRA",
        "RSAES-OAEP-EXTRA",
        "id-RSAES-OAEP-EXTRA",
        "SHA256withRSAEncryptionExtra",
        "md5WithRSAEncryptionExtra",
        "MD5withRSAX",
        "SHA256withECDSAX",
        "SHA256withECDSAExtra",
        "XSHA256withECDSA",
        "TLS_RSAX_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256_EXTRA",
    ),
)
def test_compatibility_alias_lookalikes_remain_unrecognized(
    algorithm: str,
) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == "unknown"
    assert classification.identifier_resolution == "unrecognized_identifier"
    assert classification.quantum_status == "unknown"
    assert classification.standard_status == "unknown"


@pytest.mark.parametrize(
    ("algorithm", "family", "resolution"),
    (
        ("SRP-RSA-AES-256-CBC-SHA", "unknown", "unrecognized_identifier"),
        ("RSA-PSK-AES128-GCM-SHA256", "unknown", "unrecognized_identifier"),
        ("AECDH-NULL-SHA", "unknown", "unrecognized_identifier"),
        ("rsassaPss", "unknown", "unrecognized_identifier"),
        ("RSAPSS", "unknown", "unrecognized_identifier"),
        ("X25519MLKEM768", "unknown", "unrecognized_identifier"),
        (
            "ML-KEM-768+X25519",
            "ML-KEM",
            "recognized_family_unverified_parameters",
        ),
    ),
)
def test_deferred_identifier_grammars_remain_fail_closed_in_v1_2_1(
    algorithm: str,
    family: str,
    resolution: str,
) -> None:
    classification = classify_algorithm(algorithm)

    assert classification.algorithm_family == family
    assert classification.identifier_resolution == resolution
    assert classification.quantum_status == "unknown"
    assert classification.standard_status == "unknown"
