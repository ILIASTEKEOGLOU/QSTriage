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
