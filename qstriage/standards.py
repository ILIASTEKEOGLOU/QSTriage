from __future__ import annotations

from dataclasses import dataclass


SOURCE_NIST_IR_8547 = "NIST-IR-8547-IPD"
SOURCE_FIPS_203 = "NIST-FIPS-203"
SOURCE_FIPS_204 = "NIST-FIPS-204"
SOURCE_FIPS_205 = "NIST-FIPS-205"
SOURCE_SP_800_57 = "NIST-SP-800-57-PART-1-REV-5"
SOURCE_FIPS_197 = "NIST-FIPS-197"
SOURCE_FIPS_180_4 = "NIST-FIPS-180-4"
SOURCE_FIPS_202 = "NIST-FIPS-202"
SOURCE_QSTRIAGE_SAFETY_POLICY = "QSTRIAGE-SAFETY-POLICY"


@dataclass(frozen=True)
class AlgorithmClassification:
    input_algorithm: str
    algorithm_family: str
    primitive: str
    quantum_status: str
    standard_status: str
    recommended_action: str
    rationale: str
    source_ids: tuple[str, ...]


def classify_algorithm(algorithm: str | None) -> AlgorithmClassification:
    original = (algorithm or "").strip()
    normalized = _normalize_algorithm(original)

    if not normalized:
        return _unknown_classification(original)

    if _matches_ml_kem(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="ML-KEM",
            primitive="key_encapsulation",
            quantum_status="quantum_resistant",
            standard_status="standardized_pqc",
            recommended_action="acceptable_pqc_kem",
            rationale=(
                "ML-KEM is classified as a standardized post-quantum key "
                "encapsulation mechanism."
            ),
            source_ids=(SOURCE_FIPS_203,),
        )

    if _matches_ml_dsa(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="ML-DSA",
            primitive="digital_signature",
            quantum_status="quantum_resistant",
            standard_status="standardized_pqc",
            recommended_action="acceptable_pqc_signature",
            rationale=(
                "ML-DSA is classified as a standardized post-quantum digital "
                "signature algorithm."
            ),
            source_ids=(SOURCE_FIPS_204,),
        )

    if _matches_slh_dsa(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="SLH-DSA",
            primitive="digital_signature",
            quantum_status="quantum_resistant",
            standard_status="standardized_pqc",
            recommended_action="acceptable_pqc_signature_with_operational_review",
            rationale=(
                "SLH-DSA is classified as a standardized stateless hash-based "
                "post-quantum digital signature algorithm. Later report layers "
                "should preserve operational caution for size and performance impact."
            ),
            source_ids=(SOURCE_FIPS_205,),
        )

    if _matches_rsa(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="RSA",
            primitive="public_key_encryption_or_signature",
            quantum_status="quantum_vulnerable",
            standard_status="classical_public_key",
            recommended_action="migrate_to_hybrid_or_pqc_path",
            rationale=(
                "RSA is classified as quantum-vulnerable public-key cryptography "
                "for PQC migration planning."
            ),
            source_ids=(SOURCE_NIST_IR_8547,),
        )

    if _matches_diffie_hellman(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="DH",
            primitive="key_establishment",
            quantum_status="quantum_vulnerable",
            standard_status="classical_public_key",
            recommended_action="migrate_to_hybrid_or_pqc_key_establishment",
            rationale=(
                "Finite-field Diffie-Hellman is classified as quantum-vulnerable "
                "key establishment for PQC migration planning."
            ),
            source_ids=(SOURCE_NIST_IR_8547,),
        )

    if _matches_ecc(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="ECC",
            primitive="key_establishment_or_signature",
            quantum_status="quantum_vulnerable",
            standard_status="classical_public_key",
            recommended_action="migrate_to_hybrid_or_pqc_path",
            rationale=(
                "Elliptic-curve public-key cryptography is classified as "
                "quantum-vulnerable for PQC migration planning."
            ),
            source_ids=(SOURCE_NIST_IR_8547,),
        )

    if _matches_aes(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="AES",
            primitive="symmetric_encryption",
            quantum_status="symmetric_grover_affected",
            standard_status="standardized_symmetric",
            recommended_action="review_key_strength_not_public_key_migration",
            rationale=(
                "AES is classified as symmetric encryption and is not treated as "
                "a Shor-broken public-key migration target."
            ),
            source_ids=(SOURCE_FIPS_197, SOURCE_SP_800_57),
        )

    if _matches_sha3(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="SHA-3",
            primitive="hash_or_xof",
            quantum_status="not_public_key",
            standard_status="standardized_hash",
            recommended_action="classify_separately_from_pqc_key_migration",
            rationale=(
                "SHA-3 and SHAKE are classified as hash/XOF algorithms rather "
                "than public-key establishment or signature algorithms."
            ),
            source_ids=(SOURCE_FIPS_202,),
        )

    if _matches_sha2_or_sha1(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="SHA-1/SHA-2",
            primitive="hash",
            quantum_status="not_public_key",
            standard_status="standardized_hash",
            recommended_action="classify_separately_from_pqc_key_migration",
            rationale=(
                "SHA-1 and SHA-2 family algorithms are classified as hash "
                "algorithms rather than public-key establishment or signature algorithms."
            ),
            source_ids=(SOURCE_FIPS_180_4,),
        )

    return _unknown_classification(original)


def _unknown_classification(original: str) -> AlgorithmClassification:
    return AlgorithmClassification(
        input_algorithm=original,
        algorithm_family="unknown",
        primitive="unknown",
        quantum_status="unknown",
        standard_status="unknown",
        recommended_action="manual_review_required",
        rationale=(
            "The algorithm string is not recognized by the current QSTriage "
            "standards registry. Conservative human review is required."
        ),
        source_ids=(SOURCE_QSTRIAGE_SAFETY_POLICY,),
    )


def _normalize_algorithm(algorithm: str) -> str:
    return (
        algorithm.strip()
        .upper()
        .replace("_", "-")
        .replace("/", "-")
        .replace(" ", "-")
    )


def _matches_ml_kem(normalized: str) -> bool:
    return normalized == "ML-KEM" or normalized.startswith("ML-KEM-")


def _matches_ml_dsa(normalized: str) -> bool:
    return normalized == "ML-DSA" or normalized.startswith("ML-DSA-")


def _matches_slh_dsa(normalized: str) -> bool:
    return normalized == "SLH-DSA" or normalized.startswith("SLH-DSA-")


def _matches_rsa(normalized: str) -> bool:
    return "RSA" in normalized


def _matches_diffie_hellman(normalized: str) -> bool:
    return (
        normalized == "DH"
        or "DIFFIE-HELLMAN" in normalized
        or normalized.startswith("FFDHE")
        or "FINITE-FIELD-DH" in normalized
    )


def _matches_ecc(normalized: str) -> bool:
    ecc_markers = (
        "ECC",
        "ECDH",
        "ECDHE",
        "ECDSA",
        "P-256",
        "P-384",
        "P-521",
        "CURVE25519",
        "X25519",
        "ED25519",
    )
    return any(marker in normalized for marker in ecc_markers)


def _matches_aes(normalized: str) -> bool:
    return normalized == "AES" or normalized.startswith("AES-")


def _matches_sha3(normalized: str) -> bool:
    return (
        normalized == "SHA-3"
        or normalized.startswith("SHA-3-")
        or normalized.startswith("SHA3-")
        or normalized.startswith("SHAKE")
    )


def _matches_sha2_or_sha1(normalized: str) -> bool:
    sha_markers = (
        "SHA-1",
        "SHA1",
        "SHA-2",
        "SHA2",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
    )
    return any(normalized == marker or normalized.startswith(f"{marker}-") for marker in sha_markers)
