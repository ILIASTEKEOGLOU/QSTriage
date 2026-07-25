from __future__ import annotations

import re
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

IDENTIFIER_EXACT = "exact_identifier"
IDENTIFIER_FAMILY_UNVERIFIED = "recognized_family_unverified_parameters"
IDENTIFIER_UNRECOGNIZED = "unrecognized_identifier"

ML_KEM_PARAMETER_SETS = frozenset({"512", "768", "1024"})
ML_DSA_PARAMETER_SETS = frozenset({"44", "65", "87"})
SLH_DSA_PARAMETER_SETS = frozenset(
    f"{hash_family}-{security_level}{variant}"
    for hash_family in ("SHA2", "SHAKE")
    for security_level in ("128", "192", "256")
    for variant in ("S", "F")
)

_ML_KEM_IDENTIFIERS = frozenset(
    f"ML-KEM-{parameter_set}" for parameter_set in ML_KEM_PARAMETER_SETS
)
_ML_DSA_IDENTIFIERS = frozenset(
    f"ML-DSA-{parameter_set}" for parameter_set in ML_DSA_PARAMETER_SETS
)
_SLH_DSA_IDENTIFIERS = frozenset(
    f"SLH-DSA-{parameter_set}" for parameter_set in SLH_DSA_PARAMETER_SETS
)

_CLASSICAL_KEY_ESTABLISHMENT_TOKENS = frozenset(
    {"DH", "DHE", "EDH", "ECDH", "ECDHE", "X25519", "CURVE25519"}
)
_CLASSICAL_AUTHENTICATION_TOKENS = frozenset({"RSA", "ECDSA", "ED25519"})

_RSA_EXACT_IDENTIFIERS = frozenset(
    {
        "RSA",
        "RSA-OAEP",
        "RSA-PSS",
        "RSAENCRYPTION",
        "RSASSA-PSS",
        "ID-RSASSA-PSS",
        "RSAES-OAEP",
        "ID-RSAES-OAEP",
    }
)
_TLS_RSA_KEY_TRANSPORT_IDENTIFIERS = frozenset(
    {
        "TLS-RSA-WITH-AES-128-GCM-SHA256",
        "TLS-RSA-WITH-AES-256-GCM-SHA384",
    }
)


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
    identifier_resolution: str = IDENTIFIER_UNRECOGNIZED


def classify_algorithm(algorithm: str | None) -> AlgorithmClassification:
    original = (algorithm or "").strip()
    normalized = _normalize_algorithm(original)

    if not normalized:
        return _unknown_classification(original)

    if normalized in _ML_KEM_IDENTIFIERS:
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
            identifier_resolution=IDENTIFIER_EXACT,
        )

    if normalized in _ML_DSA_IDENTIFIERS:
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
            identifier_resolution=IDENTIFIER_EXACT,
        )

    if normalized in _SLH_DSA_IDENTIFIERS:
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
            identifier_resolution=IDENTIFIER_EXACT,
        )

    pqc_family = _recognized_pqc_family(normalized)
    if pqc_family is not None:
        family, primitive, source_id = pqc_family
        return _family_unverified_classification(
            original,
            family=family,
            primitive=primitive,
            source_id=source_id,
        )

    if _matches_classical_public_key_combo(normalized):
        return AlgorithmClassification(
            input_algorithm=original,
            algorithm_family="classical_public_key_composite",
            primitive="key_establishment_and_signature",
            quantum_status="quantum_vulnerable",
            standard_status="classical_public_key",
            recommended_action="migrate_to_hybrid_or_pqc_path",
            rationale=(
                "The algorithm string combines classical public-key key establishment "
                "and/or signature components and is classified as quantum-vulnerable "
                "for PQC migration planning."
            ),
            source_ids=(SOURCE_NIST_IR_8547,),
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
            identifier_resolution=IDENTIFIER_EXACT,
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
        identifier_resolution=IDENTIFIER_UNRECOGNIZED,
    )


def _normalize_algorithm(algorithm: str) -> str:
    return re.sub(
        r"[-_/\s]+",
        "-",
        algorithm.strip().upper(),
    )


def requires_parameter_verification(classification: AlgorithmClassification) -> bool:
    return classification.identifier_resolution == IDENTIFIER_FAMILY_UNVERIFIED


def _recognized_pqc_family(
    normalized: str,
) -> tuple[str, str, str] | None:
    families = (
        ("ML-KEM", "key_encapsulation", SOURCE_FIPS_203),
        ("ML-DSA", "digital_signature", SOURCE_FIPS_204),
        ("SLH-DSA", "digital_signature", SOURCE_FIPS_205),
    )
    for family, primitive, source_id in families:
        if normalized == family or normalized.startswith(f"{family}-"):
            return family, primitive, source_id
    return None


def _family_unverified_classification(
    original: str,
    *,
    family: str,
    primitive: str,
    source_id: str,
) -> AlgorithmClassification:
    return AlgorithmClassification(
        input_algorithm=original,
        algorithm_family=family,
        primitive=primitive,
        quantum_status="unknown",
        standard_status="unknown",
        recommended_action="verify_exact_parameter_set_before_classification",
        rationale=(
            f"The identifier matches the {family} family boundary, but its exact "
            "parameter set is missing or is not supported by the current QSTriage "
            "standards registry. Exact parameter verification is required before "
            "a quantum or standards classification can be assigned."
        ),
        source_ids=(source_id, SOURCE_QSTRIAGE_SAFETY_POLICY),
        identifier_resolution=IDENTIFIER_FAMILY_UNVERIFIED,
    )


def _matches_classical_public_key_combo(normalized: str) -> bool:
    tokens = set(normalized.split("-"))
    return bool(tokens & _CLASSICAL_KEY_ESTABLISHMENT_TOKENS) and bool(
        tokens & _CLASSICAL_AUTHENTICATION_TOKENS
    )


def _matches_rsa(normalized: str) -> bool:
    return bool(
        normalized in _RSA_EXACT_IDENTIFIERS
        or normalized in _TLS_RSA_KEY_TRANSPORT_IDENTIFIERS
        or re.fullmatch(r"RSA-?\d+", normalized)
        or re.fullmatch(
            r"(?:MD(?:2|5)|SHA(?:1|224|256|384|512))"
            r"WITHRSA(?:ENCRYPTION)?",
            normalized,
        )
    )


def _matches_diffie_hellman(normalized: str) -> bool:
    return (
        normalized in {
            "DH",
            "DHE",
            "EDH",
            "DIFFIE-HELLMAN",
            "FINITE-FIELD-DH",
        }
        or re.fullmatch(r"FFDHE-?\d+", normalized) is not None
    )


def _matches_ecc(normalized: str) -> bool:
    ecc_markers = {
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
    }
    tokens = set(normalized.split("-"))
    return bool(
        normalized in ecc_markers
        or tokens & ecc_markers
        or re.fullmatch(r"SHA(?:1|224|256|384|512)WITHECDSA", normalized)
    )


def _matches_aes(normalized: str) -> bool:
    return normalized == "AES" or bool(
        re.fullmatch(r"AES-?(?:128|192|256)(?:-[A-Z0-9]+)*", normalized)
    )


def _matches_sha3(normalized: str) -> bool:
    return bool(
        re.fullmatch(r"SHA-?3-(?:224|256|384|512)", normalized)
        or re.fullmatch(r"SHAKE-?(?:128|256)", normalized)
    )


def _matches_sha2_or_sha1(normalized: str) -> bool:
    return normalized in {
        "SHA-1",
        "SHA1",
        "SHA-2",
        "SHA2",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
    }
