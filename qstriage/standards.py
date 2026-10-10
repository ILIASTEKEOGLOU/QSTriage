from __future__ import annotations

import re
from dataclasses import dataclass

from qstriage.algorithm_registry import load_registry


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

# Exact standardized PQC identifiers come from the bundled algorithm registry.
_ML_KEM_IDENTIFIERS = frozenset(load_registry().entry("ml-kem").identifiers)
_ML_DSA_IDENTIFIERS = frozenset(load_registry().entry("ml-dsa").identifiers)
_SLH_DSA_IDENTIFIERS = frozenset(load_registry().entry("slh-dsa").identifiers)

_CLASSICAL_KEY_ESTABLISHMENT_TOKENS = frozenset(
    {"DH", "DHE", "EDH", "ECDH", "ECDHE", "X25519", "CURVE25519"}
)
_CLASSICAL_AUTHENTICATION_TOKENS = frozenset({"RSA", "ECDSA", "ED25519"})

# Fail-closed guard markers. Matched against the separator-free identifier.
# Substring matching is acceptable here only because a match can never grant a
# classification: it can only withhold one (result is always unknown).
_PQC_COMPONENT_MARKERS = (
    "MLKEM",
    "MLDSA",
    "SLHDSA",
    "FNDSA",
    "KYBER",
    "DILITHIUM",
    "SPHINCS",
    "FALCON",
)

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
        return _classification_from_entry("ml-kem", original)

    if normalized in _ML_DSA_IDENTIFIERS:
        return _classification_from_entry("ml-dsa", original)

    if normalized in _SLH_DSA_IDENTIFIERS:
        return _classification_from_entry("slh-dsa", original)

    pqc_family_entry = _recognized_pqc_family_entry(normalized)
    if pqc_family_entry is not None:
        return _classification_from_entry(pqc_family_entry, original)

    if _contains_pqc_component(normalized):
        # Classical/PQC hybrids have no result in the current data model.
        # Never let a classical marker classify an identifier that also
        # carries a PQC component (e.g. X25519-ML-KEM-768).
        return _unknown_classification(original)

    if _matches_classical_public_key_combo(normalized):
        return _classification_from_entry("classical-public-key-composite", original)

    if _matches_rsa(normalized):
        return _classification_from_entry("rsa", original)

    if _matches_diffie_hellman(normalized):
        return _classification_from_entry("dh", original)

    if _matches_ecc(normalized):
        return _classification_from_entry("ecc", original)

    if _matches_aes(normalized):
        return _classification_from_entry("aes", original)

    if _matches_sha3(normalized):
        return _classification_from_entry("sha3", original)

    if _matches_sha2_or_sha1(normalized):
        return _classification_from_entry("sha1-sha2", original)

    return _unknown_classification(original)


def _classification_from_entry(entry_id: str, original: str) -> AlgorithmClassification:
    entry = load_registry().entry(entry_id)
    return AlgorithmClassification(
        input_algorithm=original,
        algorithm_family=entry.algorithm_family,
        primitive=entry.primitive,
        quantum_status=entry.quantum_status,
        standard_status=entry.standard_status,
        recommended_action=entry.recommended_action,
        rationale=entry.rationale,
        source_ids=entry.source_ids,
        identifier_resolution=entry.identifier_resolution,
    )


def _unknown_classification(original: str) -> AlgorithmClassification:
    return _classification_from_entry("unknown", original)


def _normalize_algorithm(algorithm: str) -> str:
    return re.sub(
        r"[-_/\s]+",
        "-",
        algorithm.strip().upper(),
    )


def requires_parameter_verification(classification: AlgorithmClassification) -> bool:
    return classification.identifier_resolution == IDENTIFIER_FAMILY_UNVERIFIED


def _recognized_pqc_family_entry(normalized: str) -> str | None:
    families = (
        ("ML-KEM", "ml-kem-family-unverified"),
        ("ML-DSA", "ml-dsa-family-unverified"),
        ("SLH-DSA", "slh-dsa-family-unverified"),
    )
    for family, entry_id in families:
        if normalized == family or normalized.startswith(f"{family}-"):
            return entry_id
    return None


def _contains_pqc_component(normalized: str) -> bool:
    compact = re.sub(r"[^A-Z0-9]", "", normalized)
    return any(marker in compact for marker in _PQC_COMPONENT_MARKERS)


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
