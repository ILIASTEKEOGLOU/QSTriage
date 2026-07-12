# QSTriage Standards and Classification

QSTriage uses a small deterministic registry to classify algorithm identifiers before scoring, policy evaluation, reporting, and PDR generation.

This document describes the public classification contract implemented by `qstriage/standards.py` and the CBOM identifier normalization implemented by `qstriage/cbom.py`. Code and tests remain authoritative for executable behavior.

## Classification output

Each call produces an `AlgorithmClassification` with:

- the original input algorithm,
- algorithm family,
- primitive,
- quantum status,
- standards status,
- registry recommendation,
- rationale,
- source identifiers.

The registry recommendation is classification evidence. It is not the canonical execution decision. Canonical action, gating, verification, confidence, and human review are reconciled separately as described in [Decision Model](decision-model.md).

## Direct algorithm normalization

Before registry matching, QSTriage:

1. trims leading and trailing whitespace,
2. converts text to uppercase,
3. converts underscores, slashes, and spaces to hyphens.

Examples:

- `ml_kem 768` → `ML-KEM-768`
- `ECDHE_RSA` → `ECDHE-RSA`
- `finite-field DH` → `FINITE-FIELD-DH`

This boundary is deterministic and deliberately narrow. QSTriage does not use fuzzy matching, NLP, or approximate ontology expansion. An unrecognized identifier remains unknown.

## Current registry

| Match family | Family | Primitive | Quantum status | Standards status | Registry recommendation | Sources |
|---|---|---|---|---|---|---|
| ML-KEM | `ML-KEM` | `key_encapsulation` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_kem` | NIST FIPS 203 |
| ML-DSA | `ML-DSA` | `digital_signature` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_signature` | NIST FIPS 204 |
| SLH-DSA | `SLH-DSA` | `digital_signature` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_signature_with_operational_review` | NIST FIPS 205 |
| Classical key/signature composite | `classical_public_key_composite` | `key_establishment_and_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 IPD |
| RSA | `RSA` | `public_key_encryption_or_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 IPD |
| Finite-field Diffie-Hellman | `DH` | `key_establishment` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_key_establishment` | NIST IR 8547 IPD |
| ECC, ECDH/ECDHE, ECDSA, X25519, Ed25519 | `ECC` | `key_establishment_or_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 IPD |
| AES | `AES` | `symmetric_encryption` | `symmetric_grover_affected` | `standardized_symmetric` | `review_key_strength_not_public_key_migration` | NIST FIPS 197; NIST SP 800-57 Part 1 Rev. 5 |
| SHA-3 and SHAKE | `SHA-3` | `hash_or_xof` | `not_public_key` | `standardized_hash` | `classify_separately_from_pqc_key_migration` | NIST FIPS 202 |
| SHA-1 and SHA-2 identifiers | `SHA-1/SHA-2` | `hash` | `not_public_key` | `standardized_hash` | `classify_separately_from_pqc_key_migration` | NIST FIPS 180-4 |
| Anything else or blank input | `unknown` | `unknown` | `unknown` | `unknown` | `manual_review_required` | QSTriage safety policy |

The table describes registry taxonomy, not a blanket security approval. In particular, grouping SHA-1 and SHA-2 as hash primitives does not assert equivalent security strength or approve SHA-1 for a use case.

## Matching rules and precedence

Matching is deterministic and order-sensitive.

- ML-KEM, ML-DSA, and SLH-DSA accept the family identifier and identifiers beginning with the family plus a parameter suffix.
- Classical composite identifiers are detected before the individual RSA and ECC families. A value such as `ECDHE_RSA` is therefore classified as a combined key-establishment/signature identifier.
- RSA matching recognizes identifiers containing `RSA`.
- ECC matching recognizes explicit markers including `ECC`, `ECDH`, `ECDHE`, `ECDSA`, `P-256`, `P-384`, `P-521`, `CURVE25519`, `X25519`, and `ED25519`.
- AES matching recognizes `AES` and identifiers beginning with `AES-`.
- SHA matching recognizes the explicit SHA-1, SHA-2, SHA-3, and SHAKE forms implemented by the registry.

Because matching is bounded to these rules, similar-looking enterprise or vendor terms can remain unknown. Unknown input does not automatically mean high cryptographic risk, but it does mean the current evidence is insufficient to justify a known classification.

## CBOM identifier normalization

The CBOM importer derives an algorithm identifier using this order:

1. `parameterSetIdentifier`,
2. explicit `algorithm`,
3. `algorithmFamily`,
4. component name, except when the asset is explicitly a protocol.

It combines only supported structural signals. Current explicit transformations include:

| CBOM shape | Derived QSTriage identifier |
|---|---|
| `algorithmFamily=ML-KEM`, parameter `768` | `ML-KEM-768` |
| `algorithmFamily=ML-DSA`, parameter `65` | `ML-DSA-65` |
| `algorithmFamily=RSA`, key size `2048` | `RSA-2048` |
| `algorithmFamily=AES`, key size `256` | `AES-256` |
| cdxgen component name `aes256-CBC` | `AES-256-CBC` |
| cdxgen component name `aes256-GCM` | `AES-256-GCM` |

The cdxgen AES transformation is limited to AES-128, AES-192, or AES-256 with CBC or GCM. Other values pass through unchanged and are classified by the registry or routed to unknown/manual review.

## Source identifiers

The current registry emits these stable source IDs:

- `NIST-IR-8547-IPD`
- `NIST-FIPS-203`
- `NIST-FIPS-204`
- `NIST-FIPS-205`
- `NIST-SP-800-57-PART-1-REV-5`
- `NIST-FIPS-197`
- `NIST-FIPS-180-4`
- `NIST-FIPS-202`
- `QSTRIAGE-SAFETY-POLICY`

Source IDs establish classification provenance. They do not imply that the cited standards publish QSTriage scores, policy rules, or migration approvals.

## Bounded interpretation

A recognized classification means that the input matched a current deterministic registry rule. It does not establish:

- that the scanner discovered every cryptographic use,
- that the identifier describes the actual runtime primitive,
- that key material or parameters are valid,
- that the algorithm is approved for a particular policy or use case,
- that migration can proceed without evidence and operational review.

Unknown algorithms remain visible and are routed to verification-first handling. They are never silently treated as safe.
