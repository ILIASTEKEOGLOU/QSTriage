# QSTriage v0.3.0 Source Lock

## Purpose

This document locks the authoritative sources for QSTriage v0.3.0.

The v0.3.0 implementation theme is:

QSTriage v0.3.0 — Standards Mapping and Algorithm Classification Layer

The goal is to classify cryptographic algorithms and parameter sets using explicit source-backed rules before those classifications are connected to scoring and reports.

## Source policy

- Implementation authority must come from official standards, specifications, or primary project documentation.
- Private study material and books may be used for learning, but not as implementation authority.
- PDF copies of books or private research material must not be committed to the repository.
- Source-derived behavior must remain explainable in tests and reports.
- Unknown or unsupported algorithms must be classified conservatively rather than guessed as safe.

## Locked implementation sources

| Source | Authority role | QSTriage v0.3.0 use | URL |
|---|---|---|---|
| NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard | PQC KEM standard | Classify ML-KEM as standardized PQC KEM; recognize ML-KEM-512, ML-KEM-768, ML-KEM-1024 | https://csrc.nist.gov/pubs/fips/203/final |
| NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard | PQC signature standard | Classify ML-DSA as standardized PQC signature; recognize ML-DSA parameter sets | https://csrc.nist.gov/pubs/fips/204/final |
| NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard | PQC signature standard | Classify SLH-DSA as standardized hash-based PQC signature; preserve caution around operational size/performance impact in later reporting | https://csrc.nist.gov/pubs/fips/205/final |
| NIST IR 8547 IPD — Transition to Post-Quantum Cryptography Standards | PQC migration rationale | Identify quantum-vulnerable public-key algorithm families and source migration reasoning | https://csrc.nist.gov/pubs/ir/8547/ipd |
| OWASP CycloneDX Authoritative Guide to CBOM | CBOM model guide | Interpret CBOM cryptographic assets and dependencies; preserve distinction between CBOM dependency structure and QSTriage business/security blast-radius dependencies | https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf |
| CycloneDX CBOM capability documentation | CBOM model overview | Support CBOM crypto asset representation for algorithms, keys, certificates, protocols, and relationships | https://cyclonedx.org/capabilities/cbom/ |
| NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management | Classical security strength baseline | Use security-strength concepts for classical key sizes and conservative classification metadata | https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final |
| NIST FIPS 197 — Advanced Encryption Standard | Symmetric encryption baseline | Classify AES as symmetric encryption; distinguish symmetric algorithms from quantum-vulnerable public-key algorithms | https://csrc.nist.gov/pubs/fips/197/final |
| NIST FIPS 180-4 — Secure Hash Standard | Hash baseline | Classify SHA-1 and SHA-2 family hash algorithms; preserve later deprecation handling for SHA-1 | https://csrc.nist.gov/pubs/fips/180-4/upd1/final |
| NIST FIPS 202 — SHA-3 Standard | Hash baseline | Classify SHA-3 and SHAKE family hash/XOF algorithms | https://csrc.nist.gov/pubs/fips/202/final |

## v0.3.0-A implementation scope

The first implementation track should be small and test-first:

Track v0.3.0-A — Algorithm Registry Contract and Tests

Initial module candidate:

- qstriage/standards.py

Initial test candidate:

- tests/test_standards.py

The registry should accept common algorithm strings from hand-written YAML and CBOM imports, then return an explainable classification object.

Candidate output fields:

- algorithm_family
- primitive
- quantum_status
- standard_status
- recommended_action
- rationale
- source_ids

## Initial classification contract

| Input family or pattern | Expected classification direction | Source basis |
|---|---|---|
| RSA, RSA-2048, RSA-3072, RSA-4096 | Quantum-vulnerable public-key cryptography; migration required for confidentiality/signature use | NIST IR 8547 IPD |
| DH, Diffie-Hellman, finite-field DH | Quantum-vulnerable key establishment; migration required | NIST IR 8547 IPD |
| ECDH, ECDSA, ECC, P-256, P-384, P-521, Curve25519, Ed25519 | Quantum-vulnerable elliptic-curve public-key cryptography; migration required for key establishment/signatures | NIST IR 8547 IPD |
| ML-KEM-512, ML-KEM-768, ML-KEM-1024 | Standardized PQC KEM | NIST FIPS 203 |
| ML-DSA | Standardized PQC digital signature | NIST FIPS 204 |
| SLH-DSA | Standardized stateless hash-based PQC digital signature; later reports should preserve operational caution | NIST FIPS 205 |
| AES-128, AES-192, AES-256 | Symmetric encryption; not Shor-broken like RSA/ECC; classify separately from public-key migration targets | NIST FIPS 197 and NIST SP 800-57 Part 1 Rev. 5 |
| SHA-1, SHA-2, SHA-256, SHA-384, SHA-512 | Hash function family; classify separately from key establishment/signature algorithms | NIST FIPS 180-4 |
| SHA-3, SHA3-256, SHA3-512, SHAKE128, SHAKE256 | SHA-3/XOF family; classify separately from key establishment/signature algorithms | NIST FIPS 202 |
| Unknown algorithm string | Unknown; conservative review required | QSTriage safety policy |

## Non-goals for v0.3.0-A

- No scoring refactor yet.
- No regulatory preset implementation yet.
- No automatic migration plan generation yet.
- No production execution, rollout, certificate rotation, or rollback.
- No claim that CBOM dependency relationships equal QSTriage blast-radius dependencies.

## Notes for later tracks

After the registry contract is tested, later tracks can connect it to:

- scoring explanations
- report evidence sections
- CBOM import metadata normalization
- standards-backed recommended actions
- unknown-algorithm warnings
