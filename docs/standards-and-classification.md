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
- source identifiers,
- identifier resolution,
- scheme type (`single`, `pq_t_hybrid`, or `pq_pq_hybrid`),
- for hybrids, the components in source order and the
  `certification_component`,
- the registry entry ID.

Identifier resolution separates an exact supported form from a recognized PQC
family whose parameter set is missing or unsupported, and from a wholly
unrecognized identifier. The complete bounded grammar is documented in
[Algorithm Identifier Grammar](algorithm-identifier-grammar.md).

The registry recommendation is classification evidence. It is not the canonical execution decision. Canonical action, gating, verification, confidence, and human review are reconciled separately as described in [Decision Model](decision-model.md).

## Direct algorithm normalization

Before registry matching, QSTriage:

1. trims leading and trailing whitespace,
2. converts text to uppercase,
3. treats underscores, slashes, whitespace, and hyphens as separators,
4. collapses each internal separator run to one hyphen without extracting a
   known marker from an arbitrary alphabetic token.

Examples:

- `ml_kem 768` -> `ML-KEM-768`
- `ECDHE_RSA` -> `ECDHE-RSA`
- `finite-field DH` -> `FINITE-FIELD-DH`

This boundary is deterministic and deliberately narrow. QSTriage does not use fuzzy matching, NLP, or approximate ontology expansion. An unrecognized identifier remains unknown.

## Current registry

| Match family | Family | Primitive | Quantum status | Standards status | Registry recommendation | Sources |
|---|---|---|---|---|---|---|
| ML-KEM | `ML-KEM` | `key_encapsulation` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_kem` | NIST FIPS 203 |
| ML-DSA | `ML-DSA` | `digital_signature` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_signature` | NIST FIPS 204 |
| SLH-DSA | `SLH-DSA` | `digital_signature` | `quantum_resistant` | `standardized_pqc` | `acceptable_pqc_signature_with_operational_review` | NIST FIPS 205 |
| RFC 10024 PQ/T hybrid groups (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) | `pq_t_hybrid_kem` | `key_establishment` | `quantum_resistant` | `standardized_pq_t_hybrid` | `retain_with_certification_review` | RFC 10024; NIST SP 800-227; NIST FIPS 203 |
| Classical key/signature composite | `classical_public_key_composite` | `key_establishment_and_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 |
| RSA | `RSA` | `public_key_encryption_or_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 |
| Finite-field Diffie-Hellman | `DH` | `key_establishment` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_key_establishment` | NIST IR 8547 |
| ECC, ECDH/ECDHE, ECDSA, X25519, Ed25519 | `ECC` | `key_establishment_or_signature` | `quantum_vulnerable` | `classical_public_key` | `migrate_to_hybrid_or_pqc_path` | NIST IR 8547 |
| AES | `AES` | `symmetric_encryption` | `symmetric_grover_affected` | `standardized_symmetric` | `review_key_strength_not_public_key_migration` | NIST FIPS 197; NIST SP 800-57 Part 1 Rev. 5 |
| SHA-3 and SHAKE | `SHA-3` | `hash_or_xof` | `not_public_key` | `standardized_hash` | `classify_separately_from_pqc_key_migration` | NIST FIPS 202 |
| SHA-1 and SHA-2 identifiers | `SHA-1/SHA-2` | `hash` | `not_public_key` | `standardized_hash` | `classify_separately_from_pqc_key_migration` | NIST FIPS 180-4 |
| Anything else or blank input | `unknown` | `unknown` | `unknown` | `unknown` | `manual_review_required` | QSTriage safety policy |

The table describes registry taxonomy, not a blanket security approval. In particular, grouping SHA-1 and SHA-2 as hash primitives does not assert equivalent security strength or approve SHA-1 for a use case.

## Matching rules and precedence

Matching is deterministic and order-sensitive.

- ML-KEM, ML-DSA, and SLH-DSA receive standardized-PQC status only for exact
  parameter sets in the bundled allowlists. A bare family or unsupported
  parameter set preserves the family but requires parameter verification.
- The three RFC 10024 group names are matched exactly, after normalization,
  before the PQC component guard. Any other identifier that carries a PQC
  component marker receives no positive classification.
- Classical composites are detected before leaf families. Composite means an
  exact key-establishment role token such as `DH`, `DHE`, `EDH`, `ECDH`, or
  `ECDHE` plus a separate exact authentication/signature token such as `RSA`.
- A TLS RSA key-transport suite such as `TLS_RSA_WITH_AES_128_GCM_SHA256` has
  only one public-key primitive and is classified as the RSA leaf, not as a
  composite.
- RSA matching uses exact or anchored forms for bounded RSA, OAEP/PSS,
  standards-defined textual OID names, bounded MD2/MD5/SHA-with-RSA signature
  names, and the explicit TLS RSA/AES-GCM compatibility forms. It never
  searches for `RSA` inside an arbitrary alphabetic run.
- Finite-field DH matching recognizes exact `DH`, the new bounded `DHE` and
  legacy OpenSSL `EDH` aliases, exact Diffie-Hellman phrases, and numeric FFDHE
  group syntax.
- ECC matching recognizes exact markers including `ECC`, `ECDH`, `ECDHE`,
  `ECDSA`, `P-256`, `P-384`, `P-521`, `CURVE25519`, `X25519`, and `ED25519`,
  plus bounded SHA-1/SHA-2 JCA `withECDSA` signature names.
- AES and SHA matching is confined to the structured forms listed in the
  algorithm-identifier grammar; a familiar prefix is not a wildcard.

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
| `algorithmFamily=AES`, parameter `256` | `AES-256` |
| `algorithmFamily=RSA`, key size `2048` | `RSA` (key size kept in `key_size_bits`) |
| `algorithmFamily=RSA`, parameter `512` | `RSA` (bare number not mapped) |
| cdxgen component name `aes256-CBC` | `AES-256-CBC` |
| cdxgen component name `aes256-GCM` | `AES-256-GCM` |

The cdxgen AES transformation is limited to AES-128, AES-192, or AES-256 with CBC or GCM. Other values pass through unchanged and are classified by the registry or routed to unknown/manual review.

## Source identifiers

The current registry emits these stable source IDs:

- `NIST-IR-8547`
- `NIST-FIPS-203`
- `NIST-FIPS-204`
- `NIST-FIPS-205`
- `NIST-SP-800-57-PART-1-REV-5`
- `NIST-FIPS-197`
- `NIST-FIPS-180-4`
- `NIST-FIPS-202`
- `RFC-10024`
- `NIST-SP-800-227`
- `QSTRIAGE-SAFETY-POLICY`

Source IDs establish classification provenance. They do not imply that the cited standards publish QSTriage scores, policy rules, or migration approvals.

## NIST IR 8547 source update

Registry version 3 and built-in policy pack 0.5 cite the final NIST IR 8547
instead of its initial public draft. This section records what changed in the
source, what QSTriage changed, and what it deliberately did not change.

### Sources

| | Initial public draft | Final |
|---|---|---|
| Title | Transition to Post-Quantum Cryptography Standards | Transition to Post-Quantum Cryptography Standards |
| Date | November 2024 | October 2026 (published 2026-10-27) |
| Page | https://csrc.nist.gov/pubs/ir/8547/ipd | https://csrc.nist.gov/pubs/ir/8547/final |
| PDF | https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf |
| DOI | - | https://doi.org/10.6028/NIST.IR.8547 |
| QSTriage source ID | `NIST-IR-8547-IPD` | `NIST-IR-8547` |

The final PDF read for this change has SHA-256
`3049cdfdd7c20417cf588a3d55ace6e8813982d1499502b7ef69e9593b2dc280`. The draft
PDF now served by NIST starts with a withdrawal cover sheet (withdrawal date
October 27, 2026), so its bytes differ from the 2024 file; compare passages by
section and printed page number, not by PDF page index.

### Registry entries

Only the IR 8547 source of these four entries changed. Each now has
`status: final`, `date: 2026-10`, the section below, and no excerpt.

| Entry | Section of the final report | What the section says |
|---|---|---|
| `classical-public-key-composite` | Sections 2.1.1 and 2.1.2 | Both component kinds, signatures and key establishment, are quantum-vulnerable |
| `rsa` | Sections 2.1.1 and 2.1.2 | RSA signatures (FIPS 186, 2.1.1) and RSA key establishment (SP 800-56B, 2.1.2) are vulnerable to Shor's algorithm |
| `dh` | Section 2.1.2 | Finite-field Diffie-Hellman and MQV (SP 800-56A) are vulnerable to Shor's algorithm |
| `ecc` | Sections 2.1.1 and 2.1.2 | ECDSA and EdDSA (2.1.1) and elliptic-curve Diffie-Hellman and MQV (2.1.2) are vulnerable to Shor's algorithm |

Section 2.1.1 is on printed page 3 and section 2.1.2 on printed page 4. The
composite entry is a QSTriage classification of names that combine such
components; the report does not list composite names.

Identifiers, rationale, lifecycle, classification fields, recommendations,
components, and the empty `deadlines` arrays are unchanged. The publication
status of a source is separate from an entry's lifecycle.

### What changed between the draft and the final report

- Section 2.1.2 of the final report names the key-establishment schemes of
  SP 800-56A and SP 800-56B and states that they are vulnerable to Shor's
  algorithm. The draft section 2.1.2 described the same schemes without that
  sentence; its section 2.1.1 already named the ECC-based key-establishment
  schemes of SP 800-56A in the paragraph that states the vulnerability.
- Tables 2 and 4 (final, printed pages 15 and 16 to 17; draft, pages 13 and
  14). The draft marked 112-bit security strength "Deprecated after 2030" and
  "Disallowed after 2035", and 128 bits or more "Disallowed after 2035" only.
  The final tables give one row per family, for 112 bits of classical security
  strength or more (128 or more for EdDSA), marked "Deprecated after 2030" and
  "Disallowed after 2035".
- Section 4 (final, printed page 13): "NIST will deprecate quantum-vulnerable
  public-key cryptography after 2030 and disallow its use under NIST standards
  and guidelines after 2035." The same section says that this window does not
  alter earlier deadlines for prioritized U.S. Federal systems under EO 14412
  and OMB M-26-15.

The quotations above use the report's words; the tables write "112 bits or
more" with a greater-than-or-equal sign.

### Implementation boundary

This change updates provenance only. It does not:

- encode the 2030 and 2035 dates, federal applicability, or the new table
  thresholds. Every registry `deadlines` array stays empty;
- change `deadline_pressure`, which is a QSTriage scoring heuristic based on
  retention, risk, and exposure, not an implementation of the NIST calendar;
- add algorithms (HQC, FALCON, LMS, XMSS) or change the PQ/T hybrid entries,
  unknown-algorithm handling, or certification review;
- change classification, scores, evidence findings, policy rules, or
  decisions.

### Identities

| | Before | After |
|---|---|---|
| Registry `qstriage-algorithms` | version `2`, `sha256:8ceb8492571aab632b89d5d203e98a15bdf8b4f99f2b0aead8674cff4696b84c` | version `3`, `sha256:67a0e6d13363ca78ad69ec5c23d8cfcd68ca0b8be0363dfd2502ac94458db0d3` |
| Policy pack `nist-pqc-basic` | version `0.4`, `sha256:c39286db56036c5d82118c6e135bc63477d508d0607952ad5077450e4708a639` | version `0.5`, `sha256:488598e4c831135d815d7a3ec5f46a66785edfaaba1950c10d19410c1e348fc0` |

In policy pack 0.5 the reference `NIST-IR-8547` has the title
"NIST IR 8547 - Transition to Post-Quantum Cryptography Standards" and version
`final`; the three rules that cited the draft cite it instead. The project
policy reference `QSTRIAGE-SAFETY-POLICY` carries the pack version and
therefore changes from `0.4` to `0.5`. Rule IDs, conditions, effects,
severities, thresholds, and order are unchanged.

A new PDR from the same input keeps its input snapshot, record IDs, lineage
IDs, and every decision field. Its registry and policy identities, the
`standards_applied` lists that name the source, its `run_id`, and its hashes
change; this applies to every new PDR, including one for an inventory without
any classical public-key asset. PDRs issued earlier are not rewritten and still
verify. Score exports are unchanged; reports change only in the registry
sources line.

The fallback target `manual_pqc_target_selection` also cites `NIST-IR-8547`.
No registry entry reaches it today, because every quantum-vulnerable entry has
a primitive that contains "key"; it is tested directly.

## PQ/T hybrid classification and source text

`quantum_resistant` for an RFC 10024 group rests on the RFC 10024 definition
of a hybrid key exchange. `standardized_pq_t_hybrid` states that the group is
defined in RFC 10024. Neither value states that the group, or a deployment of
it, is approved or FIPS-approved. NIST SP 800-227 Section 4.6.2 approves key
combiners, not hybrid schemes as such.

RFC 10024 Section 5 states which component implementation must be certified.
That section describes itself as informal notes on NIST guidance. An
identifier cannot show whether an implementation is certified, so every
hybrid record requires human review, and policy pack `nist-pqc-basic` (since
0.3) has the rule
`standardized_pq_t_hybrid_requires_certification_evidence_review`. For the
same reason, since policy pack 0.4 every standardized ML-KEM, ML-DSA, and
SLH-DSA record also requires human review
(`standardized_pqc_can_be_retained_with_operational_review`,
`ml_kem_usage_requires_key_establishment_context`).

### Verbatim source text

Each registry source may carry an `excerpt`: text copied verbatim from the
`section` it cites. Excerpts are never paraphrased; QSTriage's own wording is
kept in `rationale` and in generated target-state text, which quotes the
excerpt in double quotation marks. One notation change applies: a subscript
that the source typesets below the line is written with an underscore
(`S_j`). Tests pin every excerpt, so a change to source text in the registry
fails the suite and must be reviewed.

The RFC 10024 entries cite Sections 3, 4.3, 5 (introduction and
FIPS-compliance), and 7, NIST SP 800-227 Section 4.6.2, and NIST FIPS 203.

## Registry maintenance boundary

The algorithm registry is bundled with each QSTriage release. It is not
downloaded or refreshed from the network during analysis. Classification
changes are reviewed source changes and must use official standards,
specifications, or primary project documentation as implementation authority.

A registry change must:

- update direct identifier matching and CBOM normalization together when their
  contracts overlap,
- add tests for accepted identifiers, aliases, parameter forms, and inputs that
  must remain unknown,
- preserve conservative manual review outside the supported match boundary,
- update source IDs and this document when public behavior or provenance
  changes,
- increase `registry_version` in `qstriage/algorithm_registry.json` when entry
  content changes.

The registry has its own identity. Each PDR 0.3 records `registry_id`,
`registry_version`, and `registry_hash`, the RFC 8785 SHA-256 hash of the
parsed registry file, in its `registry_context`. A change to any entry changes
`registry_hash` and therefore the PDR `run_id`. See
[PDR Contract](pdr-contract.md).

## Bounded interpretation

A recognized classification means that the input matched a current deterministic registry rule. It does not establish:

- that the scanner discovered every cryptographic use,
- that the identifier describes the actual runtime primitive,
- that key material or parameters are valid,
- that the algorithm is approved for a particular policy or use case,
- that migration can proceed without evidence and operational review.

Unknown algorithms remain visible and are routed to verification-first handling. They are never silently treated as safe.
