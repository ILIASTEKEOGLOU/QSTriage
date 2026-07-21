# Algorithm Identifier Grammar

This document defines the bounded algorithm-identifier grammar targeted by
QSTriage v1.2.1. It is a deterministic classification contract, not a general
parser, fuzzy matcher, vendor ontology, or proof of the runtime cryptographic
implementation.

The central invariant is:

> Recognizing a family name is not approval of an algorithm or parameter set.

An identifier receives a positive quantum or standards classification only
when the complete normalized identifier matches an explicitly supported form.

## Resolution, quantum, and standards are separate axes

`AlgorithmClassification` exposes three independent questions:

| Field | Question | Values relevant to this grammar |
|---|---|---|
| `identifier_resolution` | How precisely was the supplied identifier resolved? | `exact_identifier`, `recognized_family_unverified_parameters`, `unrecognized_identifier` |
| `quantum_status` | What quantum posture is justified by the resolved identifier? | `quantum_vulnerable`, `quantum_resistant`, `not_public_key`, `unknown` |
| `standard_status` | What standards lifecycle claim is justified? | `standardized_pqc`, `classical_public_key`, `standardized_hash`, `unknown` |

The resolution states have the following fail-closed contract:

| Resolution | Family | Quantum and standards status | Action |
|---|---|---|---|
| `exact_identifier` | Exact supported family | Derived from the exact registry entry | Derived from the exact registry entry |
| `recognized_family_unverified_parameters` | Preserved | `unknown` / `unknown` | `verify_exact_parameter_set_before_classification` |
| `unrecognized_identifier` | `unknown` | `unknown` / `unknown` | `manual_review_required` |

`recognized_family_unverified_parameters` is limited to a supported family
boundary with missing or unsupported parameters. It must not receive
`quantum_resistant` or `standardized_pqc` merely because the string begins with
`ML-KEM`, `ML-DSA`, or `SLH-DSA`.

## Normalization

Matching operates on a normalized copy while preserving the original input in
the classification result.

1. Trim leading and trailing whitespace.
2. Convert letters to uppercase without locale-sensitive matching.
3. Treat underscores, slashes, whitespace, and hyphens as separators.
4. Collapse each internal separator run to one hyphen.
5. Preserve alphanumeric runs. Do not split a known marker out of an arbitrary
   alphabetic token.
6. Preserve a leading or trailing hyphen produced by the input. It is not
   silently removed to make a malformed value match an allowlist.

For example, `ml__kem / 768` normalizes to `ML-KEM-768`. By contrast,
`MARSALA` is one alphabetic run; the `RSA` letters inside it are not a token.

A letter-to-digit boundary is recognized only by an anchored grammar for a
known family, such as `RSA2048`. It is not a general tokenizer.

## Matching precedence

The first matching rule wins:

1. blank or structurally empty input,
2. exact standardized PQC allowlists,
3. recognized PQC family with missing or unsupported parameters,
4. explicit classical public-key composites,
5. exact or anchored classical families,
6. exact structured AES and SHA forms,
7. unrecognized fallback.

Composite matching precedes leaf-family matching so that
`ECDHE-RSA-AES128-GCM-SHA256` is not reduced to RSA or ECC alone.

## Exact standardized PQC allowlists

Only the following complete normalized identifiers receive
`quantum_resistant` and `standardized_pqc` in v1.2.1.

### ML-KEM

- `ML-KEM-512`
- `ML-KEM-768`
- `ML-KEM-1024`

### ML-DSA

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`

### SLH-DSA

For each of `SHA2` and `SHAKE`, the allowed parameter suffixes are:

- `128S`
- `128F`
- `192S`
- `192F`
- `256S`
- `256F`

Consequently, `SLH_DSA_SHA2_128S` normalizes to the exact FIPS 205 identifier
`SLH-DSA-SHA2-128S`. Bare family names and values such as `ML-KEM-9999`,
`ML-DSA-17`, and `SLH-DSA-BANANA` preserve the recognized family but require
parameter verification.

This allowlist does not include limited-signature SLH-DSA parameter sets from
later draft publications. A future registry may represent them with distinct
provenance and lifecycle status; v1.2.1 must not label them as FIPS 205
standardized identifiers.

## Classical public-key grammar

| Family | Accepted forms | Boundary rule |
|---|---|---|
| RSA | `RSA`, `RSA-<digits>`, `RSA<digits>`, `RSA-OAEP`, anchored `RSASSA-PSS`, anchored `SHA<digest>WITHRSA` | Never search for `RSA` inside an arbitrary alphabetic run |
| Finite-field DH | `DH`, `DIFFIE-HELLMAN`, `FINITE-FIELD-DH`, and `FFDHE` followed only by a numeric group | `FFDHELIUM` and longer lookalike words do not match |
| ECC | Exact `ECC`, `ECDH`, `ECDHE`, `ECDSA`, `P-256`, `P-384`, `P-521`, `CURVE25519`, `X25519`, and `ED25519` tokens | A marker must be the whole identifier or an exact separator-delimited token or sequence |
| Classical composite | Two or more exact separator-delimited public-key role tokens in one supported composite | Composite recognition runs before leaf families |

The compatibility corpus includes `RSA-OAEP`, `RSASSA-PSS`,
`SHA256withRSA`, `RSA2048`, `ECDHE_RSA`,
`ECDHE-RSA-AES128-GCM-SHA256`, `finite-field DH`, `ECDSA P-256`,
`X25519`, and `Ed25519`.

## Symmetric and hash grammar

- AES matches the exact family or a structured AES identifier rooted in an
  approved AES key-size form. A family prefix is not a wildcard.
- SHA-3 matches `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512` and their
  `SHA-3-...` spellings.
- SHAKE matches only the structured `SHAKE128` and `SHAKE256` XOF forms.
- SHA-1 and SHA-2 matching remains confined to their explicit structured
  forms.

`SHAKEWEIGHT` is therefore unrecognized. A familiar prefix inside a longer
alphabetic run cannot create a standards-backed hash classification.

## Adversarial boundary corpus

The following values must resolve as `unrecognized_identifier` with unknown
family, quantum status, and standards status:

- `universal-cipher`
- `MARSALA`
- `TORSA-HASH`
- `APP-256`
- `ECCENTRIC-V2`
- `NOT-DIFFIE-HELLMANISH`
- `FFDHELIUM`
- `SHAKEWEIGHT`

This is a regression corpus, not an exhaustive denylist. The matcher succeeds
only through the positive grammar above; it does not classify by checking that
an input is absent from this list.

## Deliberate non-goals for v1.2.1

The hotfix does not:

- use fuzzy matching, edit distance, NLP, or vendor-name inference;
- rewrite Kyber to ML-KEM or Dilithium to ML-DSA;
- add `secp256r1`, `prime256v1`, `brainpoolP256r1`, `X448`, or `Ed448`;
- add ChaCha20-Poly1305, TDEA/3DES, Blowfish, or Falcon;
- infer runtime implementation, key validity, protocol role, or policy
  approval from an identifier string;
- change the policy-pack version, scoring formula, or PDR 0.2 schema.

The deferred curve identifiers remain `unrecognized_identifier` until a
versioned, provenance-aware registry adds them. Conservative unknown handling
is preferable to an unsupported positive claim.

## Cross-layer fail-closed behavior

A recognized PQC family with unverified parameters must propagate as:

- critical blocking evidence code `unverified_algorithm_parameters`,
- confidence capped and decision grade blocked,
- human verification of the exact algorithm version and parameter set,
- action type `manual_crypto_verification`,
- execution state `verification_first`,
- verification requirement `cryptographic_parameters` at high priority,
- reason code `classification:recognized_family_unverified_parameters`,
- manual cryptographic review in the PDR,
- no standardized-PQC policy rule and no retain suggestion.

The built-in policy pack remains version `0.2`, and the PDR schema remains
version `0.2`.

## Provenance boundary

The exact PQC identifiers are grounded in NIST FIPS 203, FIPS 204, and FIPS
205. Classical migration posture uses NIST IR 8547 IPD as the current project
source. QSTriage source identifiers record classification provenance; they do
not claim that a source publication defines QSTriage scores, policy decisions,
or migration approval.
