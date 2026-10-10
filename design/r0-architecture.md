# QSTriage R0: Architecture and Contracts

Status: approved by the maintainer on 2026-10-09.
Base: `main` at `60fbb79`, QSTriage 1.3.0, PDR 0.2, policy pack
`nist-pqc-basic` 0.2.
Target release for layer 1: v1.4.0.

This is a design record, not user documentation. It lives in `design/`
because files in `docs/` are published against the release tag that contains
them.

This document fixes the decisions that must be made before v1.4.0 code is
written. It contains no production code. Where it refers to current behavior,
the code and tests at the base commit are authoritative.

## 1. Users and jobs

QSTriage serves three roles. They are often different people in different
organizations.

| Role | Who | What they do with QSTriage |
|---|---|---|
| Operator | Engineer or consultant engaged by the organization, internal security architect | Runs the CLI, builds and enriches the inventory, closes evidence gaps, generates PDRs |
| Reviewer | Internal audit, external auditor, certification body, supervisory authority | Receives the results without running the tool by default; checks that each decision is supported, traceable, and unaltered; may re-perform the run |
| Decision owner | CISO, risk committee, board | Needs current position, blocking items, and deadlines |

What each role needs from QSTriage:

- The reviewer needs to re-perform a run and obtain the same output, to trace
  each decision to evidence, a policy rule, and a published source, to see
  explicitly what is not known, and to confirm that the delivered output was
  not modified after generation.
- The operator needs a prioritized and defensible decision backlog from an
  inventory or CBOM, and the evidence that the reviewer will ask for.
- The decision owner needs progress over time and deadline exposure, stated
  in terms of risk rather than cryptography.

Regulatory context that creates these jobs:

- Commission Delegated Regulation (EU) 2024/1774 (DORA ICT risk management
  RTS), Article 6(5), requires the encryption policy of a financial entity to
  provide for updating or changing cryptographic technology "on the basis of
  developments in cryptanalysis". Entities that cannot update must adopt
  mitigation and monitoring measures. Article 6(6) requires those measures to
  be recorded with "a reasoned explanation". Article 7(4) requires a register
  of all certificates and certificate-storing devices for at least the ICT
  assets that support critical or important functions.
- The EU Coordinated Implementation Roadmap for the Transition to
  Post-Quantum Cryptography (EU Member States with Commission support,
  23 June 2025) describes inventories of cryptographic assets as a first
  "no-regret" step, sets readiness by the end of 2026, migration of
  high-risk use cases by 2030 and of medium-risk use cases by 2035, and
  recommends standardized and tested hybrid solutions where feasible.
  The roadmap text itself was not retrievable during research; these points
  come from the Commission page and from quotations in the CEPS Task Force
  comments. They must be checked against the roadmap text before any policy
  pack encodes them.

## 2. Principles

P1. Designed for the reviewer, adopted through the operator. When the needs of
the two roles conflict, verifiability wins. Where they do not conflict, the
operator's ergonomics are optimized. Existing behavior already follows this
rule: unknown identifiers fail closed, output is deterministic, and evidence
patches are applied only by a human.

P2. Determinism. The same inventory bytes, registry, policy pack, and engine
version produce byte-identical PDR output.

P3. Fail closed. An identifier receives a positive classification only when
it matches a registry entry exactly and that entry has a published source.
A positive classification is `quantum_status` `quantum_resistant` or a
standardized PQC or hybrid `standard_status`. Any other identifier is
`unknown`, or, for a recognized PQC family with a missing or unsupported
parameter set, a family with unverified parameters, as today. Recognizing a
name is not approval.

P4. Human authority. QSTriage proposes and records. It does not authorize
production change, and no layer applies a change without a human action.

P5. Classification is separate from policy. The registry states what an
identifier is and which sources define it. Whether it is acceptable for a use
case is decided by a policy pack. Authorities differ on this point, so the
difference must remain expressible as separate policy packs.

P6. Presentation never decides. Any user interface displays CLI output. It
computes no classification, score, or decision.

## 3. External basis

Each requirement in this document that depends on an outside source cites it.
Status was checked on 2026-10-09.

| Reference | Status | Used for |
|---|---|---|
| NIST FIPS 203, 204, 205 | Final | Existing standardized PQC entries |
| NIST IR 8547 | Initial public draft (12 Nov 2024); no later version published | Existing `quantum_vulnerable` sources; keep the `-IPD` identifier |
| NIST SP 800-227 | Final, 18 Sep 2025 | Section 4.6: multi-algorithm KEMs and PQ/T hybrids |
| RFC 10024 | Standards Track, Aug 2026 | Hybrid TLS 1.3 groups `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` |
| RFC 9794 | Informational, Jun 2025 | Terminology for PQ/T hybrid schemes |
| RFC 8785 | Informational, Independent Stream, Jun 2020 | Canonical JSON form for PDR 0.3 hashes (D4) |
| draft-ietf-lamps-pq-composite-sigs-19 | In the RFC Editor queue; no RFC number | Composite ML-DSA; not eligible for positive classification |
| (EU) 2024/1774, Articles 6 and 7 | In force | Record of mitigation decisions; certificate register |
| EU PQC Coordinated Implementation Roadmap | Published 23 Jun 2025; primary text not yet read | Deadlines for layer 4 and an EU policy pack |

Facts taken from these sources:

- RFC 10024 defines three groups with codepoints 4588 (`X25519MLKEM768`,
  Recommended: Y), 4587 (`SecP256r1MLKEM768`, Recommended: N), and 4589
  (`SecP384r1MLKEM1024`, Recommended: N). In `X25519MLKEM768` the ML-KEM share
  and shared secret come first. In the two NIST-curve groups the ECDHE share
  and shared secret come first. The RFC states that each group can be
  implemented in a FIPS-approved way, which requires a validated
  implementation of the first component: ML-KEM for `X25519MLKEM768`, ECDHE
  for the other two (RFC 10024, Sections 2 and 5).
- SP 800-227 Section 4.6.2 approves its key combiner when at least one
  component shared secret comes from an SP 800-56A or SP 800-56B scheme or an
  approved KEM. Approval attaches to the combiner, not to the hybrid scheme as
  a whole. X25519 is not an approved component in that document.
- RFC 9794 defines a PQ/T hybrid scheme as a multi-algorithm scheme with at
  least one post-quantum and at least one traditional component, and a PQ/PQ
  hybrid scheme as one in which all components are post-quantum. RFC 9794 uses
  "composite" for a hybrid exposed as a single interface of the component
  type. QSTriage already uses the family value
  `classical_public_key_composite` for a different concept (classical key
  establishment plus classical authentication in one identifier). That
  public value is not renamed in v1.4.0, because renaming it would break PDR
  consumers. New hybrid values must not use the word "composite".

## 4. Evolution model

The mechanism has three parts: new knowledge enters as versioned data
(variation), a human accepts or rejects its effect (selection), and both the
data and the human decision are kept with hashes (retention). P2, P3, and P4
apply to every layer.

| Layer | Adds | Depends on | Target |
|---|---|---|---|
| 1. Knowledge | Algorithm registry as versioned data; PQ/T hybrid classification; `pdr diff`; identifier corpus | none | v1.4.0 |
| 2. Judgment | Append-only record of human review outcomes; recurring overrides become proposals | 1 | v1.5.0 |
| 3. Sensing | Scheduled re-evaluation of stored inventories against a new registry or policy version; an issue lists decisions that would change | 1 | later |
| 4. Time | Deadlines attached to policy rules; decisions can become overdue without any input change | 1, policy packs | later |
| 5. Ecosystem | Separately signed registry and policy packs; scanner inputs such as CBOMkit | 1 to 4 | later |
| 6. Progress | PDR history as evidence of migration progress | 1, 2 | later |

Layer 5 comes last because it introduces trust in material produced outside
the repository. Layer 1 reserves the fields that layers 4 and 5 need, so that
they do not require a registry schema change.

## 5. Layer 1 contracts (v1.4.0)

### 5.1 Algorithm registry

Location: a JSON data file inside the package, for example
`qstriage/registry/algorithms.json`. It ships in the wheel and the sdist, so
the existing release attestations cover it.

Top-level fields:

| Field | Meaning |
|---|---|
| `registry_schema_version` | Version of this schema |
| `registry_id` | Stable identifier, for example `qstriage-algorithms` |
| `registry_version` | Version of the content |
| `entries` | List of entries |
| `signatures` | Reserved for layer 5. Empty in v1.4.0 |

Entry fields:

| Field | Meaning |
|---|---|
| `entry_id` | Stable identifier, for example `tls-group-x25519mlkem768` |
| `identifiers` | Exact normalized identifiers that resolve to this entry. Matching rules stay those of the identifier grammar; the registry does not introduce fuzzy matching |
| `scheme_type` | `single`, `pq_t_hybrid`, or `pq_pq_hybrid` (terms from RFC 9794) |
| `algorithm_family`, `primitive`, `quantum_status`, `standard_status` | As in the current `AlgorithmClassification` |
| `components` | For hybrids only: an ordered list of component entry IDs. Order is the order defined by the source |
| `validation_component` | For hybrids only: the component whose implementation must be validated for a FIPS-approved key derivation, as stated by the source |
| `sources` | A non-empty list. Each source has `source_id`, title, section, publication status, and date |
| `lifecycle` | `published`, `draft`, `deprecated`, or `withdrawn` |
| `deadlines` | Reserved for layer 4. Empty in v1.4.0 |

Source acceptance rules:

- An entry may produce a positive classification (as defined in P3) only if
  at least one source has a published status: a final NIST FIPS or SP, an
  RFC, or an equivalent final standard.
- An entry whose only sources are drafts may exist with `lifecycle: draft`.
  It is resolved to `unknown`, and its draft status is reported so that the
  reviewer sees that the identifier is known to be pending.
- Draft NIST publications that are already used as sources (for example
  NIST IR 8547 IPD for `quantum_vulnerable`) keep their current role.
  Classifying an algorithm as vulnerable can only lead to more review, never
  less, so it does not need the same evidence threshold as a positive
  classification.

Migration without behavior change: v1.4.0 first moves the current
classification tables from `qstriage/standards.py` into registry content
version 1. Acceptance criterion: for every identifier in the existing tests and
the compatibility corpus, the classification is identical before and after the
move. Only then are new entries added.

### 5.2 PQ/T hybrid classification

New entries in registry content version 2, from RFC 10024:

| Identifier | Components in order | `validation_component` |
|---|---|---|
| `X25519MLKEM768` | ML-KEM-768, X25519 | ML-KEM-768 |
| `SECP256R1MLKEM768` (normalized from `SecP256r1MLKEM768`) | ECDHE P-256, ML-KEM-768 | ECDHE P-256 |
| `SECP384R1MLKEM1024` (normalized from `SecP384r1MLKEM1024`) | ECDHE P-384, ML-KEM-1024 | ECDHE P-384 |

Classification values for these entries:

- `scheme_type`: `pq_t_hybrid`
- `algorithm_family`: `pq_t_hybrid_kem` (D2)
- `primitive`: `key_establishment`
- `quantum_status`: `quantum_resistant`
- `standard_status`: `standardized_pq_t_hybrid` (new value)
- `sources`: RFC 10024, NIST SP 800-227 Section 4.6, and FIPS 203 for the
  ML-KEM component

`quantum_resistant` here states that the scheme contains a FIPS 203 component
combined as specified by RFC 10024. It does not state that the hybrid as a
whole is approved; SP 800-227 Section 4.6.2 attaches approval to the key
combiner, not to the scheme.

Not included:

- `X25519Kyber768Draft00` and other pre-standard Kyber names. They name a
  different, pre-FIPS 203 construction. They stay `unknown`, as today.
- Composite ML-DSA signatures. Their specification is in the RFC Editor queue
  with no RFC number. They may be recorded as `lifecycle: draft` and stay
  `unknown`.
- The guard added in #51 stays. An identifier that contains a PQ marker and
  is not an exact registry identifier receives no positive classification:
  it is `unknown`, or, for a PQC-family-prefixed value, a recognized family
  with unverified parameters, as today.

Code paths that read `quantum_status` or `standard_status` and must define
behavior for the new value (reviewed at the base commit):

| Location | Current behavior | Required decision |
|---|---|---|
| `qstriage/decision.py`, action selection | `standardized_pqc` leads to `retain_monitor`; a new value has no branch | `retain_monitor` with human review required until the `validation_component` is evidenced (D3) |
| `qstriage/decision.py`, reason codes | Emits `classification:standardized_pqc` | Add `classification:standardized_pq_t_hybrid` |
| `qstriage/scoring.py`, `_cryptographic_risk` | `quantum_resistant` returns 1.5 | Confirm that hybrids receive the same value, or define a different one |
| `qstriage/pdr.py`, target-state suggestions | `quantum_resistant` gives "retain" with the rationale "standardized post-quantum cryptography" | The rationale is inaccurate for hybrids. Hybrids need their own text naming the components and the validation component |
| `qstriage/policy.py`, built-in rule `standardized_pqc_can_be_retained_with_operational_review` | Matches only `standardized_pqc` | Add a separate hybrid rule in policy pack 0.3; do not widen the existing rule |
| `qstriage/report.py` | Prints source IDs | Print components in order |

The policy pack version changes from 0.2 to 0.3 because a rule is added.

### 5.3 PDR 0.3

PDR 0.3 is a contract-version change. Hashes change.

Changes:

1. A document-level `registry_context` with `registry_id`,
   `registry_version`, and `registry_hash`, copied into each record in the
   same way as `policy_context`.
2. `run_id` is derived from `source_hash`, `policy_pack_hash`,
   `registry_hash`, and `pdr_version`.
3. `observed_state` gains `scheme_type` and, for hybrids, `components` and
   `validation_component`.
4. The `standard_status` value `standardized_pq_t_hybrid` is added.
5. The canonical serialization used for `record_hash`, `document_hash`, and
   `registry_hash` is RFC 8785, so that an independent implementation can
   recompute them (D4).

Why item 5 is needed: PDR 0.2 hashes the output of Python
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. That
form is not RFC 8785. Python writes the float `96.0` as `96.0` and `1e-07` as
`1e-07`, while RFC 8785 requires `96` and `1e-7`. Python also sorts keys by
code point, while RFC 8785 sorts by UTF-16 code unit. The two orders differ
only for characters outside the Basic Multilingual Plane. PDR documents
contain floats, for example `risk_attention_score`, so a browser cannot
reproduce a PDR 0.2 hash with standard JSON tools. PDR 0.3 therefore adopts
RFC 8785 (D4).

Existing PDR 0.2 documents keep their meaning. QSTriage has no standalone
verification command today. v1.4.0 adds `qstriage pdr verify` (D6). It and
`pdr diff` apply 0.2 rules to 0.2 documents and 0.3 rules to 0.3 documents.

### 5.4 `pdr diff`

Command: `qstriage pdr diff BEFORE.json AFTER.json [--format json|markdown]`.
Read-only. It writes only to standard output or to a new file under the
existing no-clobber rule.

Rules:

1. Both inputs are verified first (document hash and record hashes). A failed
   verification stops the command. It does not produce a partial diff.
2. Records are matched by `record_id`. Output lists added, removed, and
   changed records in a deterministic order: `record_id` ascending.
3. For a changed record, the output lists each changed field of `decision`
   and `observed_state`, with the old and new values.
4. Attribution is by provenance, not by inference. The command compares
   `input_snapshot.source_hash`, `policy_context.policy_pack_hash`,
   `registry_context.registry_hash`, `engine.version`, and `pdr_version`, and
   reports every provenance item that differs. If more than one differs, the
   output says that the cause cannot be isolated to one input.
5. If the two documents have different `pdr_version` values, fields whose
   meaning changed between versions are reported as a contract change, not as
   a decision change.

### 5.5 Identifier corpus and property tests

The existing compatibility corpus is extended with:

- the three RFC 10024 group names in their published spelling;
- pre-standard names that must stay `unknown`, for example
  `X25519Kyber768Draft00`;
- names from the IANA TLS Supported Groups registry are deferred to a later
  release (D5).

Property tests, independent of any single example:

- normalization is idempotent;
- every identifier listed in a registry entry resolves to that entry;
- every identifier with a PQ marker that is not listed in the registry
  receives no positive classification;
- no draft-only entry produces a classification other than `unknown`.

## 6. Layer 2 outline (v1.5.0, schema reserved now)

A review record answers DORA RTS Article 6(6): it records the measure adopted
and the reasoned explanation. Proposed fields:

| Field | Meaning |
|---|---|
| `record_id`, `record_hash` | The PDR record under review |
| `outcome` | `accepted`, `overridden`, or `deferred` |
| `reason` | Required for `overridden` and `deferred` |
| `mitigation` | Mitigation and monitoring measures, if any |
| `reviewer` | Identity as stated by the organization |
| `reviewed_at` | Timestamp supplied by the reviewer, not by the clock of the machine that runs QSTriage, so that the record stays deterministic |
| `previous_review_hash` | Links reviews into an append-only chain |
| `signature` | Reserved |

Review records are stored outside the PDR, so a review never changes a PDR
hash. Recurring overrides of the same rule become proposals for a registry or
policy change. They are never applied automatically.

## 7. Layers 3 to 6 outline

- Layer 3 (sensing) reuses `pdr diff`. A scheduled job regenerates PDRs for
  stored inventories under a new registry or policy version and opens an issue
  that lists the decisions that would change. The job uses the same
  permission model as the security alert workflow (#56).
- Layer 4 (time) fills `deadlines` in registry entries and adds deadlines to
  policy rules. A decision whose deadline has passed reports an overdue state.
  The evaluation date is an explicit input, never the system clock, so that
  P2 holds.
- Layer 5 (ecosystem) signs registry and policy packs that are published
  separately and verifies them before use. A PDR records which pack and which
  signer were used.
- Layer 6 (progress) aggregates a series of PDRs and review records into a
  migration history.

## 8. Presentation layer

The first user interface is a single self-contained HTML evidence package that
the CLI generates. The same file serves as the demonstration (`qstriage demo`
with the bundled examples) and, published as a static page, as the public
demo.

Requirements:

- No server, no open port, no network access, no external scripts, styles, or
  fonts. All data is embedded in the file.
- A Content Security Policy in the file that blocks network requests.
- All values taken from inputs are escaped when rendered. The existing
  presentation-character neutralization applies.
- The page recomputes `record_hash` and `document_hash` in the browser and
  shows the result for each. This requires the specified serialization of
  section 5.3. Browser support for Web Crypto on pages opened from `file://`
  must be confirmed during implementation. If a browser does not provide it,
  the page must say that it could not verify, rather than show a pass.
- The page displays decisions; it never computes them (P6).
- For the same PDR input and engine version, the generated HTML is
  byte-identical.

## 9. Security considerations

- Registry integrity: the registry ships inside the attested wheel, and every
  PDR records its version and hash. A modified registry produces a different
  `registry_hash` and a different `run_id`.
- Fail-closed boundary: registry entries add positive classifications only
  with a published source (section 5.1). The PQ-marker guard from #51 stays.
- Diff: verifies inputs before comparing and never writes over files.
- Evidence package: static and offline (section 8).
- Review records (layer 2): stored separately, hash-chained, and they do not
  modify PDRs.

## 10. Decisions

Approved by the maintainer on 2026-10-09.

D1. Registry file format: JSON. No new dependency, and RFC 8785 applies to it
directly.

D2. Family value for hybrids: `pq_t_hybrid_kem`, shared by all PQ/T hybrid
KEM entries. The RFC 10024 group name is kept in `entry_id`, in
`identifiers`, and through `components`. One policy rule can address every
hybrid. The value contains no slash, so target-state option names derived
from the family remain valid identifiers.

D3. Action for `standardized_pq_t_hybrid` under `nist-pqc-basic` 0.3:
`retain_monitor` with human review required until the implementation of the
`validation_component` is evidenced as validated. RFC 10024 ties FIPS-approved
key derivation to a validated implementation of that component; the
identifier alone does not show it.

D4. Canonical serialization: RFC 8785, implemented in the repository for the
JSON types that PDR documents and the registry use, and tested with the
examples in the RFC. Development tests also compare the output with the
`rfc8785` package (0.1.4 on PyPI). That package is not a runtime dependency.

D5. Corpus scope for v1.4.0: the RFC 10024 group names and the pre-standard
names that must stay `unknown`. Names from the IANA TLS Supported Groups
registry are deferred, because that registry changes and would need a dated
snapshot and a refresh procedure.

D6. v1.4.0 includes `qstriage pdr verify FILE`. It checks `document_hash` and
every `record_hash` and reports the result per record. `pdr diff` uses the
same verification.

### Amendment, 2026-10-10 (approved by the maintainer)

Made while implementing section 5.2, after reading the primary text of
RFC 10024 and NIST SP 800-227 Section 4.6. Sections 5.1 to 5.3 and D3 above
are kept as approved; where they differ, this amendment applies.

A1. RFC 10024 Section 5 uses "certified", not "validated": "This means that
for SecP256r1MLKEM768 and SecP384r1MLKEM1024, the ECDHE implementation must
be certified, whereas the ML-KEM implementation does not require
certification. In contrast, for X25519MLKEM768, the ML-KEM implementation
must be certified." The field `validation_component` is named
`certification_component`, and D3 reads "until the implementation of the
`certification_component` is evidenced as certified".

A2. RFC 10024 Section 5 describes itself as informal notes: "This section
provides informal notes on how the hybrid key agreement mechanisms defined in
this document relate to existing NIST guidance on key derivation and hybrid
key establishment." Generated text attributes the certification statement to
that section and says so.

A3. Registry sources carry `excerpt`, verbatim text from the cited section
(registry schema version 2). QSTriage wording stays in `rationale` and is
never presented as source text.

A4. `components` holds component algorithm names spelled as in RFC 10024
(`ML-KEM-768`, `X25519`, `secp256r1`, `secp384r1`, `ML-KEM-1024`), in the
shared-secret order of RFC 10024 Section 4.3, not registry entry IDs. The
identifiers keep the RFC spelling, for example `SecP256r1MLKEM768`; matching
normalizes both sides.

## 11. Items to verify before implementation

- The text of the EU Coordinated Implementation Roadmap (section 1). It must
  be read in its published form before an EU policy pack uses its dates.
- Web Crypto availability for pages opened from `file://` in current
  Chromium, Firefox, and Safari (section 8).
- Exact component names for composite ML-DSA, once an RFC number is assigned.

## References

- NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms, September
  2025. https://csrc.nist.gov/pubs/sp/800/227/final
- RFC 10024, Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3,
  August 2026. https://www.rfc-editor.org/rfc/rfc10024.html
- RFC 9794, Terminology for Post-Quantum Traditional Hybrid Schemes, June 2025.
  https://www.rfc-editor.org/rfc/rfc9794.html
- RFC 8785, JSON Canonicalization Scheme (JCS), June 2020.
  https://www.rfc-editor.org/rfc/rfc8785.html
- NIST IR 8547 (Initial Public Draft), November 2024.
  https://csrc.nist.gov/pubs/ir/8547/ipd
- draft-ietf-lamps-pq-composite-sigs-19.
  https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
- Commission Delegated Regulation (EU) 2024/1774, Articles 6 and 7, OJ L,
  25.6.2024.
- Coordinated Implementation Roadmap for the Transition to Post-Quantum
  Cryptography, 23 June 2025.
  https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
- CEPS Task Force, comments on the NIS Cooperation Group roadmap on PQC
  transition, October 2025.
  https://cdn.ceps.eu/2025/10/Task-FORCE-Comments-on-the-NIS-CG-Roadmap-on-PQC-Transition_FINAL.pdf
