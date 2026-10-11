# QSTriage E1: Context Resolution

Status: approved by the maintainer on 2026-10-11.
Base: `main` at `4b0bac0` (#67), QSTriage 1.4.0, PDR 0.3, policy pack
`nist-pqc-basic` 0.3.

This is a design record, not user documentation. It lives in `design/`
because files in `docs/` are published against the release tag that contains
them. No code changes accompany this record.

## 1. Problem

Six modules decide independently whether the business context of an asset
is usable:

| Module | What it checks | How it reads the value |
|---|---|---|
| `context.py` | six fields; states `declared`, `missing`, `defaulted`, `unmapped` | unknown tokens `""`, `unknown`, `no_assertion`, `no_value`, `redacted`; ignores evidence assertions |
| `evidence.py` | `data_class`, `exposure`; `retention_years`, `criticality`, `local_blast_radius` and `migration_effort` for CBOM imports only | unknown tokens `""`, `unknown`, `no assertion`; uses evidence assertions; never checks whether a value is recognized |
| `assessment.py` (`evaluate_evidence_quality`) | literal `unknown`; `retention_years == 0` for every asset; CBOM defaults by `asset_type` only | ignores evidence assertions |
| `review.py` | everything `context.py` reports | prints "is unknown" for unrecognized values |
| `closure.py` | gaps come only from `evidence.py` findings | inherits the gaps in `evidence.py` |
| `policy.py` | `data_class`, `exposure`, `retention_years` | uses `context.py` |

Three unknown-token sets and three CBOM detection functions are in use.

### 1.1 Observed disagreements

The asset under test is a hand-written inventory asset with complete context.
Each row changes one field. Measured on `4b0bac0`.

| Change | `context.py` | Evidence findings | Closure gaps | Context review | Policy | Execution state |
|---|---|---|---|---|---|---|
| none, `notes: ""` | complete | none | none | complete | no block | **gated** |
| none, `notes: "x"` | complete | none | none | complete | no block | **justified** |
| `data_class: Confidential` | unmapped | none | none | "data_class is unknown" | blocks | gated |
| `data_class: public` | unmapped | none | none | "data_class is unknown" | blocks | gated |
| `data_class: redacted` | missing | none | none | "data_class is unknown" | blocks | gated |
| `data_class: no_value` | missing | none | none | "data_class is unknown" | blocks | gated |
| `exposure: redacted` | missing | none | none | "exposure is unknown" | blocks | gated |
| `retention_years: 0` | missing | none | none | issue | blocks | gated |

Bundled Evidence Closure demo, enriched inventory:

| View | Result |
|---|---|
| Closure gap manifest | no gaps |
| Evidence review | decision-grade, no findings |
| Evidence quality | `migration_effort_context` missing, although an assertion confirms it |
| Context review | incomplete: "data_class is unknown" (value is `customer_identity_claims`), `migration_effort` reported as the CBOM default |
| Decision | gated |

The person running the demo is told that evidence is complete, and in the same
run that business context is missing.

### 1.2 Free text decides the execution state

`scoring._confidence` returns `medium-high` (base 0.80) when `notes` is not
empty and the key length is known, and `medium` (base 0.65) otherwise. The
decision threshold `minimum_decision_grade_confidence` is 0.75. For an asset
with complete declared context, as in section 1.1, one character in `notes`
moves the execution state from `gated` to `justified`. Every CBOM import
carries an import note, so every CBOM asset with a known key length receives
the higher label. The rule dates from the first public commit (`b1b8684`) and
is not documented in `docs/scoring-rationale.md`.

## 2. Goals and non-goals

Goals:

1. One function decides, for each context field, the value, its state, where
   it came from, why it is or is not usable, and what a person must do.
2. Every view (evidence review, evidence quality, closure, context review,
   policy facts, decision requirements, score confidence, report) derives from
   that function. A test proves that the views agree.
3. Every message names the field, the value read, what it means, the accepted
   values, and the consequence.
4. Labels from external classification schemes are taken from the published
   text, word for word, and are never mapped to a lower risk than the text
   supports.
5. Input in which what a reviewer sees differs from what QSTriage processes
   is rejected with an exact explanation.

Non-goals:

- No change to the algorithm registry or policy pack rules.
- No change to scoring weights.
- No PDR schema change in Phases 1 and 1b (section 10).

## 3. The resolver

```python
def resolve_asset_context(
    asset: CryptographicAsset,
    asset_evidence: AssetEvidenceAssertions | None,
    *,
    source_type: str,
) -> ResolvedAssetContext
```

`ResolvedAssetContext` holds one `ResolvedField` for each of `data_class`,
`exposure`, `retention_years`, `criticality`, `local_blast_radius` and
`migration_effort`:

| Attribute | Meaning |
|---|---|
| `field_path` | `assets[<id>].<field>` |
| `raw_value` | the value as read from the input |
| `canonical_value` | category used by scoring and policy, or `unknown` |
| `state` | section 3.1 |
| `provenance` | from the assertion when present; otherwise `user_declared`, or `qstriage_default` for a CBOM default |
| `source_reference` | from the assertion, when present |
| `reason_code` | stable identifier, also used as the evidence finding code |
| `message` | section 5 |
| `accepted_values` | the labels that would resolve the field |
| `effect` | `none`, `review` or `block` (section 3.2) |

The resolver is pure and deterministic. It reads no files and no clock.

### 3.1 States

| State | Condition |
|---|---|
| `verified` | value recognized and an assertion with `state: verified` exists |
| `declared` | value recognized; no assertion, or an assertion with `state: declared` |
| `defaulted` | value equals a QSTriage import default and no assertion exists for the field |
| `missing` | value is an unknown token (section 3.3) |
| `redacted` | value is `redacted` |
| `unmapped` | value present, not an unknown token, and not an accepted label |

`redacted` replaces the earlier working name `withheld`. The PDR enum
`EvidenceState` already contains `redacted`; one name for one concept avoids a
schema change and a translation table.

### 3.2 Effects

One table decides severity and effect. Codes marked "new" do not exist today.

| Field | State | Reason code | Severity | Effect |
|---|---|---|---|---|
| `data_class` | `missing` | `missing_data_class` | high | block |
| `data_class` | `redacted` | `redacted_data_class` (new) | high | block |
| `data_class` | `unmapped` | `unmapped_data_class` (new) | high | block |
| `exposure` | `missing` | `missing_exposure` | high | block |
| `exposure` | `redacted` | `redacted_exposure` (new) | high | block |
| `exposure` | `unmapped` | `unmapped_exposure` (new) | high | block |
| `retention_years` | `defaulted` (CBOM, 0) | `defaulted_retention_years` | high | block |
| `retention_years` | `missing` (not CBOM, 0) | `unconfirmed_zero_retention_years` (new) | high | block |
| `criticality` | `defaulted` | `defaulted_criticality` | medium | review |
| `local_blast_radius` | `defaulted` | `defaulted_local_blast_radius` | medium | review |
| `migration_effort` | `defaulted` | `defaulted_migration_effort` | medium | review |
| any | `declared`, `verified` | none | none | none |

`block` means the finding carries `decision_grade_blocked`,
`confidence_capped` and `human_review_required`. `review` means
`confidence_capped` and `human_review_required`. Existing codes keep their
current severity and effects.

### 3.3 Reading rules

1. Normalization stays as today: trim, lower case, `-` and runs of whitespace
   become `_`.
2. Unknown tokens, one set for all modules: `""`, `unknown`, `no_assertion`,
   `noassertion`, `no_value`. `noassertion` is the SPDX spelling
   `NOASSERTION`.
3. `redacted` is a separate state, not an unknown token.
4. An assertion confirms a value; it cannot supply one. An assertion on an
   unknown token leaves the field `missing` and the message states that the
   assertion has no value to confirm.
5. An assertion on an unrecognized value leaves the field `unmapped`. Who
   verified a value does not make it interpretable.
6. A CBOM default is resolved by an assertion on that field. The enriched demo
   asset (`migration_effort: medium` with a declared assertion) becomes
   `declared`.
7. `retention_years: 0` without an assertion is unresolved for every
   inventory. Existing guidance already states "0 only when explicitly
   justified"; the assertion is that justification.
8. CBOM detection, one function: `source_type == "cyclonedx_cbom"`, or
   `asset_type == "cbom_cryptographic_asset"`, or the import note marker in
   `notes`. This is the current rule in `evidence.py`.
9. Relationship completeness follows the same rule: the evidence quality
   limitation "CBOM dependency relationships are not imported" appears only
   when no relationship assertion of `none` or `known` exists.

## 4. Vocabulary

### 4.1 Canonical categories

`data_class` resolves to `sensitive`, `operational`, `public` or `unknown`.
`public` is new. Its basis is FIPS 199, which uses public information as the
example of an information type whose confidentiality impact is not
applicable:

> "SC public information = {(confidentiality, NA), (integrity, MODERATE), (availability, MODERATE)}"

Scoring treats `public` as it treats `operational` (no sensitivity
increment). No further reduction is applied; integrity and availability still
matter for signatures and key establishment.

`exposure` categories are unchanged.

### 4.2 The current label set

The current aliases (`customer_pii`, `identity_tokens`, `telemetry`,
`public_internet` and the others) were defined by QSTriage, not taken from an
external scheme. They remain accepted for compatibility, under the profile
name `qstriage-legacy`, and every output that uses them states
"QSTriage-defined label, not from an external standard".

One legacy mapping is not conservative: `internal` resolves to `operational`.
Many organizations use "Internal" as a confidentiality tier above public.
Decision D10 covers this.

### 4.3 Suggestions

For an `unmapped` value the message may name the closest accepted label. The
rule is deterministic and implemented in the repository: Damerau-Levenshtein
distance of at most 2 between normalized strings, a single closest label, no
suggestion on a tie. A suggestion is never applied automatically; the person
decides.

## 5. Messages

Every message has four parts, in this order: what was read, what it means,
what to do, what happens until it is done. Values are quoted and invisible
characters are shown as `<U+XXXX>` (section 7.3).

`unmapped`:

```text
assets[customer-api-rsa].data_class: the value "customer_identity_claims" is
not an accepted data classification label.
Accepted labels: cardholder, cardholder_data, customer_pii, gdpr_scope, health,
health_data, identity_tokens, internal, logs, medical, medical_records,
metrics, operational, patient, patient_records, payment_data,
payment_metadata, pii, pii_data, public, telemetry.
Set data_class to one of these labels in the inventory or in an Evidence
Closure patch.
Until then the decision for this asset stays gated.
```

`redacted`:

```text
assets[customer-api-rsa].data_class: the value is "redacted". The source
withheld the data classification.
Obtain the classification from the data owner and set data_class, or record
it in an Evidence Closure patch with a source_reference.
Until then the decision for this asset stays gated.
```

`defaulted`:

```text
assets[customer-api-rsa].criticality: the value "medium" is the default that
the CBOM import assigns. No evidence assertion confirms it.
Confirm or replace criticality (low, medium, high, critical) in an Evidence
Closure patch.
Until then decision confidence stays capped and human review is required.
```

Assertion without a value:

```text
assets[customer-api-rsa].data_class: an evidence assertion is recorded, but
the value is "unknown". An assertion confirms a value; it cannot supply one.
Set data_class to an accepted label.
Until then the decision for this asset stays gated.
```

## 6. Consumers

| Consumer | Change |
|---|---|
| `evidence.py` | business-context findings are produced from resolved fields using the table in 3.2 |
| `assessment.evaluate_evidence_quality` | `missing_evidence` lists the fields whose effect is not `none`; key names unchanged (`data_class`, `retention_years`, `exposure_boundary`, `business_criticality_context`, `blast_radius_context`, `migration_effort_context`) |
| `closure.py` | gaps come from the resolver; the question for `data_class` and `exposure` lists the accepted labels; `closure validate` warns when a patch value would be `unmapped` (D4) |
| `review.py` | issues and messages come from the resolver |
| `policy.py` | `business_context` is `missing` when `data_class`, `exposure` or `retention_years` has effect `block`; the `*_state` facts can also take `verified` and `redacted` |
| `decision.py` | verification requirements come from resolved fields; field-to-requirement mapping unchanged |
| `scoring.py` | canonical values from the resolver; confidence label per section 6.1 |
| report | a "Why this decision is gated" section lists blocking fields and blocking policy rules, read from data the PDR already contains |

`context.py` keeps `normalize_context_text` and the alias tables; the
resolver replaces `normalize_asset_context`.

### 6.1 Confidence label

| Label | Condition |
|---|---|
| `medium-high` | key length known and every context field `declared` or `verified` |
| `medium` | key length known and at least one context field unresolved |
| `low` | key length unknown |

`notes` no longer affects the label. `high` stays unused, as today.

Effect: an asset with complete declared context and no notes moves from
`gated` to the state its evidence supports; an asset with notes and incomplete
context loses the higher label. The bundled sample inventory is unaffected
(every asset has notes and complete context).

### 6.2 Unresolved values in the score

Today an unresolved `data_class` scores as not sensitive and an unresolved
`exposure` scores 5.0, between internal (4.0) and partner (7.0). Verification
priority uses the score band, so missing context can lower attention. Decision
D6 covers this.

## 7. Input that cannot be read as written

The question is not the intent of the author, which QSTriage cannot know, but
whether a reviewer reading the input or a QSTriage output would see something
different from what QSTriage processed.

### 7.1 Visible mistakes: explain and continue

The reviewer sees exactly what QSTriage read. Examples: `Confidential`,
`customer_identity_claims`, `X25519-ML-KEM-768`. The asset is processed, the
field or identifier is unresolved, the message follows section 5, and the
decision stays gated.

### 7.2 Divergence: stop and explain

The reviewer would see one thing and QSTriage would process another.
QSTriage writes no output, exits with the input-error code, and reports every
occurrence in one run: field path, position, code point, character name, and
the replacement to use.

| Case | Fields | Basis |
|---|---|---|
| Default ignorable code points (zero-width characters, bidirectional controls, and others) | identifier fields | UTS #39 section 3.1 restricts `Identifier_Type=Default_Ignorable` |
| Control characters (general category Cc, Cf) | identifier fields | as above |
| Mixed-script value | identifier fields | UTS #39 section 5.1 |
| Any non-ASCII character | `algorithm` | every registry identifier is ASCII; a non-ASCII character can only fail to match or imitate an ASCII one |
| Record or patch hash mismatch | PDR, Evidence Closure patch | existing behaviour |

Identifier fields: asset `id`, dependency `id`, `source` and `target`,
`algorithm`, `data_class`, `exposure`, and `asset_id` and `field` in Evidence
Closure patches.

Example:

```text
Input rejected: assets[gw-01].algorithm contains a character that looks like
a Latin letter but is not one.
  position 1: U+039C GREEK CAPITAL LETTER MU
Algorithm identifiers use ASCII characters only. Replace the character with
the Latin letter M (U+004D) and run the command again.
No output was written.
```

The message does not accuse. A Greek or Cyrillic keyboard layout and a
copied non-breaking hyphen (U+2011) produce the same rejection, and the
person corrects them in one step.

### 7.3 Free text: accept and make visible

`name`, `notes`, `source_reference` and `rationale` are accepted as written.
UTS #55 section 1.2.3 states "The solution is not to forbid the directional
formatting characters", and section 4.2 recommends an option "to make visible
any default ignorable code points". Human-readable outputs (terminal,
Markdown, HTML) render such characters as `<U+XXXX>`. Machine-readable
outputs (JSON, PDR) keep the exact value, so hashes still cover what was read.
An evidence finding `invisible_characters_in_text` (info) records the field.

### 7.4 Schema errors

A wrong type, a missing required field or an invalid enum value (for example
`criticality: hgih`) leaves no defined input to decide on. QSTriage reports
every schema error in one run, each with field path, value read, accepted
values and a suggestion under section 4.3, and writes no output (D8).

### 7.5 Unicode data

Python 3.11 to 3.14 ship different Unicode versions, and `unicodedata` does
not expose `Script`, `Script_Extensions` or `Default_Ignorable_Code_Point`.
The implementation vendors a generated table from one pinned Unicode version
(`Scripts.txt`, `ScriptExtensions.txt`, `DerivedCoreProperties.txt`), records
the source file hashes, and ships the generator script. Results are then the
same on every supported Python version.

## 8. Classification profiles (Phase 2)

### 8.1 Mapping rule

A label maps to `sensitive` when its published definition describes any harm
from unauthorised disclosure. It maps to `public` only when the published text
states that confidentiality does not apply. No label maps to `operational`.
The rule can raise attention above what an organization intends; it never
lowers it below what the scheme states.

### 8.2 Candidate profiles

Retrieved 2026-10-11 from the primary sources listed in section 12.

| Profile | Labels (verbatim) | Canonical | Basis |
|---|---|---|---|
| `fips-199` | `LOW`, `MODERATE`, `HIGH` | sensitive | "limited adverse effect", "serious adverse effect", "severe or catastrophic adverse effect" |
| `fips-199` | `NOT APPLICABLE` | public | "The potential impact value of not applicable only applies to the security objective of confidentiality." |
| `uk-gscp` | `OFFICIAL`, `SECRET`, `TOP SECRET` | sensitive | "The three classification tiers are: OFFICIAL, SECRET and TOP SECRET." |
| `uk-gscp` | `OFFICIAL-SENSITIVE` | sensitive | "The -SENSITIVE marking should be applied to OFFICIAL information that is not intended for public release and that is of at least some interest to threat actors (internal or external), activists or the media." |
| `eu-euci` | `TRÈS SECRET UE/EU TOP SECRET`, `SECRET UE/EU SECRET`, `CONFIDENTIEL UE/EU CONFIDENTIAL`, `RESTREINT UE/EU RESTRICTED` | sensitive | Council Decision 2013/488/EU, Article 2(2) |
| `eu-gdpr` | `personal data`, `special categories of personal data` | sensitive | Regulation (EU) 2016/679, Article 4(1), Article 9 |
| `us-cui` | `CUI`, `CUI Basic`, `CUI Specified` | sensitive | 32 CFR 2002.4(h), (j), (r) |
| `us-classified` | `Top Secret`, `Secret`, `Confidential` | sensitive | Executive Order 13526, Sec. 1.2(a) |

For FIPS 199 the label in `data_class` is the confidentiality impact value.
FIPS 199 applies its levels to confidentiality, integrity and availability
separately; QSTriage reads only the confidentiality value from `data_class`.

The UK OFFICIAL definition reads: "The majority of information that is
created, processed, sent or received in the public sector and by partner
organisations, which could cause no more than moderate damage if compromised
and must be defended against a broad range of threat actors with differing
capabilities using nuanced protective controls." Under the rule in 8.1 it maps
to `sensitive`, including OFFICIAL information intended for publication.

The EUCI text was read in the original Official Journal publication and in the
consolidated version of 14 August 2025; Article 2(2) is identical in both.

### 8.3 Excluded

| Scheme | Reason |
|---|---|
| FIRST TLP 2.0 | "TLP is not a formal classification scheme." TLP labels govern sharing, not sensitivity. |
| ISO/IEC 27001 and 27002 | Require an organization to classify information but do not define labels. Not verified from the primary text (paid standard). Covered by Phase 3. |

### 8.4 Selection and recording

An optional top-level inventory field `context_profiles` lists the active
profiles. Absent, the default is `["qstriage-legacy"]`. The field is part of
the inventory, so `source_hash` covers the selection.

Profiles live in a versioned data file with verbatim excerpts and source
references, like the algorithm registry. The PDR records its identifier,
version and hash, and `run_id` includes the hash. This changes the PDR
contract and requires PDR 0.4; it receives its own approval before
implementation.

A label present in two active profiles is accepted only if both map it to the
same category; the output names both profiles.

## 9. Organization mapping (Phase 3)

An optional inventory section maps an organization's own labels:

```yaml
context_mappings:
  data_class:
    Confidential:
      canonical: sensitive
      source_reference: ISMS-POL-07 section 3
```

Constraints:

1. Every mapping requires `source_reference`.
2. A mapping cannot redefine a label of an active official profile. Such an
   input is rejected with the profile, the label and the published category.
3. The output states "organization-defined label" and the source reference.

## 10. Compatibility and output changes

| Phase | PDR contract | Expected output change |
|---|---|---|
| 1 | unchanged; new finding codes only (decision C2) | new findings for unmapped, redacted and zero-retention values; confidence label per 6.1; demo expected files; sample inventory PDR unchanged apart from engine version |
| 1b | unchanged | rejected inputs that contain divergent characters; `<U+XXXX>` rendering in human-readable outputs |
| 2 | PDR 0.4 | `registry_context`-style record of the profile file |
| 3 | inventory schema addition | none for inventories without mappings |

Exact before and after hashes for the bundled sample, the Evidence Closure
demo and the CBOM fixture are listed in each PR.

The demo patch value `customer_identity_claims` becomes `customer_pii`, so the
demo ends with a decision-grade record (decision C3).

## 11. Tests

1. Agreement: for every combination of field state, CBOM or hand-written
   origin and assertion presence, the fields reported by closure gaps,
   evidence findings, evidence quality, context review, policy facts and
   decision requirements are the same set.
2. Table: each row of 3.2 produces its code, severity and effects.
3. Messages: each state produces the four parts of section 5; no message
   says "unknown" for a value that is present.
4. Confidence: changing only `notes` never changes the execution state.
5. Divergence: Greek and Cyrillic look-alikes, U+200B, U+202E, U+2011 and
   fullwidth letters in each identifier field are rejected with every position
   reported; the same characters in `notes` are accepted and rendered visibly.
6. Determinism: Unicode table results are identical on Python 3.11 to 3.14.

## 12. Decisions

All decisions were adopted as listed on 2026-10-11.

| ID | Decision | Outcome | Counter-argument considered |
|---|---|---|---|
| D1 | State name `redacted` instead of `withheld` | adopted | `withheld` describes the meaning better; two names for one concept cost more |
| D2 | Effect table in 3.2, including blocking `retention_years: 0` without an assertion in every inventory | adopted | ephemeral data may truly have 0; the assertion records that once |
| D3 | An assertion resolves a CBOM default | adopted | an assertion of `medium` is indistinguishable from the default value; the assertion and its source reference are the difference |
| D4 | `closure validate` warns on an unmapped patch value and exits 0 | adopted; the comparison step still shows the field unresolved | a non-zero exit would stop automated runs earlier |
| D5 | Confidence label from resolved context, not `notes` (6.1) | adopted; its own PR first, for a patch release | changes decision confidence for assets without notes |
| D6 | Unresolved `data_class` and `exposure` scored with the worst case (`sensitive`, `public`), with the assumption written to `assumptions_made` | adopted; its own PR | raises every CBOM import to high attention; that is the intended effect of fail-closed |
| D7 | Divergence rules in 7.2 and 7.3 | adopted | stopping on a copied hyphen adds friction; the message makes the fix one step |
| D8 | Schema errors: report all, write nothing | adopted | the principle "explain instead of stop" is met by the explanation; a record built on an undefined value would be misleading |
| D9 | Profiles and mapping rule in section 8, with PDR 0.4 | rule adopted; the PDR change returns for separate approval | the rule raises attention for OFFICIAL information intended for publication |
| D10 | Legacy label `internal` for `data_class` | kept in Phase 1; in Phase 2 report it as ambiguous with a deprecation notice | changing it in Phase 1 would gate existing users without warning |
| D11 | Organization mapping constraints in section 9 | adopted | requiring `source_reference` adds effort for small teams |

### 12.1 Delivery order

1. This record, as `design/context-resolution.md`.
2. D5: confidence label (small PR; candidate for 1.4.1). Until step 3 it
   reads completeness from the current `normalize_asset_context`.
3. Resolver and all consumers, messages, demo fix, agreement test.
4. D6: unresolved values in the score.
5. Phase 1b: input divergence and Unicode tables.
6. Phase 2 design addendum for PDR 0.4, then profiles.
7. Phase 3: organization mapping.

## 13. Sources

- NIST FIPS 199, Standards for Security Categorization of Federal Information
  and Information Systems, February 2004. https://csrc.nist.gov/pubs/fips/199/final
- UK Cabinet Office, Government Security Classifications Policy, published
  30 June 2023, updated 5 August 2024.
  https://www.gov.uk/government/publications/government-security-classifications
- Council Decision 2013/488/EU on the security rules for protecting EU
  classified information, OJ L 274, 15.10.2013, Article 2; consolidated
  version 14.08.2025. https://eur-lex.europa.eu/eli/dec/2013/488/oj
- Regulation (EU) 2016/679 (GDPR), Articles 4(1) and 9(1).
  https://eur-lex.europa.eu/eli/reg/2016/679/oj
- 32 CFR 2002.4, Definitions (eCFR, current as retrieved).
  https://www.ecfr.gov/current/title-32/section-2002.4
- Executive Order 13526, Classified National Security Information, 75 FR 707,
  5 January 2010, Sec. 1.2.
  https://www.govinfo.gov/content/pkg/FR-2010-01-05/html/E9-31418.htm
- FIRST, Traffic Light Protocol 2.0, August 2022. https://www.first.org/tlp/
- Unicode Technical Standard #39, Unicode Security Mechanisms, version
  18.0.0, 2026-08-27, sections 3.1, 4, 5.1. https://www.unicode.org/reports/tr39/
- Unicode Technical Standard #55, Unicode Source Code Handling, version 2,
  2024-01-29, sections 1.2.3, 4.2. https://www.unicode.org/reports/tr55/
