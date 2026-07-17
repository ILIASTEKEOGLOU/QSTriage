# QSTriage Evidence and Context

QSTriage separates declared business context, normalized context, context completeness, and evidence quality. These are related but distinct boundaries.

This document describes the public behavior implemented by `qstriage/context.py`, `qstriage/review.py`, and `qstriage/evidence.py`. Code and tests remain authoritative for executable behavior.

## Why the layers are separate

QSTriage uses three complementary layers:

1. **Context normalization** maps supported user terms into bounded canonical values without guessing.
2. **Decision context review** identifies missing, defaulted, or unmapped business context.
3. **Evidence review** produces typed findings, evidence scores, confidence caps, decision-grade state, and human actions.

A normalized value is not proof that the value is correct. A complete context review does not establish that the source is authoritative. An evidence score is not a cryptographic strength score or security approval.

## Context normalization

Text normalization:

1. trims leading and trailing whitespace,
2. converts text to lowercase,
3. converts hyphens to underscores,
4. collapses whitespace into underscore-separated tokens.

For example, `Public-Facing` and ` public facing ` both normalize to `public_facing`.

Unknown-like values for context normalization are:

- empty text,
- `unknown`,
- `no_assertion`,
- `no_value`,
- `no-value`,
- `redacted`.

The evidence-finding layer currently uses a narrower missing-text check: absent or empty text, `unknown`, and `no assertion`. Context review and canonical decision context use the broader normalization above.

### Value states

| State | Meaning |
|---|---|
| `declared` | The supplied value maps to a supported canonical category |
| `missing` | The value is absent or unknown-like, or a required numeric value is zero |
| `defaulted` | QSTriage supplied a conservative import default rather than business context |
| `unmapped` | A non-empty term was supplied but is not in the current bounded mapping |

`missing`, `defaulted`, and `unmapped` values require verification.

### Data sensitivity

The canonical categories are:

| Canonical value | Current recognized terms |
|---|---|
| `sensitive` | `customer_pii`, `pii_data`, `pii`, `identity_tokens`, `payment_metadata`, `payment_data`, `gdpr_scope`, `cardholder`, `cardholder_data`, `patient`, `patient_records`, `medical`, `medical_records`, `health`, `health_data` |
| `operational` | `telemetry`, `internal`, `operational`, `logs`, `metrics` |
| `unknown` | Unknown-like or unmapped values |

QSTriage does not infer sensitivity from arbitrary enterprise labels. An unrecognized term remains `unknown` with state `unmapped`.

### Exposure

The canonical categories are:

| Canonical value | Current recognized terms |
|---|---|
| `public` | `public_internet`, `internet`, `public`, `public_facing`, `internet_facing`, `external`, `external_facing`, `dmz`, `perimeter`, `edge` |
| `partner` | `partner_network`, `partner`, `partner_facing`, `third_party`, `vendor`, `supplier` |
| `internal` | `internal`, `internal_only`, `private_network`, `corp`, `corporate`, `lan` |
| `restricted` | `restricted_network`, `restricted`, `offline`, `air_gapped`, `segmented` |
| `isolated` | `isolated` |
| `unknown` | Unknown-like or unmapped values |

Unmapped exposure terms are not guessed to be public, internal, or restricted.

### Numeric and risk context

For every asset:

- `retention_years == 0` is treated as missing context,
- non-zero `retention_years` is treated as declared,
- `criticality`, `local_blast_radius`, and `migration_effort` are treated as declared for native inventories.

For CBOM-imported assets, the importer defaults `criticality`, `local_blast_radius`, and `migration_effort` to `medium`. Those values are marked `defaulted`, not declared.

An asset has complete normalized business context only when data sensitivity, exposure, retention, criticality, local blast radius, and migration effort do not require verification.

## Decision context review

`review_decision_context` returns:

- an inventory status of `complete` or `incomplete`,
- one review per asset,
- inventory-level issues,
- issue and incomplete-asset counts.

Current asset-level checks report:

- unknown or unmapped `data_class`,
- `retention_years` equal to zero,
- unknown or unmapped `exposure`,
- CBOM-defaulted `criticality`,
- CBOM-defaulted `local_blast_radius`,
- CBOM-defaulted `migration_effort`.

An asset with any current issue is `incomplete`. The recommended action is to add business context before treating its score as decision-grade.

When no QSTriage business or security dependencies are declared, the inventory review also reports that graph-amplified blast-radius reasoning may be limited.

Context review is a completeness check. It does not validate the truth of a declared value.

## Evidence review

The current evidence review version is `0.1`.

An `EvidenceReview` contains:

- `asset_id`,
- `evidence_score`,
- `confidence_cap`,
- `decision_grade`,
- `human_review_required`,
- typed `findings`,
- `blocking_finding_codes`,
- deduplicated `recommended_next_actions`.

### Finding model

Each finding can contain:

- a stable finding code,
- category and severity,
- message and affected asset or field path,
- evidence state and provenance,
- decision effects,
- relationship completeness,
- a structured human action.

Current categories are:

- `business_context`,
- `cryptographic_context`,
- `dependency_context`,
- `supply_chain_context`,
- `integrity_context`.

Current severities are `info`, `low`, `medium`, `high`, and `critical`.

Current effects are:

- `confidence_degraded`,
- `confidence_capped`,
- `decision_grade_blocked`,
- `human_review_required`.

Current provenance values are:

- `supplier_authoritative`,
- `third_party_asserted`,
- `tool_generated`,
- `qstriage_default`,
- `user_declared`.

Relationship completeness can be `unknown`, `none`, `partial`, or `known`.

### Evidence score

The evidence score starts at `1.0`. For each finding other than an informational finding with no effects, QSTriage subtracts the larger of the severity penalty and evidence-state penalty.

Severity penalties:

| Severity | Penalty |
|---|---:|
| `info` | 0.00 |
| `low` | 0.05 |
| `medium` | 0.12 |
| `high` | 0.25 |
| `critical` | 0.40 |

Evidence-state penalties:

| State | Penalty |
|---|---:|
| `verified` | 0.00 |
| `declared` | 0.02 |
| `defaulted` | 0.10 |
| `no_assertion` | 0.18 |
| `no_value` | 0.03 |
| `redacted` | 0.22 |
| `unknown` | 0.15 |

The final score is floored at zero and rounded to four decimal places. Penalties are additive, so multiple independent gaps can reduce the score materially.

### Confidence cap

The confidence cap starts at `1.0` and becomes the minimum applicable cap across each non-informational finding's severity, state, and effects.

Severity caps:

| Severity | Cap |
|---|---:|
| `info` | 1.00 |
| `low` | 0.90 |
| `medium` | 0.80 |
| `high` | 0.65 |
| `critical` | 0.40 |

Evidence-state caps:

| State | Cap |
|---|---:|
| `verified` | 1.00 |
| `declared` | 0.95 |
| `defaulted` | 0.75 |
| `no_assertion` | 0.65 |
| `no_value` | 0.90 |
| `redacted` | 0.60 |
| `unknown` | 0.70 |

Effect caps:

| Effect | Cap |
|---|---:|
| `confidence_degraded` | 0.85 |
| `confidence_capped` | 0.70 |
| `decision_grade_blocked` | 0.50 |
| `human_review_required` | 0.90 |

The final cap is rounded to four decimal places.

### Decision-grade rule

The default decision-grade threshold is `0.75`.

A review is `not_decision_grade` when either:

- at least one finding has `decision_grade_blocked`, or
- the confidence cap is below `0.75`.

Otherwise it is `decision_grade`.

Human review is required when the review is not decision-grade or any finding requires human review or supplies a human action.

### Current generated findings

The current asset evidence review can generate findings for:

- data class missing under the evidence layer's missing-text check,
- CBOM-defaulted retention equal to zero,
- exposure missing under the evidence layer's missing-text check,
- unknown or unsupported algorithm,
- missing key size for RSA, AES, DH, ECDH, or ECDSA identifiers,
- CBOM-defaulted criticality, local blast radius, and migration effort,
- unknown relationship completeness for CBOM imports,
- declared QSTriage dependency context.

For every asset treated as CBOM-imported, the current evidence review emits `unknown_dependency_completeness`. It does not infer relationship completeness from the scanner artifact or convert scanner dependencies into QSTriage blast-radius dependencies.

For native inventory assets participating in at least one declared QSTriage dependency, the review emits an informational known-context finding. That finding does not reduce evidence score or confidence.

## Interaction with canonical decisions

Evidence review can:

- cap decision confidence,
- block decision-grade status,
- require verification,
- require human review.

It does not directly approve an algorithm, authorize migration, or replace the canonical decision reconciliation described in [Decision Model](decision-model.md).

## Public boundaries

QSTriage does not claim that:

- a declared value is verified,
- a high evidence score proves security,
- normalized context is complete beyond the current rules,
- missing evidence proves the absence of risk,
- CBOM-derived business defaults are decision-grade,
- relationship completeness can be inferred from scanner output alone.

The review output is a bounded, deterministic decision aid. A human reviewer remains responsible for validating business context, source authority, and unresolved evidence gaps.
