# QSTriage Canonical Decision Model

QSTriage reconciles classification, risk attention, evidence, policy, confidence, and normalized context into one deterministic `CanonicalDecision` per asset.

This document describes the public decision contract implemented by `qstriage/decision.py` and projected into CLI, report, export, and PDR outputs. Code and tests remain authoritative for executable behavior.

## Inputs to reconciliation

The canonical decision uses:

- standards-backed algorithm classification,
- the deterministic risk-attention score and band,
- structured evidence review,
- policy evaluation and blocking rule IDs,
- decision confidence,
- migration effort,
- normalized business, dependency, and operational context.

The score-derived legacy recommendation is intentionally not used to choose the canonical action. Classification selects the action family; evidence, policy, confidence, and context control whether that action is justified, gated, or verification-first.

## Canonical decision fields

| Field | Meaning |
|---|---|
| `risk_attention_score` | Existing numeric planning score passed through unchanged |
| `risk_attention_band` | Existing planning band passed through unchanged |
| `execution_state` | Whether the proposed action is justified, gated, or requires identity verification first |
| `action_type` | Deterministic action family selected from classification and migration effort |
| `verification_priority` | `none`, `low`, `medium`, or `high` |
| `verification_requirements` | Ordered list of evidence or context that must be resolved |
| `decision_confidence` / PDR `confidence_score` | Bounded confidence value from 0.0 to 1.0 |
| `human_review_required` | Whether the current decision requires a human reviewer |
| `reason_codes` | Deterministic machine-readable reasons for the decision |

Risk attention is not execution authorization. A high score can coexist with a justified planning action, and a low or medium score can coexist with gated or verification-first handling.

## Action selection

| Classification status | Additional condition | Canonical action |
|---|---|---|
| `unknown` | Any | `manual_crypto_verification` |
| `classical_public_key` | Migration effort `high` or `critical` | `simulate_before_migration` |
| `classical_public_key` | Other migration effort | `migration_planning` |
| `standardized_pqc` | Any | `retain_monitor` |
| `standardized_symmetric` | Any | `key_strength_review` |
| `standardized_hash` | Any | `primitive_review` |
| Other unmapped status | Any | `manual_crypto_verification` |

The action is a review/planning category. It is not an instruction to deploy, replace, or approve production cryptography automatically.

## Execution states

### `verification_first`

Used when the algorithm classification is unknown. Cryptographic identity must be established before a known action can be justified.

### `gated`

Used for a recognized classification when any of these conditions applies:

- evidence review is not decision-grade,
- one or more policy findings block decision-grade status,
- decision confidence is below the default 0.75 threshold.

A gated action remains visible so reviewers can see the likely action family, but it is not represented as fully justified.

### `justified`

Used only when the classification is known, evidence is decision-grade, no blocking policy rule applies, and confidence meets the threshold.

`justified` means justified by the current QSTriage evidence and policy contract. It does not authorize an unsupervised production change.

## Verification requirements

Verification requirements are deduplicated and returned in a stable order:

1. `cryptographic_identity`
2. `cryptographic_parameters`
3. `business_context`
4. `dependency_context`
5. `operational_context`
6. `supply_chain_context`
7. `evidence_quality`
8. `policy_resolution`

Requirements can arise from:

- unknown classification,
- evidence findings with decision effects or human-review requirements,
- missing, defaulted, or unmapped normalized context,
- blocking policy rules,
- non-decision-grade evidence or low confidence when no more specific requirement exists.

Context mapping is conservative:

- data sensitivity, exposure, retention, and criticality map to `business_context`,
- local blast radius maps to `dependency_context`,
- migration effort maps to `operational_context`.

An unknown or defaulted decision-bearing value cannot silently reduce verification requirements.

## Verification priority

Priority is the maximum pressure produced by the current conditions.

- `verification_first` always creates high priority.
- Blocking evidence or policy creates medium or high priority depending on cryptographic uncertainty and known risk pressure.
- Confidence below the decision-grade threshold maps the risk-attention band to low, medium, or high verification priority.
- Missing business, dependency, operational, or supply-chain context creates low or medium priority depending on known cryptographic pressure.
- Explicit evidence-quality requirements also use the risk-attention band to set priority.

The priority describes urgency of verification, not severity of a proven vulnerability.

## Human review

Human review is required when any of these conditions is true:

- execution is not `justified`,
- one or more verification requirements exist,
- evidence review requires human action,
- policy evaluation requires human review,
- confidence is below 0.75,
- the risk-attention band is `critical` or `high` under the default threshold settings,
- the action is `key_strength_review`, `primitive_review`, or `manual_crypto_verification`.

## Reason codes

Reason codes are deterministic and grouped by namespace:

| Namespace | Examples |
|---|---|
| `classification:` | `classification:unknown`, `classification:quantum_vulnerable`, `classification:standardized_pqc` |
| `evidence:` | `evidence:missing_data_class`, or another relevant evidence finding code |
| `policy:` | `policy:<rule_id>` for each applied finding |
| `confidence:` | `confidence:below_decision_grade_threshold` |
| `verification:` | `verification:business_context`, `verification:policy_resolution` |
| `risk:` | `risk:high_attention`, `risk:critical_attention` |
| `migration:` | `migration:simulation_required` |

Reason-code order is stable: classification, relevant evidence codes, policy rule IDs, confidence, verification requirements, risk attention, then migration-specific reasons.

## Examples

### Unknown algorithm

An unrecognized algorithm produces:

- action `manual_crypto_verification`,
- execution `verification_first`,
- `cryptographic_identity` verification,
- high verification priority,
- required human review.

Unknown does not automatically mean high cryptographic risk. It means QSTriage lacks enough identity evidence to justify a known action.

### Recognized CBOM-derived SHA-256

A recognized hash imported from CBOM can produce:

- action `primitive_review`,
- execution `gated`,
- business, dependency, operational, supply-chain, or policy verification requirements,
- low decision confidence,
- required human review.

The gating is caused by incomplete evidence and context, not by failure to recognize SHA-256.

### Classical public-key asset with high migration effort

A recognized classical public-key asset with high or critical migration effort selects `simulate_before_migration`. Evidence and policy still determine whether that action is justified or gated.

## Contract boundaries

The canonical decision is an auditable planning and justification artifact. It is not:

- an automated production change authorization,
- a compliance certification,
- a probability of compromise,
- proof that input evidence is complete,
- a replacement for architecture, business-owner, or cryptographic review.
