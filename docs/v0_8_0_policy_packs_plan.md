# QSTriage v0.8.0 — Policy Packs Foundation

## Purpose

QSTriage v0.8.0 introduces Policy Packs as explicit, versioned, auditable decision assets.

v0.6.0 created PQC Decision Records.
v0.7.0 created the Evidence Quality Engine.
v0.8.0 creates the Policy Packs Foundation.

Core question:

With which policy was this cryptographic decision made?

## Design Principle 1 — Decisions Are Assets

Policy logic must not remain hidden as scattered hardcoded if/else branches.

A QSTriage policy must be represented as an explicit domain object that can be named, versioned, serialized, hashed, tested, displayed, cited in a PDR, and explained to a reviewer.

The policy pack is not only code. It is a decision asset.

## Design Principle 2 — Policy Rules as Specifications

A PolicyRule should behave like a domain specification.

A rule evaluates facts about a cryptographic asset, evidence review, classification, migration context, or PDR state and produces an explainable result.

The first implementation does not need a full custom rule language.

For v0.8.0:

- PolicyRule is declarative metadata.
- Python-side evaluators may exist.
- Each evaluator must map clearly to a rule_id.
- The PDR must preserve policy pack identity, version, hash, and standards context. Rule identity preservation is planned for later rule-level evaluation.

## Design Principle 3 — Standards-Backed Policy Context

The built-in policy pack must be standards-backed.

Initial references for nist-pqc-basic:

- NIST FIPS 203 — ML-KEM
- NIST FIPS 204 — ML-DSA
- NIST FIPS 205 — SLH-DSA
- NIST SP 800-131A Rev. 3 IPD — transition language for cryptographic algorithms and key lengths
- NIST IR 8547 IPD — PQC migration planning and inventory guidance
- NIST SP 800-227 — KEM guidance
- NIST CSWP 39 Update 1 — crypto agility considerations
- CISA quantum-readiness and PQC migration guidance
- CISA strategy for automated PQC discovery and inventory tools
- QSTriage local safety policy

The policy pack must not rewrite these standards. It must reference them and make QSTriage decisions traceable to them.

## Built-in Policy Pack

The first built-in policy pack is:

nist-pqc-basic

It should include:

- policy_pack_id
- version
- title
- description
- standards_references
- rules
- thresholds
- deterministic policy_pack_hash

## Candidate Rules

Initial rule identities:

- quantum_vulnerable_public_key_requires_pqc_migration_review
- standardized_pqc_can_be_retained_with_operational_review
- unknown_algorithm_requires_manual_crypto_review
- cbom_defaulted_context_blocks_decision_grade
- missing_business_context_requires_human_review
- unknown_dependency_completeness_blocks_decision_grade
- long_retention_sensitive_data_raises_priority
- public_or_partner_exposed_quantum_vulnerable_crypto_raises_priority
- ml_kem_usage_requires_key_establishment_context
- deprecated_or_disallowed_transition_status_requires_policy_finding

## Candidate Thresholds

Initial thresholds:

- minimum_decision_grade_confidence = 0.75
- cbom_default_confidence_cap = 0.50
- high_priority_human_review = true
- long_retention_years = 7
- harvest_now_decrypt_later_review_required = true

## Expected Domain Model

Likely module:

qstriage/policy.py

Likely models:

- PolicyPack
- PolicyRule
- PolicyReference
- PolicyThreshold
- PolicyRuleEffect
- PolicyApplicability
- PolicyEvaluationResult
- PolicyFinding

## CLI Scope

Add:

qstriage policy list
qstriage policy show nist-pqc-basic

The CLI should show:

- policy id
- version
- title
- standards references
- rules
- thresholds
- deterministic hash

## PDR Integration

The PDR policy_context must come from a real PolicyPack.

The PDR should include:

- policy_pack_id
- policy_pack_version
- policy_pack_hash
- standards_applied
- future rule-level policy identifiers, once rule evaluation is implemented

If the policy pack changes, the policy hash must change.

Same input plus same policy pack must produce deterministic policy context and deterministic PDR hashes.

## Scope Boundaries

Do not implement in v0.8.0:

- external policy YAML loading
- OPA/Rego integration
- policy marketplace
- Jira or ServiceNow integration
- UI
- PDR diff engine
- full CNSA/DORA/NIS2 compliance packs
- budget simulator

v0.8.0 is only:

Policy Pack domain model, built-in registry, policy CLI, and PDR policy context integration.

Non-goal for v0.8.0: rule-by-rule policy evaluation into PDR record-level findings.

## Commit Plan

1. Add policy pack domain model
2. Add built-in policy pack registry
3. Integrate policy packs into PDR context
4. Add policy CLI
5. Prepare v0.8.0 docs and version

## Definition of Done

v0.8.0 is complete when:

- python -m pytest passes
- qstriage version prints QSTriage 0.8.0
- qstriage policy list shows nist-pqc-basic
- qstriage policy show nist-pqc-basic shows rules, standards, thresholds, and hash
- qstriage pdr generate writes policy context from a real PolicyPack
- policy_pack_hash is deterministic
- PDR hashes remain deterministic
- README, usage docs, and CHANGELOG describe Policy Packs Foundation
