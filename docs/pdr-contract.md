# QSTriage PDR 0.2 Contract

A PQC Decision Record (PDR) is structured decision state produced from one captured QSTriage inventory or CycloneDX CBOM input.

This document describes PDR contract version `0.2` as implemented by `qstriage/pdr.py`. Code and tests remain authoritative for executable behavior.

## Contract version and authority

- PDR contract version: `0.2`
- Engine name: `QSTriage`
- Engine version: the installed QSTriage package version
- Default policy pack: `nist-pqc-basic` version `0.2`

PDR versioning is separate from the QSTriage package version. Removing, renaming, or changing the documented meaning of public PDR fields requires a PDR contract-version change. Additive fields can be introduced in a compatible minor evolution when their meaning does not alter existing fields.

## Top-level document

A `PDRDocument` contains:

| Field | Contract |
|---|---|
| `pdr_version` | PDR contract version, currently `0.2` |
| `run_id` | Deterministic identifier derived from source hash, policy-pack hash, and PDR version |
| `input_snapshot` | Provenance for the captured source |
| `policy_context` | Document-level policy-pack provenance |
| `records` | One decision record per inventory asset |
| `document_hash` | Integrity hash over the document with this field neutralized |

Records preserve native inventory asset order. `sequence_number` begins at 1 and follows that order.

## Input snapshot

`input_snapshot` contains:

| Field | Meaning |
|---|---|
| `source_type` | `qstriage_inventory` or `cyclonedx_cbom` for supported file-backed generation |
| `source_version` | CBOM `specVersion` when supplied, an explicitly requested inventory source version, or null |
| `source_path` | For QSTriage-generated file-backed snapshots, the captured file basename; null for in-memory generation |
| `source_hash` | `sha256:`-prefixed hash of the exact captured bytes for file-backed generation, or of canonical validated inventory data for in-memory generation |

### File-backed capture

For file-backed generation, QSTriage:

1. reads the bounded source file once,
2. hashes that exact byte sequence,
3. decodes the same bytes as UTF-8,
4. parses the same text,
5. records the resulting hash and source metadata.

This binds the PDR to the bytes actually parsed. A later file replacement, mutation, or symlink retarget cannot make the record refer to different source bytes.

Inventory and CBOM file limits are documented in [Input Contracts](input-contracts.md).

### In-memory generation

When no file-backed snapshot is supplied, QSTriage hashes the canonical JSON representation of the validated inventory object. In that mode, `source_path` is null. This is deterministic but is not a hash of an original file byte stream.

## Policy context

The document-level `policy_context` contains:

- `policy_pack_id`,
- `policy_pack_version`,
- deterministic `policy_pack_hash`,
- `standards_applied`.

It records policy provenance only. Applied rule IDs and policy findings are asset-specific and appear in each record's `policy_evaluation`.

A requested policy-pack version mismatch is rejected rather than silently substituted.

## Decision record

Each `PQCDecisionRecord` contains:

| Section | Purpose |
|---|---|
| Identity | `pdr_version`, `record_id`, `run_id`, `lineage_id`, and `sequence_number` |
| `engine` | QSTriage name and version |
| `input_snapshot` | Copy of the document input provenance |
| `policy_context` | Copy of policy-pack provenance |
| `policy_evaluation` | Applied rules, standards, thresholds, findings, and blocking state for this asset |
| `observed_state` | Asset identity plus classified algorithm family, primitive, quantum status, and standards status |
| `evidence_quality` | Numeric quality score, missing evidence, and limitations |
| `evidence_review` | Structured findings, evidence score, confidence cap, decision-grade status, and recommended human actions |
| `decision_confidence` | Final bounded confidence value and rationale |
| `mission_context` | Data class, retention, exposure, and impact context |
| `tradeoffs` | Deterministic migration, cryptographic, operational, or evidence-gap statements |
| `target_state_suggestion` | Bounded candidate target states with standards provenance and review flags |
| `decision` | Canonical decision projected from the shared assessment boundary |
| `assumptions_made` | Explicit evidence assumptions and blocking conditions |
| `record_integrity` | Optional prior-record reference and deterministic record hash |

`record_id` is `pdr:` followed by the QSTriage asset ID. `lineage_id` is derived from the source hash. All records in the same document share the document `run_id`, `input_snapshot`, and `policy_context`.

## Canonical decision projection

The record `decision` object contains:

- `risk_attention_score`,
- `risk_attention_band`,
- `execution_state`,
- `action_type`,
- `verification_priority`,
- `verification_requirements`,
- `confidence_score`,
- `human_review_required`,
- `reason_codes`.

Its semantics are defined in [Decision Model](decision-model.md). Legacy score fields such as `recommended_action`, `priority_score`, and `priority_band` are not substituted into this object.

## Target-state suggestions

Target-state suggestions are bounded planning options derived from current classification and context. Current categories include:

- retaining a standardized PQC family,
- hybrid key establishment using ML-KEM-768 where key-establishment context is present,
- migration toward an ML-DSA profile where signature context is present,
- key-strength or primitive review for symmetric/hash primitives,
- manual target selection where use context is insufficient,
- manual cryptographic review for unknown algorithms.

Suggestions do not approve deployment. Each suggestion records standards provenance, operational risk, and whether human review is required.

## Deterministic identifiers and hashes

QSTriage uses canonical JSON with sorted keys, compact separators, and UTF-8 encoding for object hashes.

- `run_id` is derived from `source_hash`, `policy_pack_hash`, and `pdr_version`.
- `lineage_id` is derived from the source hash.
- `record_hash` is calculated with its own `record_hash` field neutralized while preserving `previous_record_hash`.
- `document_hash` is calculated with its own `document_hash` field neutralized.

An optional `previous_record_hash` can link a record to an externally supplied prior record for the same asset. It is not an implicit chain between adjacent records in one document.

For the same QSTriage version, captured input snapshot, policy pack, and generated content, PDR output and hashes are deterministic. Exact hashes are not promised to remain unchanged across QSTriage or PDR contract versions because documented content or serialization inputs can evolve.

## Evidence and confidence behavior

A PDR can be generated for incomplete evidence when at least one supported asset exists, but incompleteness remains explicit through:

- missing-evidence lists,
- evidence findings,
- confidence caps,
- decision-grade status,
- verification requirements,
- gated or verification-first execution,
- human-review requirements,
- assumptions.

CBOM-derived assets are treated as partial cryptographic evidence until business and dependency context is added. Successful PDR generation does not mean that every record is decision-grade.

A CBOM with no supported explicit cryptographic-asset evidence produces no PDR.

## Public compatibility boundary

PDR 0.2 documents QSTriage decision state. It does not claim:

- universal CBOM compatibility,
- complete cryptographic discovery,
- security approval of a parsed algorithm,
- correctness of undeclared business context,
- automatic authorization to change production systems,
- stable hashes across different engine or contract versions.
