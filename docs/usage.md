# QSTriage Usage Guide

QSTriage is a local-first Cryptographic Policy & Justification Engine for explainable post-quantum cryptography migration planning and governance.

It follows a conservative workflow:

```text
inventory/CBOM -> standards-backed algorithm classification -> evidence quality review -> explainable scoring -> PDR -> impact simulation -> narrative report -> structured exports
```

QSTriage is designed for judgment before automation. It does not modify production systems.

## Install for local development

From the repository root:

```bash
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

## Validate an inventory

```bash
qstriage validate examples/sample_inventory.yaml
```

Expected output includes the number of assets, dependencies, and scenarios.

QSTriage prints friendly validation errors for malformed YAML and invalid inventory files. For example, missing asset fields are shown as explicit field paths such as:

```text
Missing required field `assets[0].environment`.
```

## Import a CycloneDX CBOM inventory

```bash
qstriage import cbom tests/fixtures/sample_cbom.json --output reports/imported_inventory.yaml
```

This creates a valid QSTriage YAML inventory from CycloneDX-style CBOM JSON.

Import behavior is intentionally conservative:

- CBOM cryptographic assets are imported as QSTriage assets.
- CBOM dependency relationships are not imported as QSTriage blast-radius dependencies.
- Imported assets include review-required notes because scanners cannot know business context such as data shelf life, criticality, exposure, and migration effort.
- Generated inventories use `dependencies: []` unless QSTriage-specific business/security dependencies are added later.

### CBOM algorithm normalization

QSTriage normalizes split CBOM crypto metadata into registry-ready algorithm identifiers when possible.

Examples:

- `algorithmFamily=ML-KEM` with `parameterSetIdentifier=768` becomes `ML-KEM-768`.
- `algorithmFamily=RSA` with `keySize=2048` becomes `RSA-2048`.
- `algorithmFamily=AES` with `keyLength=256` becomes `AES-256`.

This improves the path from CBOM import to standards-backed registry classification, scoring explanations, and report evidence.

After import, validate the generated inventory:

```bash
qstriage validate reports/imported_inventory.yaml
```

Then generate a report:

```bash
qstriage report reports/imported_inventory.yaml --output reports/imported_report.md
```

Reports warn when graph-amplified blast radius is limited because no QSTriage dependencies were declared.

## Generate PQC Decision Records

Review evidence quality and decision-grade readiness:

```bash
qstriage review evidence examples/sample_inventory.yaml
qstriage review evidence tests/fixtures/sample_cbom.json --input-format cbom
```

Generate a PDR from a QSTriage YAML inventory:

```bash
qstriage pdr generate examples/sample_inventory.yaml --output reports/pdr.json
```

Generate a PDR directly from CycloneDX CBOM JSON crypto evidence:

```bash
qstriage pdr generate tests/fixtures/sample_cbom.json --input-format cbom --output reports/cbom_pdr.json
```

The PDR JSON document is the documented decision artifact. It includes input snapshot metadata, policy context, asset-level policy evaluation, observed crypto state, evidence quality, structured evidence review, decision-grade status, confidence caps, decision confidence, mission context, trade-offs, target-state suggestions, assumptions, human-review status, and record integrity hashes.

### PDR output contract

QSTriage treats PDR JSON as a documented, evolving contract rather than an internal debug dump.

PDR `0.2` projects the canonical decision contract into every asset record. The `decision` object contains:

- `risk_attention_score` and `risk_attention_band` as planning-attention signals
- `execution_state` and `action_type` as the reconciled operational decision
- `verification_priority` and typed `verification_requirements`
- `confidence_score` and `human_review_required`
- deterministic `reason_codes`

The public semantic contract also includes:

- the top-level PDR document
- `policy_context` as document-level policy pack provenance
- `records` as asset-level decision records
- per-record `policy_evaluation` with applied rules, findings, standards, thresholds, and review status
- observed cryptographic state
- evidence quality and evidence review
- decision confidence and decision-grade status
- mission context, trade-offs, assumptions, and human-review state
- `document_hash` and per-record `record_integrity`

Minor versions may add fields. Removing, renaming, or changing the meaning of documented PDR fields requires a PDR contract-version change.

Exact hash values are not a cross-version compatibility promise. They are deterministic for the same QSTriage version, input snapshot, policy pack, and generated PDR content.

## Review decision context

Run `qstriage review context examples/sample_inventory.yaml`.

This checks whether the inventory has enough business context for decision-grade scoring.

The review flags missing or defaulted context such as unknown data class, zero retention years, unknown exposure, CBOM import defaults for criticality, local blast radius, migration effort, and inventories with no QSTriage business/security dependencies.

QSTriage does not change the score automatically. It explains whether the score should be treated as decision-grade or whether business context should be added first.

## Score an inventory

```bash
qstriage score examples/sample_inventory.yaml
```

This prints a prioritized migration backlog with:

```text
rank -> asset -> score -> band -> recommended action
```

The score is explainable and combines standards-aware cryptographic risk, shelf-life risk, exposure, criticality, graph-amplified blast radius, deadline pressure, and migration effort.

Scores are deterministic planning heuristics. They are not empirical probability estimates, actuarial risk measurements, or compliance certifications. See [Scoring Rationale](scoring-rationale.md).

## Algorithm classification

QSTriage includes a standards-backed algorithm registry used by scoring and reports.

The registry classifies common classical, PQC, symmetric, and hash algorithm strings, including:

- RSA, DH, ECDH, ECDHE, ECDSA, X25519, Ed25519
- ML-KEM, ML-DSA, SLH-DSA
- AES
- SHA-1, SHA-2, SHA-3, SHAKE

Unknown algorithm strings are not guessed as safe. They are classified as requiring manual review.

Markdown reports include per-asset algorithm evidence:

```text
Algorithm classification:
- Input algorithm: `RSA-2048`
- Algorithm family: RSA
- Primitive: public_key_encryption_or_signature
- Quantum status: quantum_vulnerable
- Standard status: classical_public_key
- Registry action: migrate_to_hybrid_or_pqc_path
- Registry sources: NIST-IR-8547-IPD
```

## Render a dependency graph

```bash
qstriage graph examples/sample_inventory.yaml public-api-gateway
```

This prints a readable text view of the dependency graph from the selected root asset.

## Generate a Markdown report

```bash
qstriage report examples/sample_inventory.yaml --output reports/qstriage_report.md
```

The generated report includes:

- executive summary
- canonical decision backlog with risk attention, execution, action, verification, and review state
- asset-level findings with decision confidence, typed verification requirements, and deterministic reason codes
- standards-backed algorithm classification evidence
- registry source IDs for classification rationale
- decision context review
- PQC impact simulation warnings
- dependency graph views
- method notes

The report, `qstriage score`, and structured score exports use the shared canonical assessment boundary.

Reports are written locally. Generated report artifacts should not be committed unless intentionally promoted as examples.

## Export score results

Export scores as JSON:

```bash
qstriage export scores examples/sample_inventory.yaml --format json --output reports/scores.json
```

Export scores as CSV:

```bash
qstriage export scores examples/sample_inventory.yaml --format csv --output reports/scores.csv
```

Score export contract `0.2` retains planning-score fields while projecting canonical `execution_state`, `action_type`, verification state, decision confidence, human-review state, and reason codes. The compatibility field `recommended_action` now aliases canonical `action_type`; score-derived action text is removed from explanations. JSON preserves nested score breakdowns, while CSV flattens score fields for spreadsheet-style review.

## Export simulation results

Export simulations as JSON:

```bash
qstriage export simulations examples/sample_inventory.yaml --format json --output reports/simulations.json
```

Export simulations as CSV:

```bash
qstriage export simulations examples/sample_inventory.yaml --format csv --output reports/simulations.csv
```

Simulation exports include estimated handshake size, MTU ratio, fragmentation risk, middlebox risk, compatibility risk, crypto-bearing dependency count, and warnings.

## Use a configuration file

QSTriage includes an example config:

```bash
examples/qstriage.yaml
```

Example:

```yaml
outputs:
  report_path: reports/qstriage_report.md
  scores_path: reports/scores.json
  simulations_path: reports/simulations.json

exports:
  default_format: json
```

Use it with report generation:

```bash
qstriage report examples/sample_inventory.yaml --config examples/qstriage.yaml
```

Use it with exports:

```bash
qstriage export scores examples/sample_inventory.yaml --config examples/qstriage.yaml
qstriage export simulations examples/sample_inventory.yaml --config examples/qstriage.yaml
```

Explicit CLI flags override config defaults. For example:

```bash
qstriage export scores examples/sample_inventory.yaml --config examples/qstriage.yaml --format csv --output reports/custom_scores.csv
```

## Safety boundary

QSTriage is not a production migration agent.

It does not:

- rotate certificates
- modify TLS settings
- change live cryptographic configuration
- deploy PQC algorithms
- perform rollout
- perform rollback

QSTriage helps teams reason about what to prioritize, why it matters, and what should be simulated before any real migration work.

## Policy pack inspection

List built-in policy packs:

- `qstriage policy list`

Show the built-in NIST PQC baseline policy pack:

- `qstriage policy show nist-pqc-basic`

The `policy_pack_hash` field is deterministic and is used in PDR policy context.

Current PDR records also include asset-level `policy_evaluation` results. These results record the applied policy rule IDs, policy findings, standards applied, and thresholds applied for each asset. `policy_context` remains document-level policy pack provenance.
