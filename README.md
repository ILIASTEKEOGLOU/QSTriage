# QSTriage

[![CI](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/ci.yml)

**QSTriage — Cryptographic Policy & Justification Engine**

Cryptographic migration is not a scanner problem.

A scanner can tell you where RSA is. It cannot tell you which decision must be made first, which exception is acceptable, or why a risky asset was allowed to remain unchanged.

QSTriage turns cryptographic inventory and CycloneDX CBOM crypto evidence into auditable post-quantum cryptography decision records.

It is local-first, deterministic, and designed for judgment before automation.

QSTriage currently produces:

- PQC Decision Record (PDR) JSON documents
- asset-level policy evaluation with applied rule IDs, findings, standards, and thresholds
- dependency-aware risk scores
- documented deterministic scoring rationale
- graph-amplified blast-radius analysis
- hybrid PQC migration impact warnings
- narrative Markdown migration reports
- standards-backed algorithm classification evidence
- decision context review for business-context completeness
- evidence quality review with decision-grade status, confidence caps, blocking findings, and human-review actions
- JSON and CSV exports
- CycloneDX CBOM JSON import lite
- CBOM algorithm identifier normalization for registry-ready imports
- config-driven default output paths

## Current scope

QSTriage reads a YAML inventory or CycloneDX CBOM crypto evidence, builds a directed dependency graph when QSTriage dependencies are present, classifies cryptographic algorithms using a standards-backed registry, reviews evidence quality, scores cryptographic assets, generates PQC Decision Records, simulates basic hybrid PQC migration impact, generates Markdown reports, and exports structured JSON/CSV results.

Scoring is documented as a deterministic planning heuristic, not as an empirical probability or actuarial risk model. See [Scoring Rationale](docs/scoring-rationale.md).

No production systems are touched.
No certificates are rotated.
No automatic rollout is performed.

The first goal is judgment before automation.

## Quickstart

From a fresh clone, create and activate a virtual environment for your platform.

Windows Git Bash:

```bash
python -m venv .venv
source .venv/Scripts/activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then install QSTriage and run a small smoke path:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m qstriage.cli version
python -m qstriage.cli policy list
python -m qstriage.cli pdr generate examples/sample_inventory.yaml --output reports/pdr.json
```

Expected result: QSTriage prints its version, lists the built-in `nist-pqc-basic` policy pack, and writes a PDR JSON document under `reports/`.

The installed `qstriage` console command is also available after installation. The `python -m qstriage.cli` form is shown because it is explicit and works reliably in local virtual environments.

## Developer setup

Create and activate a virtual environment as above, then install the development extra and run tests:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
```

## CLI usage

Validate an inventory:

```bash
qstriage validate examples/sample_inventory.yaml
```

Print the canonical decision backlog:

```bash
qstriage score examples/sample_inventory.yaml
```

The CLI separates risk attention from execution state and shows the canonical action, verification priority, and human-review requirement for each asset.

Render a text dependency graph:

```bash
qstriage graph examples/sample_inventory.yaml public-api-gateway
```

Generate a Markdown report:

```bash
qstriage report examples/sample_inventory.yaml --output reports/sample_report.md
```

Markdown reports and structured score exports use the same canonical assessment boundary as the CLI and PDR.

Export canonical decision-aware score results:

```bash
qstriage export scores examples/sample_inventory.yaml --format json --output reports/scores.json
```

Review whether an inventory has enough business context for decision-grade scoring:

```bash
qstriage review context examples/sample_inventory.yaml
```

Review evidence quality and decision-grade readiness:

```bash
qstriage review evidence examples/sample_inventory.yaml
qstriage review evidence tests/fixtures/sample_cbom.json --input-format cbom
```

Import a CycloneDX CBOM JSON file as a partial QSTriage inventory:

```bash
qstriage import cbom tests/fixtures/sample_cbom.json --output reports/imported_inventory.yaml
```

CBOM imports are intentionally conservative. Imported cryptographic assets become QSTriage assets, but CBOM dependency relationships are not automatically treated as QSTriage business/security blast-radius dependencies.

During import, QSTriage normalizes split CBOM crypto metadata into stronger algorithm identifiers when possible. For example, `algorithmFamily=ML-KEM` with `parameterSetIdentifier=768` becomes `ML-KEM-768`, `algorithmFamily=RSA` with `keySize=2048` becomes `RSA-2048`, and `algorithmFamily=AES` with `keyLength=256` becomes `AES-256`.

## PQC Decision Records

Generate a PDR from a QSTriage inventory:

```bash
qstriage pdr generate examples/sample_inventory.yaml --output reports/pdr.json
```

Generate a PDR from CycloneDX CBOM crypto evidence:

```bash
qstriage pdr generate tests/fixtures/sample_cbom.json --input-format cbom --output reports/cbom_pdr.json
```

A PDR is structured decision state, not a narrative report. It includes input snapshot hash, policy context, asset-level policy evaluation, observed crypto state, evidence quality, structured evidence review, decision-grade status, confidence caps, decision confidence, mission context, trade-offs, target-state suggestions, assumptions, human-review status, and record integrity hashes.

### PDR output contract

QSTriage treats the PDR JSON document as a documented, evolving decision artifact.

PDR `0.2` projects the canonical decision contract into each record. The `decision` object separates `risk_attention_score` and `risk_attention_band` from `execution_state` and `action_type`, and records `verification_priority`, `verification_requirements`, `confidence_score`, `human_review_required`, and deterministic `reason_codes`.

The public semantic contract includes the top-level PDR document, `policy_context`, `records`, per-record `policy_evaluation`, observed crypto state, evidence review, canonical decision state, assumptions, and record/document integrity hashes.

Minor versions may add fields. Removing, renaming, or changing the meaning of documented PDR fields requires a PDR contract-version change.

Exact `document_hash` and `record_hash` values are not guaranteed to remain the same across QSTriage versions. They are deterministic for the same QSTriage version, input snapshot, policy pack, and generated PDR content.

## Standards-aware classification

QSTriage classifies algorithm strings before they are used in scoring and reports.

Examples:

- `RSA-2048` -> quantum-vulnerable public-key cryptography
- `ECDHE_RSA` -> quantum-vulnerable classical public-key composite
- `ML-KEM-768` -> standardized PQC key encapsulation
- `ML-DSA` -> standardized PQC digital signature
- `SLH-DSA` -> standardized stateless hash-based PQC digital signature
- `AES-256` -> symmetric encryption, separate from public-key PQC migration targets
- unknown algorithms -> manual review required

Classification output is shown in Markdown reports with registry action, rationale, and source IDs.


Use configuration defaults:

```bash
qstriage report examples/sample_inventory.yaml --config examples/qstriage.yaml
```

## Current workflow

```text
inventory/CBOM -> algorithm classification -> evidence review -> scoring -> policy evaluation -> PDR -> impact simulation -> report/export
```

## Example output

The sample inventory produces a priority backlog with assets such as:

- Public API Gateway
- Customer Database
- Payments API
- Authentication Service
- OT Gateway

The generated report includes:

- executive summary
- ranked migration backlog
- asset-level scoring explanations
- standards-backed algorithm classification evidence
- decision context review for business-context completeness
- registry source IDs for classification rationale
- PQC impact simulation warnings
- text dependency graph views
- method notes

## Project status

QSTriage is an early public release for local cryptographic analysis, PQC migration planning, and auditable decision records. It is not a production migration orchestrator.

## Policy packs and policy evaluation

QSTriage includes a built-in policy pack registry and live asset-level policy evaluation in PDR records.

Built-in pack: `nist-pqc-basic` policy pack version `0.2`.

Commands:

- `qstriage policy list`
- `qstriage policy show nist-pqc-basic`

Policy pack output includes a deterministic `policy_pack_hash` used by PDR policy context.

Current PDR records include `policy_evaluation` with applied rule IDs, policy findings, standards applied, and thresholds applied for each asset. `policy_context` remains document-level policy pack provenance: policy pack ID, version, hash, and standards context.

## License

Copyright 2026 Ilias Tekeoglou.

QSTriage is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
