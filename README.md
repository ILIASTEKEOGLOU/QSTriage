# QSTriage

**QSTriage — Explainable PQC Migration Decision Engine**

QSTriage is a local-first command line tool for post-quantum cryptography migration planning.

It turns cryptographic inventories into:

- dependency-aware risk scores
- graph-amplified blast-radius analysis
- hybrid PQC migration impact warnings
- narrative Markdown migration reports
- standards-backed algorithm classification evidence
- decision context review for business-context completeness
- JSON and CSV exports
- CycloneDX CBOM JSON import lite
- CBOM algorithm identifier normalization for registry-ready imports
- config-driven default output paths

## MVP scope

The current MVP reads a YAML inventory, builds a directed dependency graph, classifies cryptographic algorithms using a standards-backed registry, scores cryptographic assets, simulates basic hybrid PQC migration impact, generates Markdown reports, and exports structured JSON/CSV results.

No production systems are touched.
No certificates are rotated.
No automatic rollout is performed.

The first goal is judgment before automation.

## Install for local development

```bash
py -3.11 -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run tests

```bash
pytest
```

## CLI usage

Validate an inventory:

```bash
qstriage validate examples/sample_inventory.yaml
```

Print the migration priority backlog:

```bash
qstriage score examples/sample_inventory.yaml
```

Render a text dependency graph:

```bash
qstriage graph examples/sample_inventory.yaml public-api-gateway
```

Generate a Markdown report:

```bash
qstriage report examples/sample_inventory.yaml --output reports/sample_report.md
```

Export score results:

```bash
qstriage export scores examples/sample_inventory.yaml --format json --output reports/scores.json
```

Review whether an inventory has enough business context for decision-grade scoring:

```bash
qstriage review context examples/sample_inventory.yaml
```

Import a CycloneDX CBOM JSON file as a partial QSTriage inventory:

```bash
qstriage import cbom tests/fixtures/sample_cbom.json --output reports/imported_inventory.yaml
```

CBOM imports are intentionally conservative. Imported cryptographic assets become QSTriage assets, but CBOM dependency relationships are not automatically treated as QSTriage business/security blast-radius dependencies.

During import, QSTriage normalizes split CBOM crypto metadata into stronger algorithm identifiers when possible. For example, `algorithmFamily=ML-KEM` with `parameterSetIdentifier=768` becomes `ML-KEM-768`, `algorithmFamily=RSA` with `keySize=2048` becomes `RSA-2048`, and `algorithmFamily=AES` with `keyLength=256` becomes `AES-256`.

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

## MVP flow

```text
inventory -> dependency graph -> explainable scoring -> impact simulation -> narrative report -> structured exports
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

QSTriage is currently an MVP prototype for local analysis and planning. It is not a production migration orchestrator.
