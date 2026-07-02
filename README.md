# QSTriage

**QSTriage — Explainable PQC Migration Decision Engine**

QSTriage is a local-first command line tool for post-quantum cryptography migration planning.

It turns cryptographic inventories into:

- dependency-aware risk scores
- graph-amplified blast-radius analysis
- hybrid PQC migration impact warnings
- narrative Markdown migration reports
- JSON and CSV exports
- CycloneDX CBOM JSON import lite
- config-driven default output paths

## MVP scope

The first version reads a YAML inventory, builds a directed dependency graph, scores cryptographic assets, simulates basic hybrid PQC migration impact, generates Markdown reports, and exports structured JSON/CSV results.

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

Import a CycloneDX CBOM JSON file as a partial QSTriage inventory:

```bash
qstriage import cbom tests/fixtures/sample_cbom.json --output reports/imported_inventory.yaml
```

CBOM imports are intentionally conservative. Imported cryptographic assets become QSTriage assets, but CBOM dependency relationships are not automatically treated as QSTriage business/security blast-radius dependencies.

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
- PQC impact simulation warnings
- text dependency graph views
- method notes

## Project status

QSTriage is currently an MVP prototype for local analysis and planning. It is not a production migration orchestrator.
