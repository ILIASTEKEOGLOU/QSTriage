# QSTriage Usage Guide

QSTriage is a local-first command line tool for explainable post-quantum cryptography migration planning.

It follows a conservative workflow:

```text
inventory -> dependency graph -> standards-backed algorithm classification -> explainable scoring -> impact simulation -> narrative report -> structured exports
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

## Score an inventory

```bash
qstriage score examples/sample_inventory.yaml
```

This prints a prioritized migration backlog with:

```text
rank -> asset -> score -> band -> recommended action
```

The score is explainable and combines standards-aware cryptographic risk, shelf-life risk, exposure, criticality, graph-amplified blast radius, deadline pressure, and migration effort.

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
- priority backlog
- asset-level findings
- standards-backed algorithm classification evidence
- registry source IDs for classification rationale
- PQC impact simulation warnings
- dependency graph views
- method notes

Reports are written locally. The default `reports/` directory is ignored by Git.

## Export score results

Export scores as JSON:

```bash
qstriage export scores examples/sample_inventory.yaml --format json --output reports/scores.json
```

Export scores as CSV:

```bash
qstriage export scores examples/sample_inventory.yaml --format csv --output reports/scores.csv
```

The JSON export preserves nested score breakdowns and explanations. The CSV export flattens score fields for spreadsheet-style review.

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
