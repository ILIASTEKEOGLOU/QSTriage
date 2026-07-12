# QSTriage Usage Guide

QSTriage is a local-first Cryptographic Policy & Justification Engine. This
guide covers the supported CLI workflows; the linked contract documents define
the meaning and boundaries of their outputs.

## Install for local development

Use Python 3.11 to match the current CI baseline. From the repository root,
after activating a virtual environment:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The examples below use the installed `qstriage` command. The equivalent
`python -m qstriage.cli` form is also supported.

## Validate an inventory

```bash
qstriage validate examples/sample_inventory.yaml
```

Successful validation prints the number of assets, dependencies, and scenarios.
Malformed or unsupported input fails with a controlled error and field paths
where available.

The supported YAML shape, field semantics, and workload limits are defined in
[Input Contracts](input-contracts.md).

## Import a CycloneDX CBOM inventory

```bash
qstriage import cbom \
  tests/fixtures/sample_cbom.json \
  --output reports/imported_inventory.yaml
```

The importer creates a QSTriage YAML inventory from supported cryptographic
asset components. It does not convert scanner dependency relationships into
QSTriage business/security dependencies, and imported business context remains
conservative until reviewed.

Validate and use the generated inventory:

```bash
qstriage validate reports/imported_inventory.yaml
qstriage report \
  reports/imported_inventory.yaml \
  --output reports/imported_report.md
```

See [CBOM Compatibility](cbom-compatibility.md) for tested artifact shapes,
normalization behavior, scanner coverage boundaries, and explicit non-claims.

## Review context and evidence

Review business-context completeness:

```bash
qstriage review context examples/sample_inventory.yaml
```

Review evidence quality and decision-grade readiness:

```bash
qstriage review evidence examples/sample_inventory.yaml
qstriage review evidence \
  tests/fixtures/sample_cbom.json \
  --input-format cbom
```

These reviews do not verify that a declared value is true. Their states,
findings, confidence caps, and decision-grade rules are defined in
[Evidence and Context](evidence-and-context.md).

## Score an inventory

```bash
qstriage score examples/sample_inventory.yaml
```

The backlog shows risk attention, execution state, canonical action,
verification priority, and human-review status. The score ranks assets for
review; it does not authorize execution.

See [Scoring Rationale](scoring-rationale.md) for score semantics and
[Canonical Decision Model](decision-model.md) for reconciliation and gating.

## Generate PQC Decision Records

From a native QSTriage inventory:

```bash
qstriage pdr generate \
  examples/sample_inventory.yaml \
  --output reports/pdr.json
```

Directly from supported CycloneDX CBOM evidence:

```bash
qstriage pdr generate \
  tests/fixtures/sample_cbom.json \
  --input-format cbom \
  --output reports/cbom_pdr.json
```

PDR 0.2 records input provenance, policy context, evidence, confidence,
canonical decision state, assumptions, and integrity hashes. File-backed
generation parses and hashes one captured byte snapshot.

The serialized compatibility boundary is defined in
[PDR 0.2 Contract](pdr-contract.md).

## Inspect algorithm classification

Classification is included in reports, PDR records, and score explanations.
Unknown identifiers remain conservative rather than being guessed safe.

The supported registry, precedence, aliases, and CBOM normalization rules are
documented in
[Standards and Classification](standards-and-classification.md).

## Render a dependency graph

```bash
qstriage graph examples/sample_inventory.yaml public-api-gateway
```

This prints a bounded text view of the declared QSTriage dependency graph from
the selected asset.

## Generate a Markdown report

```bash
qstriage report \
  examples/sample_inventory.yaml \
  --output reports/qstriage_report.md
```

Reports include the canonical decision backlog, asset-level findings,
classification evidence, context review, simulation warnings, dependency views,
and method notes. Reports, score output, PDR records, and score exports consume
the same canonical assessment boundary.

Generated reports remain local artifacts unless intentionally promoted as
examples.

## Export score results

JSON:

```bash
qstriage export scores \
  examples/sample_inventory.yaml \
  --format json \
  --output reports/scores.json
```

CSV:

```bash
qstriage export scores \
  examples/sample_inventory.yaml \
  --format csv \
  --output reports/scores.csv
```

Score contract 0.2 retains planning-score fields and projects the canonical
decision fields. The compatibility field `recommended_action` aliases
`action_type`. JSON preserves nested score breakdowns; CSV flattens fields for
review.

## Export simulation results

JSON:

```bash
qstriage export simulations \
  examples/sample_inventory.yaml \
  --format json \
  --output reports/simulations.json
```

CSV:

```bash
qstriage export simulations \
  examples/sample_inventory.yaml \
  --format csv \
  --output reports/simulations.csv
```

The meaning and limits of the estimated handshake size, MTU ratio, risk labels,
dependency contribution, and warnings are defined in
[Simulation Rationale](simulation-rationale.md).

## Safe output behavior

Report, CBOM import, PDR, and JSON/CSV export commands share one file-output
boundary:

- existing files are not replaced by default,
- `--overwrite` must be explicit,
- symlink destinations and active input/config collisions are rejected,
- complete temporary output is published atomically,
- new files and directories receive restrictive permissions where supported.

Example intentional replacement:

```bash
qstriage report \
  examples/sample_inventory.yaml \
  --output reports/qstriage_report.md \
  --overwrite
```

Windows access control continues to depend on the containing directory ACL.
See the [Security Policy](../SECURITY.md) for the operational trust boundary.

## Use a configuration file

The example configuration is `examples/qstriage.yaml`:

```yaml
outputs:
  report_path: reports/qstriage_report.md
  scores_path: reports/scores.json
  simulations_path: reports/simulations.json

exports:
  default_format: json
```

Use it with report generation or exports:

```bash
qstriage report \
  examples/sample_inventory.yaml \
  --config examples/qstriage.yaml
qstriage export scores \
  examples/sample_inventory.yaml \
  --config examples/qstriage.yaml
qstriage export simulations \
  examples/sample_inventory.yaml \
  --config examples/qstriage.yaml
```

Explicit CLI flags override configuration defaults.

## Inspect policy packs

```bash
qstriage policy list
qstriage policy show nist-pqc-basic
```

Policy output includes the deterministic `policy_pack_hash` used by PDR policy
context. Asset-level PDR records include applied rules, findings, standards,
thresholds, and review status.

## Operational boundary

QSTriage does not rotate certificates, modify live cryptographic settings,
deploy algorithms, perform rollout, or perform rollback.

Input and workload limits are enforced before or during bounded analysis. A
limit violation is a controlled failure, not a partial decision result. Split
large or highly connected datasets into reviewable decision scopes instead of
removing the limits.

See [Input Contracts](input-contracts.md) for the exact limits and
[Security Policy](../SECURITY.md) for safe handling and reporting.
