# QSTriage

[![CI](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/ci.yml)
[![Security](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/security.yml/badge.svg)](https://github.com/ILIASTEKEOGLOU/QSTriage/actions/workflows/security.yml)

**QSTriage — Cryptographic Policy & Justification Engine**

Cryptographic migration is not a scanner problem.

A scanner can tell you where RSA is. It cannot tell you which decision comes
next, which uncertainty blocks action, or how that decision can be defended
later.

QSTriage evaluates cryptographic inventories and supported CycloneDX CBOM
evidence and produces deterministic PQC Decision Records (PDR 0.2). Each record
preserves the evidence, policy context, confidence limits, and resulting action.
QSTriage runs locally and does not modify production systems.

## What QSTriage does

QSTriage:

- validates native YAML inventories and supported CycloneDX CBOM JSON,
- classifies cryptographic algorithms against a bounded standards registry,
- separates risk attention from evidence, confidence, and verification needs,
- reconciles those signals into one canonical decision per asset,
- generates PDR 0.2 decision records with deterministic integrity hashes,
- scores assets and models graph-amplified blast radius,
- estimates basic hybrid-PQC migration pressure,
- produces Markdown reports and JSON/CSV exports.

## Scope

QSTriage scores are deterministic prioritization indices. They rank assets for
review; they do not estimate compromise probability, the arrival date of a
cryptographically relevant quantum computer, or expected financial loss. See
[Scoring Rationale](docs/scoring-rationale.md).

QSTriage stops at the decision boundary. It can recommend, gate, and explain an
action, but it cannot execute that action. It does not modify production
systems, rotate certificates, deploy cryptographic changes, or perform
remediation.

## Quickstart

QSTriage requires Python 3.11 or later. The current CI and release baseline is
Python 3.11. Use `python3` instead of `python` where that is the installed
executable name.

From a fresh clone, create a virtual environment:

```bash
python -m venv .venv
```

Activate it with the command for your shell.

Windows Git Bash:

```bash
source .venv/Scripts/activate
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux or macOS:

```bash
source .venv/bin/activate
```

Install QSTriage and generate a PDR from the sample inventory:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m qstriage.cli version
python -m qstriage.cli policy list
python -m qstriage.cli pdr generate examples/sample_inventory.yaml --output reports/pdr.json
```

The final command writes `reports/pdr.json`. If that file already exists,
QSTriage refuses to replace it unless `--overwrite` is supplied.

The editable install also exposes the `qstriage` command. The module form above
avoids shell-specific entry-point resolution.

## Core workflow

```text
inventory/CBOM
  -> classification
  -> context and evidence review
  -> risk scoring and policy evaluation
  -> canonical decision
  -> PDR, impact simulation, report, and export
```

Common commands:

```bash
qstriage validate examples/sample_inventory.yaml
qstriage score examples/sample_inventory.yaml
qstriage review evidence examples/sample_inventory.yaml
qstriage report examples/sample_inventory.yaml --output reports/qstriage_report.md
```

See the [Usage Guide](docs/usage.md) for the complete CLI workflow.

## OpenAI Build Week 2026 - Evidence Closure

Evidence Closure is unreleased work developed after QSTriage `v1.2.0`. It is
not part of the `v1.2.0` tag or its release artifacts.

Before Build Week, QSTriage already provided CBOM import, cryptographic classification, evidence review, deterministic scoring and policy decisions, PDR generation, graph analysis, simulation, reporting, and exports. Build Week adds structured evidence gaps, provenance-aware source-bound enrichment, deterministic validate/apply/compare commands, read-only MCP tools, and the `qstriage-evidence-closure` Codex skill.

The one-command judge demo is:

```bash
python scripts/build_week_demo.py
```

Five-minute setup from a fresh clone:

```bash
python -m venv .venv
```

Windows Git Bash:

```bash
source .venv/Scripts/activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install and run:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[mcp]"
python scripts/build_week_demo.py
```

Manual workflow:

```bash
python -m qstriage.cli import cbom examples/build-week/sample_cbom.json --output imported.yaml
python -m qstriage.cli closure inspect imported.yaml --format json --output gaps.json
python -m qstriage.cli closure validate imported.yaml examples/build-week/approved_enrichment.patch.yaml
python -m qstriage.cli closure apply imported.yaml examples/build-week/approved_enrichment.patch.yaml --output enriched.yaml
python -m qstriage.cli review evidence imported.yaml
python -m qstriage.cli review evidence enriched.yaml
python -m qstriage.cli closure compare imported.yaml enriched.yaml --format json --output comparison.json
```

The optional MCP integration is installed by `python -m pip install -e ".[mcp]"`. The model may ask questions and draft a patch, but it cannot establish truth, approve evidence, apply changes, alter scores, or authorize migration. The human applies an approved patch, and QSTriage remains the deterministic decision authority. In the demo, evidence becomes decision-grade while the migration action remains gated; this is not production authorization.

See [Evidence Closure](docs/evidence-closure.md), the [demo script](docs/build-week-demo-script.md), the [submission draft](docs/build-week-submission.md), and the [Build Week traceability ledger](BUILD_WEEK.md).

## Enforced workload limits

QSTriage refuses inputs that exceed its supported limits. It does not truncate
them or continue with a partial decision result.

| Input or workload | Enforced limit |
|---|---:|
| Inventory YAML | 10 MiB |
| CycloneDX CBOM JSON | 32 MiB |
| CBOM components | 10,000 |
| Configuration YAML | 1 MiB |
| Assets per inventory | 1 to 1,000 |
| Dependencies per inventory | 10,000 |
| Migration scenarios | 100 |
| Asset/scenario simulation results | 20,000 |

Additional limits cover field length, YAML structure, graph traversal,
rendered output, and critical-path enumeration. See
[Input Contracts](docs/input-contracts.md) for the complete enforced contract.

## Documentation

Reference documentation:

- [Usage Guide](docs/usage.md) — commands, workflows, examples, and configuration
- [Input Contracts](docs/input-contracts.md) — supported inputs, limits, and parsing boundaries
- [Standards and Classification](docs/standards-and-classification.md) — registry and normalization behavior
- [Scoring Rationale](docs/scoring-rationale.md) — prioritization index and interpretation limits
- [Simulation Rationale](docs/simulation-rationale.md) — model, warnings, assumptions, and non-claims
- [Evidence and Context](docs/evidence-and-context.md) — normalization, completeness, evidence, and confidence
- [Canonical Decision Model](docs/decision-model.md) — action gating, verification, and reason codes
- [PDR 0.2 Contract](docs/pdr-contract.md) — structure, provenance, determinism, and versioning
- [CBOM Compatibility](docs/cbom-compatibility.md) — tested artifact shapes and scanner boundaries
- [Security Policy](SECURITY.md) — reporting and enforced trust boundaries

- [Evidence Closure](docs/evidence-closure.md) - provenance-aware enrichment and judge workflow
- [Build Week Demo Script](docs/build-week-demo-script.md) - timed video actions and voiceover
- [Build Week Submission Draft](docs/build-week-submission.md) - Devpost-ready project fields

Code and tests remain authoritative for executable behavior.

## Trust model

Generated files are no-clobber by default, and terminal/Markdown output
neutralizes untrusted presentation characters. File-backed PDR generation
parses and hashes the same captured bytes.

The CI and security workflows use read-only repository permissions, immutable
action references, hashed dependency locks, vulnerability and static-analysis
checks, and full-history secret scanning.

The release-artifact workflow builds twice from clean source snapshots and
requires byte-for-byte reproducibility. It emits SHA-256 checksums and a
reproducible CycloneDX SBOM. GitHub-hosted attestations are created only for
eligible public-repository runs; private-repository runs retain the local
integrity evidence.

Verify a downloaded release bundle from its directory with:

```bash
sha256sum --check SHA256SUMS
```

For an eligible public run with GitHub attestations:

```bash
gh attestation verify qstriage-*.whl --repo ILIASTEKEOGLOU/QSTriage
gh attestation verify qstriage-*.tar.gz --repo ILIASTEKEOGLOU/QSTriage
```

Release tags must match the package version exactly, for example `v1.2.0` for
package version `1.2.0`.

## Development

For development work intended to match CI, use Python 3.11. Create and activate
the virtual environment as described in Quickstart, then install the development
dependencies:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The development extra includes the test dependency. CI installs the exact
hashed dependency resolution recorded in `requirements/py311.lock`.

## Project status

QSTriage is an early public release for local cryptographic analysis, PQC
migration planning, and PDR generation. It is not a production migration
orchestrator or a universal cryptography-discovery scanner.

## License

Copyright 2026 Ilias Tekeoglou.

QSTriage is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
