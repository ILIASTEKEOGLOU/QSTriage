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
- classifies algorithm identifiers against a bounded, standards-backed grammar,
- keeps risk attention separate from evidence, confidence, and verification,
- reconciles classification, evidence, policy, and context into one canonical
  decision per asset,
- generates PDR 0.2 records with deterministic integrity hashes,
- models dependency-amplified blast radius and basic hybrid-PQC migration
  pressure,
- produces Markdown reports and JSON/CSV exports.

## Why now

[NIST's first three PQC standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
are final, and its transition plan removes quantum-vulnerable algorithms from
NIST standards by 2035.
[Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks)
sets 2030 and 2031 milestones for PQC key establishment and signatures in U.S.
Federal high-value assets and high-impact systems, excluding National Security
Systems.
[NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
sets a separate schedule for those systems. Long-lived data creates pressure
sooner because
[ciphertext collected today](https://csrc.nist.gov/pubs/ir/8547/ipd) may remain
valuable when decryption becomes possible. QSTriage addresses the work between
inventory and migration: what must be verified, what moves first, and why.

## Quickstart

QSTriage requires Python 3.11 or later.

```bash
python -m pip install qstriage
qstriage version
```

The [repository](https://github.com/ILIASTEKEOGLOU/QSTriage) contains the
bundled inventory and CBOM examples used below.

## Core workflow

```text
inventory/CBOM
  -> classification
  -> context and evidence review
  -> risk scoring and policy evaluation
  -> canonical decision
  -> PDR, impact simulation, report, and export
```

From a fresh clone:

```bash
python -m pip install -e .
qstriage validate examples/sample_inventory.yaml
qstriage review evidence examples/sample_inventory.yaml
qstriage score examples/sample_inventory.yaml
qstriage pdr generate examples/sample_inventory.yaml --output reports/pdr.json
```

Generated files are no-clobber by default. Use `--overwrite` only when replacing
an existing output is intentional. See the
[Usage Guide](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/usage.md)
for the complete CLI workflow.

## Example decision backlog

The bundled five-asset inventory produces:

| Rank | Asset | Risk attention | Canonical action |
|---:|---|---:|---|
| 1 | Public API Gateway | 96.00 / critical | `migration_planning` |
| 2 | Customer Database | 88.00 / critical | `simulate_before_migration` |
| 3 | Payments API | 81.00 / high | `simulate_before_migration` |
| 4 | Authentication Service | 78.00 / high | `migration_planning` |
| 5 | OT Gateway | 64.00 / medium | `simulate_before_migration` |

All five sample actions are `justified` under the supplied evidence and still
require human review. Risk attention ranks assets; it does not select the
canonical action or authorize a production change.

## Classifier integrity

QSTriage does not classify by substring or fuzzy similarity. `MARSALA` is not
RSA; `SHAKEWEIGHT` is not SHAKE. A positive classification requires the
complete normalized identifier to match an explicit grammar.

Unknown identifiers stay unknown and block decision-grade treatment; they are
never quietly treated as safe. A recognized PQC family with missing or
unsupported parameters receives neither quantum-resistant nor standardized-PQC
status. The v1.2.1 compatibility corpus locks 26 reviewed identifiers to eight
named public sources.

See the
[Algorithm Identifier Grammar](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/algorithm-identifier-grammar.md).

## Verifiable release provenance

Release jobs require two clean builds to match byte for byte and include
SHA-256 checksums and a reproducible CycloneDX SBOM. Eligible public runs add
GitHub build-provenance and SBOM attestations. PyPI publication is
environment-gated and uses OIDC Trusted Publishing rather than a stored API
token. Verification commands appear in the [Trust model](#trust-model).

## Evidence Closure

Evidence Closure is available on `main` and is not part of the `v1.2.1`
release.

It converts QSTriage-reported evidence gaps into structured questions and
provenance-aware assertions. Patches are bound to the exact source inventory,
validated before application, written to a new inventory, and compared through
the same deterministic assessment pipeline.

The optional MCP surface exposes four read-only, path-confined tools. The
repository Codex skill may inspect gaps, draft and validate a patch, and compare
inventories only after the human applies it. It never applies the patch itself.

The bundled demo closes seven evidence findings and moves the evidence score
from `0.00` to `1.00`; the `migration_planning` action and `gated` state remain
unchanged.

See the
[Evidence Closure guide](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/main/docs/evidence-closure.md).

## Scope

QSTriage is not a universal cryptography-discovery scanner. It accepts explicit
native inventories and supported CycloneDX CBOM shapes.

Its scores are deterministic prioritization indices. They do not estimate
compromise probability, the arrival date of a cryptographically relevant
quantum computer, or expected financial loss. See
[Scoring Rationale](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/scoring-rationale.md).

Canonical actions are review and planning categories, not deployment
instructions. QSTriage does not rotate certificates, deploy cryptographic
changes, or perform remediation.

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
[Input Contracts](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/input-contracts.md)
for the complete enforced contract.

## Documentation

- [Usage Guide](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/usage.md) — commands, workflows, examples, and configuration
- [Input Contracts](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/input-contracts.md) — supported inputs, limits, and parsing boundaries
- [Standards and Classification](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/standards-and-classification.md) — registry and normalization behavior
- [Algorithm Identifier Grammar](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/algorithm-identifier-grammar.md) — bounded matching rules and fail-closed behavior
- [Scoring Rationale](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/scoring-rationale.md) — prioritization index and interpretation limits
- [Simulation Rationale](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/simulation-rationale.md) — model, warnings, assumptions, and non-claims
- [Evidence and Context](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/evidence-and-context.md) — normalization, completeness, evidence, and confidence
- [Evidence Closure](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/main/docs/evidence-closure.md) — provenance-aware enrichment with human approval
- [Canonical Decision Model](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/decision-model.md) — action gating, verification, and reason codes
- [PDR 0.2 Contract](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/pdr-contract.md) — structure, provenance, determinism, and versioning
- [CBOM Compatibility](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/docs/cbom-compatibility.md) — tested artifact shapes and scanner boundaries
- [Security Policy](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/SECURITY.md) — reporting and enforced trust boundaries

## Trust model

Generated files are no-clobber by default, and terminal/Markdown output
neutralizes untrusted presentation characters. File-backed PDR generation
parses and hashes the same captured bytes.

The CI and security workflows use read-only repository permissions, immutable
action references, hashed dependency locks, vulnerability and static-analysis
checks, and full-history secret scanning.

The release workflow resolves an exact tag to an immutable commit, checks that
the tag and package version agree, and builds only that source. Its two clean
builds must match before the workflow emits the wheel, source archive,
CycloneDX SBOM, and SHA-256 manifest. Attestations are created only for eligible
public-repository runs.

Verify a downloaded release bundle from its directory with:

```bash
sha256sum --check SHA256SUMS
```

For an eligible public run with GitHub attestations:

```bash
gh attestation verify qstriage-*.whl --repo ILIASTEKEOGLOU/QSTriage
gh attestation verify qstriage-*.tar.gz --repo ILIASTEKEOGLOU/QSTriage
```

Release tags must match the package version exactly, for example `v1.2.1` for
package version `1.2.1`. PyPI publication uses an exact existing tag, a guarded
GitHub environment, and OIDC Trusted Publishing rather than a stored PyPI API
token.

Manual release-artifact runs require an existing exact release tag. Run the
workflow definition from `main` and supply the tag to rebuild:

```bash
gh workflow run release.yml --ref main -f release_tag=v1.2.1
```

## Development

Python 3.11 is the locked CI and release baseline. Create and activate a virtual
environment, then install the development dependencies:

```bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
```

The Python 3.11 job installs the exact hashed resolution in
`requirements/py311.lock`. Separate blocking jobs resolve the declared
dependency ranges afresh on Python 3.12 through 3.14 and run the same CLI,
dependency, and test checks.

## Project status

QSTriage is an early public release for local cryptographic analysis, PQC
migration planning, and PDR generation. It is provided without an SLA or
guaranteed response time.

## License

Copyright 2026 Ilias Tekeoglou.

QSTriage is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/ILIASTEKEOGLOU/QSTriage/blob/v1.2.1/LICENSE).
