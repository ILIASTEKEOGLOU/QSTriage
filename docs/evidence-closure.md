# QSTriage Evidence Closure

Evidence Closure is available on `main` and remains unreleased. It is not part
of the `v1.2.1` tag or its release artifacts.

## Problem

A CBOM can identify a cryptographic asset while omitting the business,
retention, exposure, and dependency facts needed for a defensible migration
decision. An assistant can help collect those facts. It cannot invent them,
approve them, or turn them into an autonomous production change.

## What Evidence Closure adds

Evidence Closure adds:

- structured manifests for unresolved evidence,
- provenance-aware assertions for allowlisted fields,
- enrichment patches bound to the source inventory hash,
- deterministic validation and explicit application to a new output file,
- refusal to overwrite an existing output,
- stable before-and-after comparison,
- four path-confined read-only MCP tools,
- the `qstriage-evidence-closure` repository skill,
- a reproducible end-to-end demo.

## End-to-end workflow

1. Import a CBOM.
2. Inspect only the gaps reported by QSTriage.
3. Ask a human for unresolved facts and provenance.
4. Draft and validate a source-bound patch.
5. Stop for human review.
6. The human applies the approved patch to a new inventory.
7. QSTriage compares both inventories through the same deterministic pipeline.

## Evidence assertion contract

Regular assertions identify an asset, allowlisted field, value, state,
provenance, and optional rationale. Relationship assertions record `none`,
`partial`, or `known`. Unknown keys, duplicate targets, invalid field values,
unknown assets, stale source hashes, and relationship claims that contradict
existing dependencies are rejected.

## Declared versus verified

`declared` records a supplied claim without treating it as independently
verified. `verified` is distinct and requires `source_reference`. A model may
ask questions and draft a patch; it cannot establish that a supplied fact is
true.

## Source inventory binding

Every manifest and patch binds to SHA-256 over canonical Inventory JSON with
sorted keys, compact separators, and UTF-8 encoding. Validation rejects a patch
when the source inventory hash differs.

## Authority boundaries

- The model may inspect gaps, ask targeted questions, and draft a patch.
- The model cannot approve evidence, change scores, apply patches, or authorize
  migration.
- The human supplies facts, reviews every claim, and runs `closure apply`.
- QSTriage remains the deterministic decision authority.
- Decision-grade evidence is not production authorization.

## CLI workflow

```bash
python -m qstriage.cli import cbom examples/evidence-closure/sample_cbom.json --output imported.yaml
python -m qstriage.cli closure inspect imported.yaml --format json --output gaps.json
python -m qstriage.cli closure validate imported.yaml examples/evidence-closure/approved_enrichment.patch.yaml
python -m qstriage.cli closure apply imported.yaml examples/evidence-closure/approved_enrichment.patch.yaml --output enriched.yaml
python -m qstriage.cli review evidence imported.yaml
python -m qstriage.cli review evidence enriched.yaml
python -m qstriage.cli closure compare imported.yaml enriched.yaml --format json --output comparison.json
```

## MCP tools

The optional MCP server exposes exactly four read-only tools:
`inspect_evidence_gaps`, `generate_patch_template`,
`validate_enrichment_patch`, and `compare_inventories`. The handlers accept only
existing regular files that resolve inside the working directory. The MCP
surface exposes no apply, write, subprocess, network, discovery, or production
operation.

## Codex skill workflow

The `qstriage-evidence-closure` skill inspects first, asks only about returned
gaps, accepts unknown, distinguishes declared from verified, validates a
complete draft, displays claims and provenance, and stops for explicit human
review. It never applies a patch. Instead, it gives the exact command for the
human to run.

## Demo

From a fresh clone:

```bash
python -m venv .venv
# Activate .venv for your shell.
python -m pip install --upgrade pip
python -m pip install -e ".[mcp]"
python scripts/evidence_closure_demo.py
```

The demo closes seven evidence findings and reports:

| Field | Before | After |
|---|---:|---:|
| Evidence score | `0.00` | `1.00` |
| Confidence cap | `0.50` | `1.00` |
| Action | `migration_planning` | `migration_planning` |
| Execution state | `gated` | `gated` |
| Verification priority | `high` | `high` |

The enriched record becomes decision-grade. Its canonical action, gated
execution state, and high verification priority remain unchanged.

## Security and privacy

The core analysis path requires no external service, account, or credential and
does not emit telemetry. Loaders enforce size and structure limits. Patch
application is explicit, never in-place, no-clobber by default, and writes a new
file. MCP remains read-only and path-confined.

## Limitations and non-claims

Evidence Closure does not discover cryptography, verify supplied facts, certify
compliance, or alter the classifier, scoring rules, or policy model. It records
reviewed assertions and reports the deterministic differences they produce.
