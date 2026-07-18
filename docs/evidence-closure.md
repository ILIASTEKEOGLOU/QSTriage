# QSTriage Evidence Closure

## Problem

CBOM imports identify cryptographic assets but often omit the business and dependency context needed for a defensible migration decision. An assistant can help collect missing facts, but it must not invent, approve, or turn those facts into an autonomous production change.

## Existing QSTriage behavior before Build Week

Before Build Week, QSTriage already imported CycloneDX CBOMs, classified algorithms, reviewed evidence and context, scored risk, evaluated policy, produced canonical decisions, generated PDRs, analyzed graphs, simulated migration pressure, and exported reports. Imported context defaults were deliberately visible as evidence limitations.

## What Evidence Closure adds

Evidence Closure adds structured gap manifests, provenance-aware assertions, source-hash-bound enrichment patches, deterministic validation and no-clobber apply, stable before/after comparison, four read-only MCP tools, a repository Codex skill, and a reproducible judge demo.

## End-to-end workflow

1. Import a CBOM.
2. Inspect only QSTriage-reported gaps.
3. Ask a human for unresolved facts and provenance.
4. Draft and validate a source-bound patch.
5. Stop for human approval.
6. The human runs `closure apply` to create a new inventory.
7. Compare the original and enriched inventories through the same deterministic pipeline.

## Evidence assertion contract

Regular assertions identify an asset, allowlisted field, value, state, provenance, and optional rationale. Relationship assertions record `none`, `partial`, or `known`. Unknown keys, duplicate targets, unsafe values, unknown assets, stale hashes, and contradictory relationship claims are rejected.

## Declared versus verified

`declared` records a supplied claim without treating it as independently verified. `verified` is distinct and requires `source_reference`. GPT-5.6/Codex may ask questions and draft a patch. The model cannot establish that a fact is true.

## Source inventory hash binding

Every manifest and patch binds to SHA-256 over canonical Inventory JSON with sorted keys, compact separators, and UTF-8 encoding. Validation rejects a patch if the source inventory hash differs.

## Human/model/deterministic authority boundaries

- The model may inspect gaps, ask targeted questions, and draft a patch.
- The model cannot approve evidence, change scores, apply patches, or authorize migration.
- The human supplies facts, reviews every claim, and runs `closure apply`.
- QSTriage remains the deterministic decision authority.
- Decision-grade does not mean migration-authorized.

In the demo, evidence becomes decision-grade, but execution remains gated and verification priority remains high.

## CLI commands

```bash
python -m qstriage.cli import cbom examples/build-week/sample_cbom.json --output imported.yaml
python -m qstriage.cli closure inspect imported.yaml --format json --output gaps.json
python -m qstriage.cli closure validate imported.yaml examples/build-week/approved_enrichment.patch.yaml
python -m qstriage.cli closure apply imported.yaml examples/build-week/approved_enrichment.patch.yaml --output enriched.yaml
python -m qstriage.cli review evidence imported.yaml
python -m qstriage.cli review evidence enriched.yaml
python -m qstriage.cli closure compare imported.yaml enriched.yaml --format json --output comparison.json
```

## MCP tools

The MCP server is read-only and exposes exactly `inspect_evidence_gaps`, `generate_patch_template`, `validate_enrichment_patch`, and `compare_inventories`. It confines existing regular-file inputs to its working directory and performs no writes, subprocess calls, network access, or telemetry.

## Codex skill workflow

Use the `qstriage-evidence-closure` skill. It inspects first, asks only about returned gaps, accepts unknown, distinguishes declared from verified, validates a complete draft, displays claims and provenance, then stops for explicit human approval. It never runs patch application; it gives the exact command for the human.

Exact Codex model verification pending before submission.

## Five-minute judge quickstart

```bash
python -m venv .venv
# Windows Git Bash: source .venv/Scripts/activate
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[mcp]"
python scripts/build_week_demo.py
```

The demo closes seven evidence findings and reports evidence score `0.00 -> 1.00` and confidence cap `0.50 -> 1.00`. Action remains `migration_planning`, execution remains `gated`, and verification priority remains `high`.

## Security and privacy

The core workflow runs locally with no secrets, telemetry, or network access. Loaders enforce size and structure limits. Patch apply is explicit, never in-place, no-clobber by default, and produces a new file. MCP is read-only and path-confined.

## Limitations and non-claims

Evidence Closure does not discover cryptography universally, prove supplied facts, certify compliance, authorize migration, modify production, or replace human review. Scores are deterministic prioritization aids, not compromise probabilities or financial forecasts.
