# QSTriage OpenAI Build Week 2026

## Implemented candidate status

- Existing project: QSTriage v1.2.0
- Baseline SHA: `91858aa06494761baea378f7aaa1f41bd4218952`
- Build Week branch: `build-week/evidence-closure`
- Candidate commit range: `91858aa..HEAD`
- Status: implemented submission candidate; no public release or tag yet

The baseline already included CycloneDX CBOM import, classification, evidence and context review, deterministic scoring, policy evaluation, canonical decisions, PDR generation, graph analysis, simulation, reporting, and exports.

## Build Week capabilities

The candidate adds structured evidence-gap diagnostics; strict provenance assertions bound to a canonical source inventory hash; deterministic validate, no-clobber apply, and before/after comparison; closure CLI commands; four path-confined read-only MCP tools; the `qstriage-evidence-closure` repository skill; cross-platform judge automation; deterministic fixtures; contract, protocol, portability, and end-to-end tests; and submission documentation.

## Trust boundary

- A model may inspect gaps, ask targeted questions, and draft a patch.
- A model cannot establish truth, approve evidence, alter scores, apply patches, or authorize migration.
- The human supplies and approves facts and explicitly runs patch application.
- QSTriage validates inputs and remains the deterministic decision authority.
- MCP is read-only. The core workflow has no secrets, telemetry, or network access.
- Decision-grade evidence is not production or migration authorization.

Exact Codex model verification pending before submission.

## Test strategy

Tests cover backward-compatible serialization, strict evidence models, provenance-aware review, stable manifests and hashes, patch validation and safe apply, deterministic comparison, CLI failures, official MCP STDIO protocol behavior, path confinement, skill/config contracts, dependency-lock portability, generated fixture equality, and independent end-to-end demo runs on Windows and Linux.

## Accurate demo result

For the synthetic `customer-api-rsa` asset:

- action: `migration_planning -> migration_planning`
- execution state: `gated -> gated`
- evidence score: `0.00 -> 1.00`
- confidence cap: `0.50 -> 1.00`
- evidence decision grade: `not_decision_grade -> decision_grade`
- closed evidence findings: `7`
- verification priority: `high -> high`

The unchanged gate is intentional: supplied evidence closes evidence-quality gaps without authorizing migration.

## Judging and release status

Private-repository judges can clone the authorized branch, install `.[mcp]`, and run `python scripts/build_week_demo.py`; no external service or credential is required. A public release/tag has not been created. Release claims and exact model metadata must be verified separately before submission.

## Out of scope

No web UI, REST API, multi-tenant policy service, ticketing adapter, automated rotation, universal discovery scanner, compliance certification, LLM risk decision, or production orchestration is claimed.
