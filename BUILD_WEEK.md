# QSTriage OpenAI Build Week 2026

## Baseline

- Existing project: QSTriage v1.2.0
- Baseline commit: `91858aa06494761baea378f7aaa1f41bd4218952`
- Baseline tag: `v1.2.0`
- Baseline date: 2026-07-17
- Supported runtime: Python 3.11+
- Windows verification (Python 3.11.2): 326 passed, 1 skipped
- Linux sandbox verification (Python 3.13.5): 327 passed

The repository already provided CycloneDX CBOM import, cryptographic classification, decision-context and evidence review, deterministic scoring, policy evaluation, graph analysis, simulation, PDR generation, reporting, and exports before Build Week.

## Build Week extension

Working name: **QSTriage Evidence Closure — Guided CBOM Enrichment with Deterministic Decision Boundaries**.

New work planned during Build Week:

1. Structured evidence-gap manifest and improved diagnostics.
2. Provenance-aware enrichment assertions bound to the source inventory hash.
3. Deterministic patch validation and no-clobber apply workflow.
4. Stable before/after comparison of evidence findings and decisions.
5. Read-only MCP tools and a Codex skill for GPT-5.6-guided evidence collection.
6. End-to-end sample, tests, judge quickstart, and demo workflow.

## Trust boundary

- GPT-5.6 may read structured gaps, ask targeted questions, and draft an enrichment patch.
- The model may not invent facts, approve evidence, alter scores, or authorize migration.
- The human operator supplies and approves facts.
- QSTriage validates evidence, applies approved patches, and remains the deterministic decision authority.
- MCP tools remain read-only; patch application is an explicit human-run CLI action.

## Out of scope for this submission

- Web UI or dashboard
- REST API
- Splunk, Jira, or ServiceNow adapters
- Multi-organization tenancy or policy sharing
- Automated key or credential rotation
- Universal cryptographic discovery scanning
- Compliance orchestration or certification claims
- LLM-generated risk decisions

## Implementation branch

`build-week/evidence-closure`

This file is the traceability ledger separating the pre-existing v1.2.0 product from the Build Week extension.
