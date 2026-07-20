# Build Week submission draft

## Project name

QSTriage Evidence Closure

## Tagline

Close CBOM evidence gaps with human-approved provenance while deterministic decisions stay authoritative.

## Problem

CBOMs can identify cryptographic assets while omitting the business, retention, exposure, and relationship context needed for defensible migration decisions. An AI assistant can help ask for missing facts, but it must not invent evidence or become the decision authority.

## What it does

Evidence Closure turns QSTriage evidence findings into structured questions, accepts provenance-aware human assertions, validates a source-hash-bound patch, writes a new enriched inventory only after explicit human apply, and compares evidence and canonical decisions deterministically.

## What existed before Build Week

QSTriage v1.2.0 already provided CycloneDX CBOM import, algorithm classification, context and evidence review, deterministic scoring, policy evaluation, canonical decisions, PDR generation, graph analysis, simulation, reporting, and exports.

## What was built during Build Week

Build Week added strict evidence metadata, structured gap manifests, deterministic patch validation and no-clobber apply, stable before/after comparison, closure CLI commands, four read-only MCP tools, a repository Codex skill, dependency-lock portability, generated demo fixtures, a cross-platform judge runner, and end-to-end contract tests.

## How Codex was used

Codex was used to inspect the existing architecture, write contract tests first, implement the scoped phases, run Windows and Linux verification, debug MCP STDIO and dependency portability, generate deterministic fixtures through real commands, and prepare submission documentation. Primary Build Week Codex session model: gpt-5.6-sol, verified through the Codex /model selector before submission.

## How GPT-5.6 is used in the product workflow

Through the `qstriage-evidence-closure` skill, GPT-5.6 reads only QSTriage-reported gaps, asks targeted questions, accepts unknown, distinguishes declared from verified, drafts a complete patch, validates it through read-only MCP, displays every claim and provenance, and stops for human approval. It never runs patch application.

## Technical architecture

Pydantic models enforce strict inventory evidence and patch contracts. Canonical Inventory JSON produces the SHA-256 source binding. Existing evidence review and assessment pipelines generate gaps and comparisons. Typer exposes local CLI commands. FastMCP exposes exactly four path-confined read-only tools. Atomic no-clobber output protects source files. The Python judge runner uses argument-list subprocess calls and checked exit codes.

## Trust and safety boundary

The model cannot establish truth, approve evidence, change risk scores, apply patches, or authorize migration. The human reviews claims and runs `qstriage closure apply`. QSTriage remains the deterministic decision authority. Decision-grade evidence is not production authorization, and the demo execution state remains gated.

## Challenges

The main challenges were preserving legacy serialization and hashes, keeping declared and verified evidence distinct, making generated output byte-stable, safely binding patches to source inventories, implementing a truly read-only MCP surface, and maintaining one hashed development lock across Windows and Linux.

## Accomplishments

The demo closes exactly seven evidence findings. Evidence score changes `0.00 -> 1.00` and confidence cap `0.50 -> 1.00`. Evidence review becomes decision-grade with no remaining or introduced findings. The canonical action accurately remains `migration_planning -> migration_planning`, execution remains `gated -> gated`, and verification priority remains `high -> high`.

## What was learned

Closing uncertainty is valuable even when the action does not change. Provenance and explicit authority boundaries make AI assistance useful without transferring decision rights. Deterministic fixtures and protocol tests make that boundary demonstrable rather than aspirational.

## What is next

Next steps are judge feedback, broader real-world CBOM compatibility fixtures,
usability improvements for evidence interviews, and final video and submission
metadata. Evidence Closure remains unreleased pending final product review.

## Testing instructions

```bash
python -m venv .venv
# Windows Git Bash: source .venv/Scripts/activate
# Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[mcp]"
python scripts/build_week_demo.py
python -m pytest -q
python -m pip check
```

The runner imports the synthetic CBOM, inspects gaps, validates and applies the approved synthetic patch, reviews evidence before and after, and produces deterministic comparison output.

## Repository access

Use the repository's default `main` branch. The core demo requires no secret,
telemetry, production access, or network service after installation.

## Video

The final submission video will be linked after it is recorded and published.

## Codex /feedback Session ID

Codex /feedback Session ID: `019f7434-a1d5-7f93-84ed-b3b24e1d666e`
