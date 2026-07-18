# Build Week submission draft

## Project name

QSTriage Evidence Closure

## Tagline

Close CBOM evidence gaps with human-approved provenance while deterministic decisions stay authoritative.

## Concise description

QSTriage Evidence Closure turns imported CBOM uncertainty into a structured, source-bound workflow. A model can inspect unresolved fields and draft provenance-aware claims; QSTriage validates them deterministically, a human explicitly applies the patch, and stable comparison shows only actual evidence and decision differences.

## Verified demo result

The synthetic demo closes seven evidence findings. Evidence score moves from `0.00` to `1.00`, confidence cap from `0.50` to `1.00`, and evidence review becomes decision-grade. The canonical action remains `migration_planning`, execution remains `gated`, and verification priority remains `high`. This is not production authorization.

## Judge path

Install with `python -m pip install -e ".[mcp]"` and run `python scripts/build_week_demo.py`. The workflow is local, deterministic, no-clobber, and requires no secret, telemetry, network service, or production access.

## Trust boundary

The model may ask questions and draft a patch but cannot establish truth, approve evidence, apply changes, modify scores, or authorize migration. The human reviews and applies; QSTriage remains authoritative.

## Submission note

Primary Build Week Codex session model: gpt-5.6-sol, verified through the Codex /model selector before submission. No public release or tag has been created.
