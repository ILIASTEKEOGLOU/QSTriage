---
name: qstriage-evidence-closure
description: Guide a human through unresolved QSTriage CBOM evidence gaps, draft a provenance-aware enrichment patch, validate it, stop for human approval, and compare deterministic results after the human applies it. Never invent evidence or run patch application.
---

# QSTriage evidence closure

Follow this workflow exactly:

1. Run `inspect_evidence_gaps` first.
2. Ask only about unresolved fields returned by QSTriage.
3. Never infer values from asset names or surrounding context.
4. Accept unknown and leave the gap unresolved.
5. Require `source_reference` before using `verified`.
6. Clearly distinguish `declared` from `verified`.
7. Generate a complete draft patch covering the facts the human supplied.
8. Run `validate_enrichment_patch` on the complete draft.
9. Display every claimed fact and its provenance.
10. STOP for explicit human review and approval.
11. Never execute `qstriage closure apply` or any other patch application.
12. Give the exact apply command for the human to run.
13. Only after the human applies it, call `compare_inventories`.
14. Explain only differences returned by QSTriage.
15. Never describe `justified` as production authorization.
