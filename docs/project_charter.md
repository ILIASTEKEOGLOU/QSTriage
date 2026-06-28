# QSTriage Project Charter

QSTriage means Quantum-Safe Triage.

QSTriage is an explainable post-quantum cryptography migration decision engine.

It helps teams turn cryptographic inventory data into a prioritized, explainable migration planning backlog.

Core workflow:

```text
inventory -> dependency graph -> explainable scoring -> impact simulation -> narrative report -> structured exports
```

Primary design principle:

```text
judgment before automation
```

QSTriage is not a production migration orchestrator. It does not rotate certificates, change live cryptographic configuration, deploy PQC algorithms, or perform rollout or rollback.

The tool is intended to help teams reason about what to prioritize, why it matters, and what should be simulated before any production migration work begins.
