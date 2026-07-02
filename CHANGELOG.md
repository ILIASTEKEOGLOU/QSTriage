# Changelog

## v0.4.0 - CBOM algorithm normalization

### Added

- CBOM algorithm identifier normalization for registry-ready imports.
- Integration smoke tests proving normalized CBOM metadata flows into report registry evidence and scoring explanations.

### Changed

- CBOM import now normalizes split crypto metadata into stronger algorithm identifiers when possible.
- Split `algorithmFamily=ML-KEM` and `parameterSetIdentifier=768` imports as `ML-KEM-768`.
- Split `algorithmFamily=RSA` and `keySize=2048` imports as `RSA-2048`.
- Split `algorithmFamily=AES` and `keyLength=256` imports as `AES-256`.

### Validation

- Full test suite passes with 82 tests.
- End-to-end integration smoke covers CBOM split metadata -> QSTriage inventory -> standards registry -> report/scoring evidence.

## v0.3.0 - Standards-aware algorithm classification

### Added

- Source lock for v0.3.0 standards and implementation authority.
- Standards-backed algorithm classification registry.
- Algorithm classification evidence in Markdown reports.
- Registry source IDs for explainable classification output.
- Compound TLS/public-key identifier handling for algorithm strings such as `ECDHE_RSA`.
- Tests for classical public-key, PQC, symmetric, hash, compound, and unknown algorithm classifications.

### Changed

- Cryptographic scoring now uses the algorithm registry instead of standalone string-only heuristics.
- Score explanations now include registry classification and recommended registry action.
- Reports now show algorithm family, primitive, quantum status, standard status, registry action, rationale, and registry sources for each asset.

### Classification semantics

- RSA, finite-field DH, ECC, ECDH, ECDHE, ECDSA, X25519, Ed25519, and classical public-key composites are classified as quantum-vulnerable public-key cryptography for PQC migration planning.
- ML-KEM is classified as standardized PQC key encapsulation.
- ML-DSA is classified as standardized PQC digital signature.
- SLH-DSA is classified as standardized stateless hash-based PQC digital signature with operational review preserved for later reporting.
- AES is classified as symmetric encryption, separate from Shor-broken public-key migration targets.
- SHA-1, SHA-2, SHA-3, and SHAKE are classified as hash/XOF families, separate from key establishment and signature migration targets.
- Unknown algorithms are classified conservatively as requiring manual review.

### Validation

- Full test suite passes with 77 tests.

## v0.2.0 - CBOM import lite

### Added

- CycloneDX-style CBOM JSON import core.
- `qstriage import cbom` CLI command.
- Sample CBOM JSON fixture for import testing.
- Valid QSTriage YAML generation from imported CBOM cryptographic assets.
- Report warning when no QSTriage business/security dependencies are declared.
- Tests for CBOM import core, CLI import workflow, and dependency-scope report transparency.

### Import semantics

- Imported CBOM cryptographic assets become QSTriage assets.
- CBOM dependency relationships are not automatically converted into QSTriage blast-radius dependencies.
- Imported assets are marked as requiring human review for business context.
- Generated imported inventories use `dependencies: []` unless QSTriage-specific dependencies are added later.

### Validation

- End-to-end smoke tested: CBOM JSON -> QSTriage YAML -> validate -> report.
- Full test suite passes with 59 tests.

## v0.1.0 - Initial public baseline

### Added

- YAML inventory model for cryptographic assets, dependencies, and migration scenarios.
- Directed dependency graph with graph-amplified blast radius analysis.
- Explainable PQC migration priority scoring.
- Basic hybrid PQC impact simulation.
- Narrative Markdown report generation.
- Text-based dependency graph rendering.
- Friendly inventory error messages for malformed YAML and invalid inventory schemas.
- CLI commands for validation, scoring, graph rendering, report generation, and structured exports.
- JSON and CSV export commands for score results.
- JSON and CSV export commands for PQC impact simulation results.
- Basic QSTriage configuration model.
- Example configuration file at `examples/qstriage.yaml`.
- Optional `--config` support for report and export commands.
- Configurable default output paths for reports, scores, and simulations.
- Configurable default export format.
- Sample inventory and usage documentation.

### Safety boundary

- QSTriage is a local-first decision-support tool.
- QSTriage does not modify production systems.
- QSTriage does not rotate certificates, change live cryptographic settings, deploy PQC algorithms, or perform automated rollout or rollback.
