# Changelog

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
