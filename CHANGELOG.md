# Changelog

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
