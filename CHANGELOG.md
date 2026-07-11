# Changelog

## Unreleased

### Added

- Added a hashed Python 3.11 dependency lock, automated vulnerability and static-analysis workflows, full-history secret scanning, and Dependabot coverage for Python and GitHub Actions.

- Added immutable GitHub Actions references, bounded CI execution, non-persistent checkout credentials, and dependency-consistency verification.

- Added a read-once PDR input capture boundary that parses and hashes the same exact source bytes.
- Added a documented input and workload safety boundary covering file size, collection size, string length, YAML structure, simulation fan-out, and graph traversal/output budgets.
- Added a shared private file-output boundary with atomic publication, owner-only file permissions, symlink rejection, and protected input/config collision checks.
- Added a shared presentation-safety boundary for terminal and Markdown output generated from untrusted inventory or CBOM values.
- Added versioned canonical execution, action, verification, confidence, review, and reason-code fields to JSON and CSV score exports.
- Added deterministic inventory-level assessment assembly for analyst-facing output surfaces.
- Added canonical execution, action, verification, confidence, review, and reason-code detail to Markdown reports.
- Added a shared asset-assessment boundary that gathers classification, scoring, normalized context, evidence review, policy evaluation, decision confidence, and canonical decision state.
- Added canonical execution, action, verification, review, and reason-code fields to PDR decision records.
- Added a shared typed context-normalization layer that preserves raw values and records declared, missing, defaulted, or unmapped state.

### Changed

- CI now installs the exact hashed dependency resolution and uses current immutable Node 24-compatible checkout and Python setup actions.

- CI now installs a pinned pip release and the development dependency floor excludes pytest versions affected by CVE-2025-71176.

- File-backed PDR generation now derives inventory data, CBOM version metadata, and `source_hash` from one immutable captured byte snapshot.
- Inventory, configuration, and CBOM loading now reject oversized, structurally invalid, duplicate-key, or unsupported alias-based input before analysis begins.
- Report, CBOM import, PDR, and JSON/CSV export commands now refuse to replace existing output unless `--overwrite` is explicitly provided.
- Score exports now use assessment contract `0.2`; the compatibility field `recommended_action` aliases canonical `action_type`, and score-derived action text is omitted from explanations.
- CLI score output and Markdown reports now project the shared canonical decision instead of the legacy score-derived action.
- Bumped the PDR contract version from `0.1` to `0.2`; record and document hashes therefore change with the new serialized decision contract.
- PDR generation now projects `CanonicalDecision` instead of rebuilding action and human-review state from score fields.
- Policy, scoring, simulation, context review, and decision gating now consume the same canonical data-sensitivity and exposure categories.

### Fixed

- Prevented PDR source-snapshot TOCTOU inconsistencies where decision state and `source_hash` could previously come from different file contents.
- Replaced empty-inventory, malformed-CBOM, and excessive graph-work crashes with deterministic validation or resource-limit errors.
- Prevented output paths from following symlinks, overwriting source/config files, or leaving a partially replaced artifact when publication fails.
- Neutralized terminal control/markup injection and Markdown structure/raw-HTML injection while preserving suspicious values as visible escape sequences.
- JSON and CSV score exports no longer publish score-derived action text that can contradict the canonical decision.
- Markdown score explanations no longer repeat a legacy action that can contradict the canonical decision.
- PDR records no longer expose score-derived action text that can contradict canonical execution and verification state.
- Realistic context aliases no longer receive contradictory cross-module interpretations, while unknown or unmapped values require verification instead of being guessed.

## v1.1.0 - 2026-07-08

### Added

- Added an IBM-style CBOM compatibility fixture using `bomFormat: "CBOM"` and `crypto-asset` components.
- Confirmed the CBOM importer accepts `cryptoProperties`-bearing components even when typed `crypto-asset` rather than `cryptographic-asset`, covering IBM-style CBOM artifacts.
- Added compatibility coverage for CBOM import, CLI workflows, evidence review, scoring, and report generation.
- Added `docs/scoring-rationale.md` documenting priority scores as deterministic planning heuristics rather than probability estimates, actuarial measurements, compliance certifications, or empirical risk predictions.
- Added policy normalization tests for realistic data-class and exposure vocabulary.
- Added context-normalization contract tests covering existing data-class and exposure behavior.
- Added divergence tests documenting where policy, scoring, and simulation do not yet share the same context vocabulary.
- Added regression coverage for parameterized ML-KEM, ML-DSA, and SLH-DSA identifiers.
- Added CSV export regression coverage for spreadsheet formula trigger characters across reachable asset, protocol, and scenario fields.

### Changed

- Normalized CBOM protocol-only assets so protocol identifiers are preserved in the QSTriage `protocol` field.
- Protocol-only assets without algorithm evidence now import with `algorithm: "unknown"` rather than treating the component or protocol name as an algorithm.
- CBOM import notes now preserve `assetType=protocol` metadata for review traceability.
- Normalized hyphen and underscore variants in policy-derived context.
- Extended policy-derived data-sensitivity detection for GDPR, cardholder, and patient context.
- Extended policy exposure categorization for common public, partner, internal, and restricted exposure terms.
- Reused standards classification during PDR evidence-quality evaluation.

### Fixed

- Parameterized standardized PQC identifiers such as ML-KEM, ML-DSA, and SLH-DSA variants are no longer incorrectly reported as missing `key_size_bits`.
- Protocol identifiers such as `tlsv12` are no longer represented as algorithm families during CBOM import.
- CSV score and simulation exports now preserve formula-leading user-controlled values as plain spreadsheet text.

### Security

- Neutralized spreadsheet formula injection risk in analyst-facing CSV exports for reachable asset, protocol, scenario, and derived explanation fields.
- Restricted the GitHub Actions `GITHUB_TOKEN` to read-only repository contents using explicit least-privilege workflow permissions.

### Validation

- Confirmed IBM-style AES and TLS v1.2 crypto assets import into a valid QSTriage inventory.
- Confirmed imported assets pass through validation, scoring, evidence review, and report generation.
- Confirmed protocol-only and unknown-algorithm evidence continues to require conservative human review.
- Confirmed normal CSV text, numeric CSV fields, and JSON score exports remain unchanged.
- GitHub Actions validation passed after the CI permission restriction.
- Full local test suite passes with 233 tests.

### Known Limitations

- CBOM dependency relationships are not yet mapped into QSTriage blast-radius dependencies.
- Shared cross-module context normalization remains a follow-up implementation track.
- Epistemic action gating and conflict resolution remain a separate post-v1.1.0 track.
- Scoring weights, simulation behavior, and the PDR schema are unchanged.

## v1.0.1 - Public Trust Infrastructure

### Added

- Added GitHub Actions CI for push and pull_request validation.
- Added Python 3.11 GitHub runner validation using the supported baseline.
- Added CLI smoke validation in CI with `python -m qstriage.cli version`.
- Added full test execution in CI with `python -m pytest`.
- Added README CI status badge.

### Validation

- GitHub Actions CI passed on the feature branch.
- GitHub Actions CI passed on main after merge.
- Local CLI version smoke passed.
- Full local test suite passes with 153 tests.

### Scope

- No engine changes.
- No policy changes.
- No importer changes.
- No PDR schema changes.
- No scoring changes.



## v1.0.0 - Public Release Baseline

### Released

- First public baseline of QSTriage as a local-first tool for PQC migration decisions.
- The release centers on the working path: inventory and CBOM input, algorithm classification, evidence review, scoring, policy evaluation, PDR generation, reports, and structured exports.
- Added Apache-2.0 licensing and a security policy for public use and responsible reporting.

### Clarified

- Reworked the README opening around the migration problem QSTriage is meant to solve.
- Split the quickstart from the developer setup path.
- Documented the PDR JSON output as an evolving public decision artifact, not an internal debug dump.
- Clarified that PDR hashes are deterministic for the same version, input, policy pack, and generated content, but are not a cross-version compatibility promise.
- Cleaned stale wording before the v1.0 release.

### Validation

- Fresh clone, runtime install, policy listing, PDR generation, and policy evaluation smoke passed.
- Development install with test dependencies passed.
- Full test suite passes with 153 tests.

## v0.9.0 - Live Policy Evaluation

### Added

- Added deterministic asset-level `PolicyEvaluator.evaluate_asset()`.
- Added executable policy fact derivation for data sensitivity, exposure category, and business context.
- Added record-level `policy_evaluation` to PDR records using `PolicyEvaluationResult`.
- Added policy evaluation tests for quantum-vulnerable assets, standardized PQC assets, unknown algorithms, missing business context, long-retention sensitive data, and exposed assets.

### Changed

- Updated the built-in `nist-pqc-basic` policy pack to version `0.2`.
- Aligned built-in policy rule conditions with deterministic asset facts.
- PDR record hashes now naturally include policy evaluation output.
- `PolicyContext` remains document-level policy pack provenance only.

### Fixed

- Prevented PDR generation from crashing on unknown algorithms by routing them to manual cryptographic review.
- Stabilized PDR record and document hashes across relative and absolute source path forms.
- Centralized QSTriage version metadata for CLI output and PDR engine metadata.
- Clarified policy pack scope in documentation.
- Added ASCII fallback for text dependency graph output on non-UTF-8 terminals to avoid Windows `UnicodeEncodeError` failures.

### Validation

- Full test suite passes with 153 tests.

## v0.8.0 - Policy Packs Foundation

- Added explicit policy pack domain models for versioned, auditable cryptographic decision policy.
- Added the built-in `nist-pqc-basic` policy pack with NIST, CISA, and QSTriage safety references.
- Added deterministic policy pack hashing for reproducible PDR policy context.
- Integrated PDR policy context with the built-in policy pack registry.
- Added `qstriage policy list` and `qstriage policy show nist-pqc-basic`.
- Kept policy packs local-first and deterministic; no external policy loading is included in this release.

## v0.7.0 - Evidence Quality Engine

### Added

- Evidence review domain model for structured decision-grade evidence assessment.
- Evidence findings with severity, category, effects, evidence state, maturity, provenance, relationship completeness, and recommended human action.
- Inventory evidence review engine for QSTriage YAML inventories and CycloneDX CBOM-derived inventories.
- Confidence caps and decision-grade status based on blocking evidence findings.
- Explicit handling for missing, defaulted, no-assertion, unknown, and CBOM-derived evidence states.
- Relationship completeness handling for dependency evidence, including unknown and known dependency context.
- PDR records now include structured `evidence_review` data alongside the existing `evidence_quality` compatibility block.
- `qstriage review evidence` CLI command.
- Evidence review support for CycloneDX CBOM input via `--input-format cbom`.
- Audit-friendly evidence review CLI details with untruncated asset IDs and blocking finding codes.

### Changed

- PDR decision confidence is now constrained by evidence review confidence caps.
- Human-review status now reflects structured evidence review findings.
- Informational evidence findings no longer degrade evidence score or confidence cap.
- README and usage documentation now describe evidence quality review and decision-grade readiness.

### Validation

- Full test suite passes with 113 tests.
- Manual smoke verified `qstriage review evidence examples/sample_inventory.yaml`.
- Manual smoke verified `qstriage review evidence tests/fixtures/sample_cbom.json --input-format cbom`.
- Manual smoke verified sample inventory assets are decision-grade with full evidence confidence.
- Manual smoke verified CBOM-derived assets are not decision-grade until business and dependency context is supplied.

## v0.6.0 - PDR foundation

### Added

- PQC Decision Record (PDR) document model.
- Deterministic record and document hashing for reproducible decision artifacts.
- Input snapshot metadata with source type, source version, source path, and source hash.
- Policy context metadata with built-in `nist-pqc-basic` policy pack identity and standards applied.
- Observed cryptographic state per asset.
- Evidence quality scoring for missing or defaulted decision evidence.
- Decision confidence scoring separate from evidence quality.
- Mission context, trade-offs, assumptions, human-review status, and target-state suggestions.
- `qstriage pdr generate` CLI command.
- PDR generation from QSTriage YAML inventories.
- PDR generation from CycloneDX CBOM JSON crypto evidence.

### Changed

- Project positioning updated to Cryptographic Policy & Justification Engine.
- Package discovery is now explicit so editable installs do not accidentally include generated report folders.

### Validation

- Full test suite passes with 97 tests.
- Manual smoke verified PDR generation from `examples/sample_inventory.yaml`.
- Manual smoke verified PDR generation from `tests/fixtures/sample_cbom.json`.
- Generated PDRs include SHA-256 record integrity hashes.

## v0.5.0 - Decision context review

### Added

- Decision context review core for identifying incomplete business context.
- `qstriage review context` CLI command.
- Decision Context Review section in Markdown reports.
- Tests for complete hand-written inventories and incomplete CBOM-imported inventories.

### Changed

- Reports now state whether the supplied inventory appears decision-grade under the current review rules.
- CBOM-imported inventories now surface missing or defaulted business context directly in CLI review output and reports.

### Review semantics

- Assets with `data_class=unknown`, `retention_years=0`, or `exposure=unknown` are flagged as incomplete.
- CBOM-imported assets using default `criticality=medium`, `local_blast_radius=medium`, or `migration_effort=medium` are flagged for business review.
- Inventories with no QSTriage business/security dependencies are flagged because graph-amplified blast radius may be limited.
- QSTriage does not change the score automatically; it explains whether the score should be treated as decision-grade.

### Validation

- Full test suite passes with 89 tests.
- Manual smoke verified sample inventory review status is complete.
- Manual smoke verified CBOM-imported inventory review status is incomplete.
- Manual smoke verified generated reports include Decision Context Review.

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
