# Security Policy

QSTriage is an early-stage, local-first security tool for cryptographic inventory review and post-quantum migration decision support.

QSTriage does not modify production systems, rotate certificates, deploy cryptography, or perform automatic remediation.

## Reporting security issues

Please do not open a public GitHub issue for sensitive security reports.

Until private vulnerability reporting is configured for this repository, contact the maintainer privately before sharing technical exploit details.

Do not include secrets, private keys, production inventories, customer data, credentials, access tokens, or confidential system diagrams in any report.

## Scope

Security reports are most useful when they affect:

- unsafe parsing or handling of inventory or CBOM input
- incorrect policy or PDR behavior that could mislead a reviewer
- unsafe file writing behavior
- dependency or packaging issues
- documentation that could lead users to unsafe operational assumptions

QSTriage is not a production scanner, certificate manager, deployment tool, or automated compliance oracle. Reports about missing enterprise automation features are product feedback, not security vulnerabilities.

## Supported versions

Security fixes are handled on the latest `main` branch and the most recent tagged release.

## CI trust boundary

The primary CI workflow uses read-only repository permissions, immutable full-length action commit references, non-persistent checkout credentials, bounded job execution, and dependency-consistency checks. The Python 3.11 CI environment is installed from a hashed dependency lock. A separate read-only security workflow audits both the application and release-tool locks, runs Bandit across runtime and release tooling, and performs full-history Gitleaks scanning. Dependabot monitors Python and GitHub Actions updates. A separate release-artifact workflow uses an exact Python 3.11 build-tool lock, proves wheel and source-distribution reproducibility across two clean source trees, emits SHA-256 checksums and a reproducible CycloneDX SBOM, and creates GitHub provenance and SBOM attestations for tag or approved main-branch manual runs.

## Operational safety

Use sanitized inventories and examples when testing or reporting issues.

Do not run QSTriage on data you are not allowed to process.

Generated artifacts are no-clobber by default. Use `--overwrite` only for an intentional replacement; symlink destinations and active input/config collisions are rejected even when overwrite is requested.

File-backed PDR generation captures each inventory or CBOM once. The same bytes are parsed and hashed for `input_snapshot.source_hash`, preventing decision records from being bound to a later file state.

Untrusted inventory, CBOM, and configuration files are processed only within documented size, structure, string, collection, simulation, and graph-work budgets. YAML aliases are not supported. Inputs that exceed these limits are rejected explicitly; do not remove the limits to force analysis of a large or highly connected dataset. Split the dataset into reviewable scopes instead.
