# Security Policy

QSTriage is an early-stage, local-first security tool for cryptographic
inventory review and post-quantum migration decision support.

QSTriage stops at the decision boundary. It does not modify production systems,
rotate certificates, deploy cryptographic changes, or perform remediation.

## Reporting security issues

Do not open a public GitHub issue for a sensitive security report.

Use GitHub's
[private vulnerability reporting](https://github.com/ILIASTEKEOGLOU/QSTriage/security/advisories/new)
for sensitive reports. If that channel is unavailable, contact the maintainer
privately before sharing technical exploit details.

Do not include secrets, private keys, production inventories, customer data,
credentials, access tokens, or confidential system diagrams in a report.

## Scope

Security reports are most useful when they concern:

- unsafe parsing or handling of inventory, CBOM, or configuration input,
- policy, evidence, decision, or PDR behavior that could mislead a reviewer,
- unsafe terminal, Markdown, or file-output behavior,
- dependency, workflow, packaging, or release-integrity weaknesses,
- documentation that encourages unsafe operational assumptions.

QSTriage is not a production scanner, certificate manager, deployment tool, or
automated compliance oracle. Missing enterprise automation is product feedback,
not a security vulnerability.

## Supported versions

Security fixes are handled on the latest `main` branch and the most recent
tagged release.

## Enforced security posture

The repository uses:

- read-only default GitHub Actions permissions,
- immutable full-length action commit references,
- non-persistent checkout credentials and bounded job execution,
- hashed Python 3.11 application and release-tool locks,
- dependency auditing, Bandit analysis, and full-history Gitleaks scanning,
- Dependabot monitoring for Python and GitHub Actions,
- reproducible wheel/source builds, SHA-256 manifests, and CycloneDX SBOMs.

GitHub-hosted provenance and SBOM attestations run only for eligible tag pushes
or explicit exact-tag rebuilds in a public repository. Private-repository runs
retain the reproducible release bundle and local integrity evidence without
requesting attestation permissions.

## Input and decision boundaries

Inventory, CBOM, and configuration files are untrusted input. QSTriage enforces
size, structure, string, collection, simulation, and graph-work limits. YAML
aliases are rejected. Limit violations fail explicitly rather than producing a
partial decision result.

The exact supported input contract is documented in
[Input Contracts](docs/input-contracts.md).

Supported CBOM parsing is bounded structural validation, not universal
CycloneDX validation or proof of complete cryptographic discovery. See
[CBOM Compatibility](docs/cbom-compatibility.md).

File-backed PDR generation captures each source once and parses and hashes the
same bytes. See [PDR 0.2 Contract](docs/pdr-contract.md).

## Output handling

Generated files are no-clobber by default. `--overwrite` is required for an
intentional replacement, but never permits writing through a symlink or
replacing the active input/configuration file.

QSTriage publishes complete temporary output atomically and applies restrictive
permissions where supported. Terminal and Markdown presentation boundaries
neutralize user-controlled control sequences, markup, and raw HTML while
preserving the supplied value as visible text.

Use only data you are authorized to process. Prefer sanitized inventories and
examples when testing or reporting an issue. Detailed command behavior is
documented in the [Usage Guide](docs/usage.md).
