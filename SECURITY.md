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

## Operational safety

Use sanitized inventories and examples when testing or reporting issues.

Do not run QSTriage on data you are not allowed to process.
