# Contributing to QSTriage

QSTriage welcomes focused bug reports, feature proposals, documentation
corrections, and tested pull requests. Contributions should preserve the
project's deterministic, conservative decision boundaries.

## Report bugs and request features

Use a GitHub issue for non-sensitive bugs and feature requests. Search existing
issues first and include:

- the QSTriage version or commit,
- operating system and Python version,
- minimal reproduction steps,
- expected and actual behavior,
- sanitized sample input when necessary.

Never include secrets, private keys, credentials, production inventories,
customer data, or confidential system details.

For security vulnerabilities, do not open a public issue. Follow
[SECURITY.md](SECURITY.md).

## Local setup and validation

Create and activate a virtual environment, then run:

    python -m venv .venv
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    python -m qstriage.cli version
    python -m pytest
    git diff --check

## Branches and pull requests

- Branch from the current `main`; do not push normal development directly to
  `main`.
- Keep one coherent purpose per branch, commit, and pull request.
- Explain the behavioral or contract change and meaningful validation.
- Add or update tests when behavior changes.
- Update canonical documentation instead of duplicating explanations.
- Keep generated artifacts, internal handoffs, temporary audit files,
  production data, and credentials out of the repository.

## Policy and registry contributions

QSTriage currently exposes one built-in policy pack. It does not load external
policy files or provide a custom policy language.

Policy-pack, registry, or classification changes must:

- cite authoritative sources,
- remain deterministic,
- preserve conservative handling of unknown evidence,
- include positive, negative, and regression tests,
- update provenance and canonical documentation.

A proposal may be declined when it falls outside the product boundary. The
project does not promise an SLA, response time, release cadence, or acceptance
of every contribution.
