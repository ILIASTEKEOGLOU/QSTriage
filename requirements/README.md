# Python 3.11 dependency lock

`py311.lock` is the hashed dependency resolution used by the Python 3.11 CI and dependency-audit jobs.

Regenerate it only from a clean Python 3.11 virtual environment using the pinned toolchain:

```bash
python -m pip install "pip==26.1.2" "pip-tools==7.5.3"
CUSTOM_COMPILE_COMMAND="python -m piptools compile pyproject.toml --extra dev --generate-hashes --output-file requirements/py311.lock" \
  python -m piptools compile \
    pyproject.toml \
    --extra dev \
    --generate-hashes \
    --output-file requirements/py311.lock
python scripts/normalize_dev_lock.py requirements/py311.lock
```

The development lock is consumed by Linux CI and also supports Windows
development, so Windows-only dependencies retain explicit environment markers.

Verify the lock before committing it:

```bash
python -m pip install --require-hashes -r requirements/py311.lock
python -m pip check
python -m pytest -q
```

The lock is CI evidence for Python 3.11. Public package consumers continue to install from `pyproject.toml`.

## Python 3.11 runtime and Linux release locks

`runtime-py311.lock` is the hashed production dependency resolution used to install and inspect the built wheel. `release.in` contains the exact direct release-tool pins. `release-linux-py311.lock` is the authoritative Ubuntu 24.04 / CPython 3.11 resolution used by the release workflow.

Environment markers can change dependency closure by operating system. Generate the Linux release lock only on Ubuntu 24.04 with Python 3.11. A Windows-generated release lock is not authoritative for the Linux release workflow.

Force the public package index so repository files cannot inherit credentials from local pip configuration:

```bash
python -m pip install "pip==26.1.2" "pip-tools==7.5.3"

CUSTOM_COMPILE_COMMAND="python -m piptools compile pyproject.toml --index-url https://pypi.org/simple --generate-hashes --output-file requirements/runtime-py311.lock" \
  python -m piptools compile \
    pyproject.toml \
    --index-url https://pypi.org/simple \
    --generate-hashes \
    --output-file requirements/runtime-py311.lock

CUSTOM_COMPILE_COMMAND="python -m piptools compile requirements/release.in --index-url https://pypi.org/simple --generate-hashes --allow-unsafe --output-file requirements/release-linux-py311.lock" \
  python -m piptools compile \
    requirements/release.in \
    --index-url https://pypi.org/simple \
    --generate-hashes \
    --allow-unsafe \
    --output-file requirements/release-linux-py311.lock
```

Inspect generated headers before committing. No private index URL, username, password, token, or trusted-host entry may appear in either lock. The release workflow independently recompiles the Linux lock and requires byte-for-byte equality before any artifact build begins.

The release workflow builds from two independent `git archive` source trees, normalizes source-distribution metadata to the commit timestamp, installs each wheel from the runtime lock, requires byte-identical wheel, sdist, CycloneDX SBOM, and checksum outputs, and validates package metadata.
