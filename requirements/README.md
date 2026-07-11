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
```

Verify the lock before committing it:

```bash
python -m pip install --require-hashes -r requirements/py311.lock
python -m pip check
python -m pytest -q
```

The lock is CI evidence for Python 3.11. Public package consumers continue to install from `pyproject.toml`.
