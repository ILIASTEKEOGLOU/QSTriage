from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"

pytestmark = pytest.mark.skipif(
    not WORKFLOW.is_file(),
    reason="repository-only workflow contract; .github is not shipped in sdist",
)


def _workflow_jobs() -> tuple[str, str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    compatibility_marker = "  compatibility:\n"

    assert text.count("  test:\n") == 1
    assert text.count(compatibility_marker) == 1

    baseline, compatibility = text.split(compatibility_marker, maxsplit=1)
    return baseline, compatibility_marker + compatibility


def test_python_311_remains_the_locked_ci_baseline() -> None:
    baseline, _ = _workflow_jobs()

    assert "name: test (Python 3.11)" in baseline
    assert 'python-version: "3.11"' in baseline
    assert 'cache-dependency-path: "requirements/py311.lock"' in baseline
    assert (
        "python -m pip install --require-hashes -r requirements/py311.lock"
        in baseline
    )
    assert "matrix.python-version" not in baseline


def test_later_python_versions_use_a_separate_blocking_compatibility_matrix() -> None:
    _, compatibility = _workflow_jobs()

    for version in ("3.12", "3.13", "3.14"):
        assert f'          - "{version}"' in compatibility

    assert "fail-fast: false" in compatibility
    assert "continue-on-error" not in compatibility
    assert "name: compatibility (Python ${{ matrix.python-version }})" in compatibility
    assert "python-version: ${{ matrix.python-version }}" in compatibility


def test_compatibility_job_resolves_dependencies_and_runs_full_validation() -> None:
    _, compatibility = _workflow_jobs()

    assert "requirements/py311.lock" not in compatibility
    assert "--require-hashes" not in compatibility
    assert "PIP_INDEX_URL: https://pypi.org/simple" in compatibility
    assert 'PIP_EXTRA_INDEX_URL: ""' in compatibility
    assert 'cache-dependency-path: "pyproject.toml"' in compatibility
    assert 'python -m pip install -e ".[dev]"' in compatibility
    assert "python -m pip check" in compatibility
    assert "python -m qstriage.cli version" in compatibility
    assert "python -m pytest" in compatibility
