"""Supported dependency ranges exclude releases with known advisories.

mcp 1.8.0 to 1.29.x and 2.0.0 to 2.1.x are affected by GHSA-84m7-p3x7-pcfv,
GHSA-5h93-6whr-6q8j, GHSA-w4fh-qvv9-3v23 and GHSA-rwrf-2pqf-9j8j (fixed in
1.30.0 and 2.2.0). setuptools before 84.1.0 is affected by
GHSA-xmj3-9gf7-h52w.
"""

from pathlib import Path
import tomllib

from packaging.requirements import Requirement
from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

AFFECTED_MCP = ["1.27.0", "1.28.1", "1.29.1", "2.0.0", "2.0.1", "2.1.1"]
FIXED_MCP = ["1.30.0", "2.2.0", "2.3.0"]


def _mcp_requirements() -> list[Requirement]:
    extras = PYPROJECT["project"]["optional-dependencies"]
    found = [
        Requirement(entry)
        for group in ("dev", "mcp")
        for entry in extras[group]
        if Requirement(entry).name == "mcp"
    ]
    assert len(found) == 2
    return found


def test_mcp_ranges_exclude_affected_releases() -> None:
    for requirement in _mcp_requirements():
        for version in AFFECTED_MCP:
            assert not requirement.specifier.contains(Version(version)), (
                requirement,
                version,
            )
        for version in FIXED_MCP:
            assert requirement.specifier.contains(Version(version)), (
                requirement,
                version,
            )
        assert not requirement.specifier.contains(Version("3.0.0"))


def test_build_backend_setuptools_is_not_affected() -> None:
    [pin] = [
        Requirement(entry)
        for entry in PYPROJECT["build-system"]["requires"]
        if Requirement(entry).name == "setuptools"
    ]
    [version] = [Version(spec.version) for spec in pin.specifier]

    assert version >= Version("84.1.0")
