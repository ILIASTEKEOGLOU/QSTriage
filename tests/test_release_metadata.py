from __future__ import annotations

from pathlib import Path
import tomllib

from qstriage import __version__


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata() -> dict[str, object]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]


def test_release_version_is_centralized() -> None:
    project = _project_metadata()

    assert project["version"] == "1.2.1"
    assert __version__ == project["version"]


def test_public_package_metadata_is_present() -> None:
    project = _project_metadata()

    assert project["authors"] == [{"name": "Ilias Tekeoglou"}]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    assert project["requires-python"] == ">=3.11"
    assert project["urls"]["Repository"] == (
        "https://github.com/ILIASTEKEOGLOU/QSTriage"
    )


def test_changelog_contains_current_release() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "## v1.2.1 - 2026-07-22" in changelog


def test_source_distribution_manifest_keeps_public_evidence() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "recursive-include docs *.md" in manifest
    assert "recursive-include tests *.json *.py" in manifest
    assert "recursive-include requirements *.in *.lock *.md" in manifest
