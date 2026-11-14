from __future__ import annotations

from pathlib import Path
import re
import tomllib

from qstriage import __version__


ROOT = Path(__file__).resolve().parents[1]


def _project_metadata() -> dict[str, object]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["project"]


# A release is MAJOR.MINOR.PATCH. Between releases, main carries the next
# release number with the suffix .dev0, so output produced from unreleased code
# is never labelled with a published version. The suffix does not identify
# the commit.
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(\.dev0)?")
_RELEASE_HEADING = re.compile(r"^## v(\d+)\.(\d+)\.(\d+) - \d{4}-\d{2}-\d{2}$", re.MULTILINE)


def _changelog() -> str:
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def _released(changelog: str) -> list[tuple[int, int, int]]:
    return [tuple(int(part) for part in match) for match in _RELEASE_HEADING.findall(changelog)]


def test_release_version_is_centralized() -> None:
    project = _project_metadata()

    assert __version__ == project["version"]
    assert _VERSION.fullmatch(project["version"]), (
        f"Version {project['version']!r} must be MAJOR.MINOR.PATCH for a release "
        "or MAJOR.MINOR.PATCH.dev0 between releases."
    )


def test_public_package_metadata_is_present() -> None:
    project = _project_metadata()

    assert project["authors"] == [{"name": "Ilias Tekeoglou"}]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    assert project["requires-python"] == ">=3.11"
    assert project["urls"]["Repository"] == (
        "https://github.com/ILIASTEKEOGLOU/QSTriage"
    )


def test_changelog_matches_the_package_version() -> None:
    match = _VERSION.fullmatch(_project_metadata()["version"])
    assert match is not None
    version = tuple(int(part) for part in match.groups()[:3])
    changelog = _changelog()
    released = _released(changelog)
    assert released == sorted(released, reverse=True), "Release sections must be newest first."

    if match.group(4):
        # Between releases: changes are collected under Unreleased, above the
        # newest release, and the development version is higher than it.
        assert changelog.index("## Unreleased") < changelog.index("## v")
        assert version > released[0]
    else:
        # Release preparation: the newest section is this release and no
        # Unreleased section remains.
        assert released[0] == version
        assert "## Unreleased" not in changelog


def test_development_suffix_is_never_a_release_tag() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    # One exact-tag check, applied on manual dispatch and on tag push.
    assert workflow.count(r'"$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$') == 1
    assert 'require_exact_release_tag "$requested_tag"' in workflow
    assert 'require_exact_release_tag "$GITHUB_REF_NAME"' in workflow
    assert 'test "$GITHUB_REF_NAME" = "v$version"' in workflow


def test_source_distribution_manifest_keeps_public_evidence() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "recursive-include docs *.md" in manifest
    assert "recursive-include tests *.json *.py" in manifest
    assert "recursive-include requirements *.in *.lock *.md" in manifest
