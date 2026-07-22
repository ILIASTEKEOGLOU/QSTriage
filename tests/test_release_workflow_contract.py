from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"

pytestmark = pytest.mark.skipif(
    not WORKFLOW.is_file(),
    reason="repository-only workflow contract; .github is not shipped in sdist",
)


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _publish_job(text: str) -> str:
    marker = "  publish-pypi:\n"
    assert text.count(marker) == 1
    return marker + text.split(marker, maxsplit=1)[1]


def test_manual_release_requires_an_exact_existing_tag() -> None:
    text = _workflow_text()

    assert "release_tag:" in text
    assert "required: true" in text
    assert 'REQUESTED_RELEASE_TAG: ${{ inputs.release_tag }}' in text
    assert "^v[0-9]+\\.[0-9]+\\.[0-9]+$" in text
    assert 'refs/tags/$requested_tag^{commit}' in text
    assert 'test "$requested_tag" = "v$version"' in text


def test_release_jobs_use_the_resolved_immutable_source() -> None:
    text = _workflow_text()

    assert text.count("ref: ${{ needs.source.outputs.source_sha }}") == 2
    assert "artifact_name=qstriage-release-$source_sha" in text
    assert "name: ${{ needs.source.outputs.artifact_name }}" in text
    assert "qstriage-release-${{ github.sha }}" not in text


def test_reproducible_cyclonedx_uses_the_canonical_predicate_type() -> None:
    text = _workflow_text()

    assert "predicate-type: https://cyclonedx.org/bom" in text
    assert "predicate-path: ${{ steps.sbom.outputs.path }}" in text
    assert "sbom-path: ${{ steps.sbom.outputs.path }}" not in text


def test_pypi_publish_is_manual_opt_in_and_environment_guarded() -> None:
    text = _workflow_text()
    publish = _publish_job(text)

    assert "publish_pypi:" in text
    assert "default: false" in text
    assert "type: boolean" in text
    assert "github.event.repository.private == false" in publish
    assert "github.event_name == 'workflow_dispatch'" in publish
    assert "inputs.publish_pypi" in publish
    assert "environment:\n      name: pypi" in publish
    assert "permissions:\n      id-token: write" in publish


def test_pypi_publish_reuses_only_verified_wheel_and_sdist() -> None:
    publish = _publish_job(_workflow_text())

    assert "needs:\n      - source\n      - build\n      - attest" in publish
    assert "name: ${{ needs.source.outputs.artifact_name }}" in publish
    assert "(cd release && sha256sum --check SHA256SUMS)" in publish
    assert 'wheel="release/qstriage-${PACKAGE_VERSION}-py3-none-any.whl"' in publish
    assert 'sdist="release/qstriage-${PACKAGE_VERSION}.tar.gz"' in publish
    assert "cp -- \"$wheel\" \"$sdist\" dist/" in publish
    assert 'test "$(find dist -maxdepth 1 -type f | wc -l)" -eq 2' in publish


def test_pypi_publish_uses_pinned_trusted_publisher_without_credentials() -> None:
    publish = _publish_job(_workflow_text())

    assert (
        "pypa/gh-action-pypi-publish@"
        "ba38be9e461d3875417946c167d0b5f3d385a247 # v1.14.1"
        in publish
    )
    assert "packages-dir: dist/" in publish
    assert "attestations: true" in publish
    assert "skip-existing:" not in publish
    assert "password:" not in publish
    assert "username:" not in publish
