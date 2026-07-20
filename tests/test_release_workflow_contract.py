from pathlib import Path


WORKFLOW = Path(".github/workflows/release.yml")


def test_manual_release_requires_an_exact_existing_tag() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "release_tag:" in text
    assert "required: true" in text
    assert 'REQUESTED_RELEASE_TAG: ${{ inputs.release_tag }}' in text
    assert '^v[0-9]+\\.[0-9]+\\.[0-9]+$' in text
    assert 'refs/tags/$requested_tag^{commit}' in text
    assert 'test "$requested_tag" = "v$version"' in text


def test_release_jobs_use_the_resolved_immutable_source() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert text.count("ref: ${{ needs.source.outputs.source_sha }}") == 2
    assert "artifact_name=qstriage-release-$source_sha" in text
    assert "name: ${{ needs.source.outputs.artifact_name }}" in text
    assert "qstriage-release-${{ github.sha }}" not in text

def test_reproducible_cyclonedx_uses_the_canonical_predicate_type() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "predicate-type: https://cyclonedx.org/bom" in text
    assert "predicate-path: ${{ steps.sbom.outputs.path }}" in text
    assert "sbom-path: ${{ steps.sbom.outputs.path }}" not in text
