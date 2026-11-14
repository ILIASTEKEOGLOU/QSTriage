import os
from pathlib import Path
import shutil
import subprocess

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


def _source_identity_script(text: str) -> str:
    marker = "      - name: Verify source and package identity\n"
    assert text.count(marker) == 1
    step = text.split(marker, maxsplit=1)[1]
    script = step.split("        run: |\n", maxsplit=1)[1]
    lines = []
    for line in script.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines)


def test_both_tag_paths_apply_the_same_exact_tag_check() -> None:
    script = _source_identity_script(_workflow_text())
    dispatch, push = script.split('elif [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then', 1)

    assert script.count("^v[0-9]+\\.[0-9]+\\.[0-9]+$") == 1
    assert 'require_exact_release_tag "$requested_tag"' in dispatch
    assert 'require_exact_release_tag "$GITHUB_REF_NAME"' in push
    # The check runs before the tag is resolved or compared on each path.
    assert dispatch.index("require_exact_release_tag \"$requested_tag\"") < dispatch.index(
        "refs/tags/$requested_tag^{commit}"
    )
    assert push.index('require_exact_release_tag "$GITHUB_REF_NAME"') < push.index(
        "refs/tags/$GITHUB_REF_NAME^{commit}"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not available")
@pytest.mark.parametrize(
    ("tag", "accepted"),
    [
        ("v1.5.0", True),
        ("v10.20.30", True),
        ("v1.5.0.dev0", False),
        ("v1.5.0rc1", False),
        ("v1.5.0-rc.1", False),
        ("v1.5", False),
        ("1.5.0", False),
        ("v1.5.0\n", False),
    ],
)
def test_exact_tag_check_accepts_only_release_tags(tag: str, accepted: bool) -> None:
    script = _source_identity_script(_workflow_text())
    start = script.index("require_exact_release_tag() {")
    end = script.index("\n}\n", start) + 3
    function = script[start:end]

    # Preserve trailing whitespace when native Windows Python starts Git Bash.
    result = subprocess.run(
        ["bash", "-c", function + 'require_exact_release_tag "$QSTRIAGE_TEST_RELEASE_TAG"'],
        env={**os.environ, "QSTRIAGE_TEST_RELEASE_TAG": tag},
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode == 0) is accepted
    if not accepted:
        assert "is not an exact vMAJOR.MINOR.PATCH release tag" in result.stdout


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
        "7245906fb61fa33a13554f9d5fb856fe61758086 # v1.14.3"
        in publish
    )
    assert "packages-dir: dist/" in publish
    assert "attestations: true" in publish
    assert "skip-existing:" not in publish
    assert "password:" not in publish
    assert "username:" not in publish


def test_linux_release_lock_check_is_seeded_and_refetches_hashes() -> None:
    text = _workflow_text()

    seed = (
        "cp requirements/release-linux-py311.lock "
        "generated/release-linux-py311.lock"
    )
    assert seed in text
    assert "--no-reuse-hashes" in text
    assert text.index(seed) < text.index("python -m piptools compile \\")
    assert "cmp -s \\" in text
