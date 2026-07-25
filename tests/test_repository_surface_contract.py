from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

import pytest

from qstriage import __version__


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README = REPOSITORY_ROOT / "README.md"
REPOSITORY_URL = "https://github.com/ILIASTEKEOGLOU/QSTriage"

pytestmark = pytest.mark.skipif(
    not (REPOSITORY_ROOT / ".git").exists() or shutil.which("git") is None,
    reason="repository-only surface contract; Git metadata is not shipped in sdist",
)


def _tracked_paths() -> set[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    )
    paths = {
        Path(value.decode())
        for value in result.stdout.split(b"\0")
        if value
    }
    paths.add(Path(__file__).resolve().relative_to(REPOSITORY_ROOT))
    return {
        path
        for path in paths
        if (REPOSITORY_ROOT / path).is_file()
        or (REPOSITORY_ROOT / path).is_symlink()
    }


def _markdown_targets(text: str) -> list[str]:
    return re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)


def _repository_blob_targets(text: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        re.escape(REPOSITORY_URL)
        + r"/blob/(?P<ref>[^/]+)/(?P<path>[^)#?]+)"
    )
    return [
        (match.group("path"), match.group("ref"))
        for target in _markdown_targets(text)
        if (match := pattern.fullmatch(target))
    ]


def test_readme_release_references_match_the_package_version() -> None:
    readme = README.read_text(encoding="utf-8")
    release_refs = re.findall(r"/blob/v(\d+\.\d+\.\d+)/", readme)
    release_tag_examples = re.findall(r"release_tag=v(\d+\.\d+\.\d+)", readme)

    assert release_refs
    assert set(release_refs) == {__version__}
    assert release_tag_examples
    assert set(release_tag_examples) == {__version__}

    relative_docs = [
        target
        for target in _markdown_targets(readme)
        if target.startswith(("docs/", "./docs/", "../docs/"))
    ]
    assert relative_docs == []

    blob_targets = _repository_blob_targets(readme)
    assert {
        path for path, ref in blob_targets if ref == "main"
    } == {"docs/evidence-closure.md"}
    assert {
        ref
        for path, ref in blob_targets
        if path != "docs/evidence-closure.md"
    } == {f"v{__version__}"}


def test_documentation_index_is_complete_and_pypi_safe() -> None:
    readme = README.read_text(encoding="utf-8")
    marker = "## Documentation\n"
    assert readme.count(marker) == 1
    section = readme.split(marker, maxsplit=1)[1].split("\n## ", maxsplit=1)[0]

    tracked_docs = {
        path.as_posix()
        for path in _tracked_paths()
        if path.parts and path.parts[0] == "docs" and path.suffix == ".md"
    }
    links = [
        (path, ref)
        for path, ref in _repository_blob_targets(section)
        if path.startswith("docs/") and path.endswith(".md")
    ]

    assert len(links) == len(tracked_docs)
    assert {path for path, _ in links} == tracked_docs

    main_docs = {path for path, ref in links if ref == "main"}
    assert main_docs == {"docs/evidence-closure.md"}
    assert {
        ref
        for path, ref in links
        if path != "docs/evidence-closure.md"
    } == {f"v{__version__}"}


def test_retired_event_framing_is_absent_from_the_current_tree() -> None:
    generic_legal_term = "sub" + "mission"
    retired_terms = (
        "build" + " week",
        "build" + "-week",
        "build" + "_week",
        "jud" + "ge",
        "hack" + "athon",
        generic_legal_term,
        "dev" + "post",
    )
    legal_path = Path("LICENSE")
    legal_text = (REPOSITORY_ROOT / legal_path).read_text(encoding="utf-8")
    assert legal_text.casefold().count(generic_legal_term) == 1
    assert (
        "5. " + generic_legal_term.title() + " of Contributions."
        in legal_text
    )

    findings: list[str] = []
    for path in sorted(_tracked_paths()):
        relative = path.as_posix().casefold()
        for term in retired_terms:
            if term in relative:
                findings.append(f"{path}: path contains {term!r}")

        source = REPOSITORY_ROOT / path
        if source.is_symlink():
            continue
        data = source.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8").casefold()
        except UnicodeDecodeError:
            continue
        for term in retired_terms:
            if path == legal_path and term == generic_legal_term:
                continue
            if term in text:
                findings.append(f"{path}: content contains {term!r}")

    assert findings == []


def test_evidence_closure_demo_paths_are_canonical() -> None:
    expected_paths = {
        Path("examples/evidence-closure/approved_enrichment.patch.yaml"),
        Path("examples/evidence-closure/expected/comparison.json"),
        Path("examples/evidence-closure/expected/enriched.yaml"),
        Path("examples/evidence-closure/expected/gaps.json"),
        Path("examples/evidence-closure/imported.yaml"),
        Path("examples/evidence-closure/sample_cbom.json"),
        Path("scripts/evidence_closure_demo.ps1"),
        Path("scripts/evidence_closure_demo.py"),
        Path("scripts/evidence_closure_demo.sh"),
        Path("tests/test_evidence_closure_demo.py"),
    }
    tracked_paths = _tracked_paths()
    assert expected_paths <= tracked_paths
    assert not any(
        path.parts
        and path.parts[0].startswith("evidence-closure-demo-output")
        for path in tracked_paths
    )

    script = (
        REPOSITORY_ROOT / "scripts" / "evidence_closure_demo.py"
    ).read_text(encoding="utf-8")
    assert '"examples" / "evidence-closure"' in script
    assert 'default=Path("evidence-closure-demo-output")' in script

    shell_wrapper = (
        REPOSITORY_ROOT / "scripts" / "evidence_closure_demo.sh"
    ).read_text(encoding="utf-8")
    powershell_wrapper = (
        REPOSITORY_ROOT / "scripts" / "evidence_closure_demo.ps1"
    ).read_text(encoding="utf-8")
    assert shell_wrapper.splitlines()[1] == (
        'python "$(dirname "$0")/evidence_closure_demo.py" "$@"'
    )
    assert powershell_wrapper.splitlines()[0] == (
        '& python "$PSScriptRoot\\evidence_closure_demo.py" @args'
    )

    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "evidence-closure-demo-output*/" in ignore.splitlines()
    for output in (
        "evidence-closure-demo-output/result.json",
        "evidence-closure-demo-output.previous.1/result.json",
    ):
        subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", output],
            cwd=REPOSITORY_ROOT,
            check=True,
        )


def test_contributing_explains_a_red_compatibility_job() -> None:
    text = " ".join(
        (REPOSITORY_ROOT / "CONTRIBUTING.md")
        .read_text(encoding="utf-8")
        .split()
    )
    for phrase in (
        "compatibility (Python X.Y)",
        "fresh dependency resolution",
        "full suite",
        "Python 3.11 lock",
        "weakening the check",
    ):
        assert phrase in text
