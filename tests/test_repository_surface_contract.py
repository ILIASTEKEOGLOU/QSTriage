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


def _documented_release() -> str:
    """Release whose tagged documentation the README links to.

    A release links to its own tag. Between releases the package version is
    ``X.Y.Z.dev0``, which is never tagged, so the README keeps linking to the
    newest release listed in ``CHANGELOG.md``.
    """

    if not __version__.endswith(".dev0"):
        return __version__
    changelog = (REPOSITORY_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = re.search(r"^## v(\d+\.\d+\.\d+) - ", changelog, re.MULTILINE)
    assert newest is not None
    return newest.group(1)

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


def test_top_level_hidden_paths_are_limited_to_git_and_github() -> None:
    hidden = {
        path.parts[0]
        for path in _tracked_paths()
        if path.parts and path.parts[0].startswith(".")
    }

    assert hidden <= {".gitattributes", ".github", ".gitignore"}


def test_readme_release_references_match_the_package_version() -> None:
    readme = README.read_text(encoding="utf-8")
    release_refs = re.findall(r"/blob/v(\d+\.\d+\.\d+)/", readme)
    release_tag_examples = re.findall(r"release_tag=v(\d+\.\d+\.\d+)", readme)

    assert release_refs
    assert set(release_refs) == {_documented_release()}
    assert release_tag_examples
    assert set(release_tag_examples) == {_documented_release()}

    relative_docs = [
        target
        for target in _markdown_targets(readme)
        if target.startswith(("docs/", "./docs/", "../docs/"))
    ]
    assert relative_docs == []

    blob_targets = _repository_blob_targets(readme)
    assert blob_targets
    assert {ref for _, ref in blob_targets} == {f"v{_documented_release()}"}


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

    assert {ref for _, ref in links} == {f"v{_documented_release()}"}


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


# Tracked text files are ASCII. Each exception below names the exact lines
# (stripped of surrounding whitespace) that may contain other characters; a
# new non-ASCII line anywhere else, including elsewhere in the same file,
# fails. Escapes keep this file itself ASCII.
NON_ASCII_LINES_ALLOWED: dict[str, set[str]] = {
    # Official EU classification marking, quoted verbatim.
    "design/context-resolution.md": {
        "| `eu-euci` | `TR\u00c8S SECRET UE/EU TOP SECRET`, `SECRET UE/EU SECRET`, "
        "`CONFIDENTIEL UE/EU CONFIDENTIAL`, `RESTREINT UE/EU RESTRICTED` | "
        "sensitive | Council Decision 2013/488/EU, Article 2(2) |",
    },
    # Box-drawing characters are the output format of `qstriage graph`.
    "qstriage/graph.py": {
        'branch="\u251c\u2500\u2500",',
        'last_branch="\u2514\u2500\u2500",',
        'continuation="\u2502   ",',
        'edge_arrow="\u2500\u2500>",',
        '_UNICODE_TREE_CHARACTERS = "\u251c\u2514\u2502\u2500"',
    },
    # Source titles enter the policy pack hash; changing them needs a new
    # policy pack version.
    "qstriage/policy.py": {
        'title="NIST FIPS 203 \u2014 ML-KEM",',
        'title="NIST FIPS 204 \u2014 ML-DSA",',
        'title="NIST FIPS 205 \u2014 SLH-DSA",',
        '"NIST SP 800-131A Rev. 3 IPD \u2014 Transitioning the Use of "',
        'title="NIST SP 800-227 \u2014 Recommendations for Key-Encapsulation Mechanisms",',
        '"RFC 10024 \u2014 Post-Quantum Traditional (PQ/T) Hybrid Key Agreement "',
        'title="NIST CSWP 39 Update 1 \u2014 Considerations for Achieving Crypto Agility",',
    },
    # Test data that exercises non-ASCII handling on purpose.
    "tests/test_canonical_json.py": {
        "'\"string\":\"\u20ac$\\\\u000f\\\\nA\\'B\\\\\"\\\\\\\\\\\\\\\\\\\\\"/\"}'",
    },
    "tests/test_context_resolver.py": {
        "assert display_value(\"pii\u200b\") == '\"pii<U+200B>\"'",
        "assert display_value(\"a\u202eb\") == '\"a<U+202E>b\"'",
    },
    "tests/test_graph.py": {
        'assert "\u2502   \u2514\u2500\u2500(database, mTLS, w=0.80)\u2500\u2500> [customer-db]" in rendered',
        'assert "\u251c\u2500\u2500(auth, HTTPS/TLS1.3, w=0.90)\u2500\u2500> [auth-service]" in rendered',
        'assert "\u2514\u2500\u2500(api_call, HTTPS/TLS1.3, w=0.75)\u2500\u2500> [payments-api]" in rendered',
        'assert "\u251c" not in rendered',
        'assert "\u2514" not in rendered',
        'assert "\u2502" not in rendered',
        'assert "\u2500" not in rendered',
    },
    "tests/test_policy.py": {
        'title="NIST FIPS 203 \u2014 ML-KEM",',
    },
}


def test_tracked_text_files_are_ascii_except_named_lines() -> None:
    findings: list[str] = []
    seen: dict[str, set[str]] = {}
    for path in sorted(_tracked_paths()):
        source = REPOSITORY_ROOT / path
        if source.is_symlink():
            continue
        data = source.read_bytes()
        if b"\0" in data or data.isascii():
            continue
        key = path.as_posix()
        allowed = NON_ASCII_LINES_ALLOWED.get(key, set())
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            findings.append(f"{key}: not UTF-8 text")
            continue
        for number, line in enumerate(lines, start=1):
            if line.isascii():
                continue
            stripped = line.strip()
            if stripped in allowed:
                seen.setdefault(key, set()).add(stripped)
                continue
            characters = sorted({f"U+{ord(c):04X}" for c in line if ord(c) > 127})
            findings.append(f"{key}:{number}: non-ASCII {', '.join(characters)}")

    # An exception that no longer matches must be removed, so the list
    # cannot grow stale and silently allow the line again later.
    for key, lines in NON_ASCII_LINES_ALLOWED.items():
        for line in sorted(lines - seen.get(key, set())):
            findings.append(f"{key}: allowed line no longer present: {ascii(line)}")

    assert findings == []
