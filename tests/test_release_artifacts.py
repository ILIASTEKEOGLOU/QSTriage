from __future__ import annotations

import gzip
import io
from pathlib import Path
import tarfile

import pytest

from scripts.release_artifacts import (
    ReleaseArtifactError,
    compare_directories,
    normalize_sdist,
    verify_checksums,
    write_checksums,
)


def _write_sdist(path: Path, *, mtime: int, unsafe_name: str | None = None) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename=path.name,
            mode="wb",
            fileobj=raw,
            mtime=mtime,
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                root = tarfile.TarInfo("qstriage-1.1.0")
                root.type = tarfile.DIRTYPE
                root.mode = 0o775
                root.mtime = mtime + 0.5
                archive.addfile(root)

                name = unsafe_name or "qstriage-1.1.0/qstriage/example.py"
                payload = b"VALUE = 1\n"
                source = tarfile.TarInfo(name)
                source.size = len(payload)
                source.mode = 0o664
                source.mtime = mtime + 0.25
                archive.addfile(source, io.BytesIO(payload))


def test_sdist_normalization_is_byte_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, mtime=100)
    _write_sdist(second, mtime=900)

    normalize_sdist(first, epoch=42)
    normalize_sdist(second, epoch=42)

    assert first.read_bytes() == second.read_bytes()

    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == sorted(
        member.name for member in members
    )
    assert {member.mtime for member in members} == {42}
    assert {member.uid for member in members} == {0}
    assert {member.gid for member in members} == {0}
    assert all(not member.pax_headers for member in members)


def test_sdist_normalization_rejects_unsafe_member_path(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    _write_sdist(archive, mtime=100, unsafe_name="../escape.py")

    with pytest.raises(ReleaseArtifactError, match="unsafe sdist member path"):
        normalize_sdist(archive, epoch=42)


def test_checksum_manifest_is_sorted_and_verifiable(tmp_path: Path) -> None:
    (tmp_path / "z.whl").write_bytes(b"wheel")
    (tmp_path / "a.tar.gz").write_bytes(b"sdist")
    manifest = tmp_path / "SHA256SUMS"

    write_checksums(tmp_path, manifest)

    lines = manifest.read_text(encoding="utf-8").splitlines()
    assert lines[0].endswith("  a.tar.gz")
    assert lines[1].endswith("  z.whl")
    verify_checksums(manifest)


def test_checksum_verification_rejects_tampering(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"original")
    manifest = tmp_path / "SHA256SUMS"
    write_checksums(tmp_path, manifest)

    artifact.write_bytes(b"changed")

    with pytest.raises(ReleaseArtifactError, match="checksum mismatch"):
        verify_checksums(manifest)


def test_directory_comparison_requires_identical_bytes(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "artifact.whl").write_bytes(b"same")
    (second / "artifact.whl").write_bytes(b"same")

    compare_directories(first, second)

    (second / "artifact.whl").write_bytes(b"different")
    with pytest.raises(ReleaseArtifactError, match="not byte-for-byte reproducible"):
        compare_directories(first, second)
