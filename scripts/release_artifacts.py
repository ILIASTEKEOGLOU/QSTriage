"""Deterministic release-artifact helpers for QSTriage.

This module is release tooling, not part of the QSTriage runtime package.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
from typing import BinaryIO, Iterable

_SHA256_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<name>[^\\/\r\n]+)$")


class ReleaseArtifactError(ValueError):
    """Raised when a release artifact violates the deterministic contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member_name(name: str) -> str:
    candidate = PurePosixPath(name)
    if not name or name.startswith("/") or ".." in candidate.parts:
        raise ReleaseArtifactError(f"unsafe sdist member path: {name!r}")
    if "\\" in name:
        raise ReleaseArtifactError(f"non-POSIX sdist member path: {name!r}")
    return candidate.as_posix()


def _canonical_member(member: tarfile.TarInfo, epoch: int) -> tarfile.TarInfo:
    name = _safe_member_name(member.name)
    if not (member.isfile() or member.isdir()):
        raise ReleaseArtifactError(
            f"unsupported sdist member type for deterministic release: {name!r}"
        )

    canonical = copy.copy(member)
    canonical.name = name
    canonical.mtime = epoch
    canonical.uid = 0
    canonical.gid = 0
    canonical.uname = ""
    canonical.gname = ""
    canonical.pax_headers = {}
    canonical.linkname = ""

    if canonical.isdir():
        canonical.mode = 0o755
        canonical.size = 0
    else:
        canonical.mode = 0o755 if member.mode & 0o111 else 0o644

    return canonical


def normalize_sdist(path: Path, epoch: int) -> None:
    """Rewrite a gzip-compressed source distribution deterministically."""

    if epoch < 0:
        raise ReleaseArtifactError("SOURCE_DATE_EPOCH must be non-negative")
    if not path.is_file():
        raise ReleaseArtifactError(f"sdist does not exist: {path}")

    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, mode="r:gz") as source:
        for member in source.getmembers():
            canonical = _canonical_member(member, epoch)
            payload: bytes | None = None
            if member.isfile():
                extracted = source.extractfile(member)
                if extracted is None:
                    raise ReleaseArtifactError(
                        f"unable to read sdist member: {member.name!r}"
                    )
                payload = extracted.read()
                if len(payload) != member.size:
                    raise ReleaseArtifactError(
                        f"sdist member size mismatch: {member.name!r}"
                    )
            entries.append((canonical, payload))

    entries.sort(key=lambda item: item[0].name)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)

    try:
        with temporary.open("wb") as raw_output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as gzip_output:
                with tarfile.open(
                    fileobj=gzip_output,
                    mode="w",
                    format=tarfile.GNU_FORMAT,
                ) as destination:
                    for member, payload in entries:
                        stream: BinaryIO | None = None
                        if payload is not None:
                            stream = io.BytesIO(payload)
                        destination.addfile(member, stream)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _release_files(directory: Path, output_name: str) -> list[Path]:
    files = [
        path
        for path in directory.iterdir()
        if path.is_file() and path.name != output_name
    ]
    if not files:
        raise ReleaseArtifactError(f"no release files found in {directory}")
    return sorted(files, key=lambda path: path.name)


def write_checksums(directory: Path, output: Path) -> None:
    """Write a deterministic SHA-256 manifest for immediate child files."""

    directory = directory.resolve()
    output = output.resolve()
    if output.parent != directory:
        raise ReleaseArtifactError("checksum manifest must be inside its artifact directory")

    lines = [
        f"{_sha256(path)}  {path.name}\n"
        for path in _release_files(directory, output.name)
    ]
    output.write_text("".join(lines), encoding="utf-8", newline="\n")


def _parse_checksum_lines(lines: Iterable[str]) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        match = _SHA256_LINE.fullmatch(line)
        if match is None:
            raise ReleaseArtifactError(
                f"invalid SHA256SUMS line {line_number}: {line!r}"
            )
        name = match.group("name")
        if name in seen:
            raise ReleaseArtifactError(f"duplicate SHA256SUMS entry: {name!r}")
        seen.add(name)
        parsed.append((match.group("digest"), name))
    if not parsed:
        raise ReleaseArtifactError("SHA256SUMS is empty")
    return parsed


def verify_checksums(manifest: Path) -> None:
    """Verify every entry in a strict SHA-256 manifest."""

    entries = _parse_checksum_lines(
        manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    )
    for expected, name in entries:
        path = manifest.parent / name
        if not path.is_file():
            raise ReleaseArtifactError(f"missing release artifact: {name}")
        actual = _sha256(path)
        if actual != expected:
            raise ReleaseArtifactError(
                f"checksum mismatch for {name}: expected {expected}, got {actual}"
            )


def compare_directories(first: Path, second: Path) -> None:
    """Require two release directories to contain identical bytes."""

    first_files = {
        path.relative_to(first).as_posix(): path
        for path in first.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path
        for path in second.rglob("*")
        if path.is_file()
    }

    if first_files.keys() != second_files.keys():
        missing_from_first = sorted(second_files.keys() - first_files.keys())
        missing_from_second = sorted(first_files.keys() - second_files.keys())
        raise ReleaseArtifactError(
            "release file sets differ; "
            f"missing from first={missing_from_first}, "
            f"missing from second={missing_from_second}"
        )

    mismatches = [
        name
        for name in sorted(first_files)
        if _sha256(first_files[name]) != _sha256(second_files[name])
    ]
    if mismatches:
        raise ReleaseArtifactError(
            f"release artifacts are not byte-for-byte reproducible: {mismatches}"
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser(
        "normalize-sdist", help="normalize one .tar.gz source distribution"
    )
    normalize.add_argument("path", type=Path)
    normalize.add_argument("--epoch", type=int, required=True)

    checksums = subparsers.add_parser(
        "checksums", help="write deterministic SHA256SUMS"
    )
    checksums.add_argument("directory", type=Path)
    checksums.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify-checksums", help="verify SHA256SUMS")
    verify.add_argument("manifest", type=Path)

    compare = subparsers.add_parser(
        "compare", help="compare two release directories byte-for-byte"
    )
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "normalize-sdist":
            normalize_sdist(args.path, args.epoch)
        elif args.command == "checksums":
            write_checksums(args.directory, args.output)
        elif args.command == "verify-checksums":
            verify_checksums(args.manifest)
        elif args.command == "compare":
            compare_directories(args.first, args.second)
        else:  # pragma: no cover - argparse guarantees the command set
            parser.error(f"unsupported command: {args.command}")
    except (OSError, tarfile.TarError, ReleaseArtifactError) as exc:
        print(f"release artifact error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
