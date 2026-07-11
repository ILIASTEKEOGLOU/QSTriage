from __future__ import annotations

import errno
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700


class UnsafeOutputError(ValueError):
    """Raised when an output path violates the safe-write contract."""


def write_private_text(
    output_path: str | Path,
    text: str,
    *,
    overwrite: bool = False,
    protected_paths: Iterable[str | Path | None] = (),
    encoding: str = "utf-8",
) -> Path:
    """Write text through an atomic, private, symlink-safe output boundary.

    Existing files are never replaced unless ``overwrite`` is explicitly true.
    Output paths that resolve to a protected input/config path are rejected.
    A complete temporary file is fsynced before atomic publication, and newly
    published files use owner-only permissions on platforms that support them.
    """

    destination = Path(output_path)
    payload = text.encode(encoding)
    _write_private_bytes(
        destination,
        payload,
        overwrite=overwrite,
        protected_paths=protected_paths,
    )
    return destination


def _write_private_bytes(
    destination: Path,
    payload: bytes,
    *,
    overwrite: bool,
    protected_paths: Iterable[str | Path | None],
) -> None:
    physical_parent = destination.parent.resolve(strict=False)
    physical_destination = physical_parent / destination.name

    _ensure_private_directory(physical_parent)
    _reject_protected_destination(physical_destination, protected_paths)
    _validate_destination(physical_destination, overwrite=overwrite)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=physical_parent,
    )
    temporary_path = Path(temporary_name)

    try:
        os.chmod(temporary_path, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as temporary_file:
            descriptor = -1
            temporary_file.write(payload)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        _publish_temporary_file(
            temporary_path,
            physical_destination,
            overwrite=overwrite,
        )
        _fsync_directory(physical_parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise


def _publish_temporary_file(
    temporary_path: Path,
    destination: Path,
    *,
    overwrite: bool,
) -> None:
    if overwrite:
        if destination.is_symlink():
            raise UnsafeOutputError(
                f"Refusing to replace symlink output path: {destination}"
            )
        if destination.exists() and not destination.is_file():
            raise UnsafeOutputError(
                f"Output path is not a regular file: {destination}"
            )
        os.replace(temporary_path, destination)
        return

    try:
        os.link(temporary_path, destination)
    except FileExistsError as error:
        raise UnsafeOutputError(
            f"Output already exists; pass --overwrite to replace it: {destination}"
        ) from error
    except OSError as error:
        unsupported_errors = {
            errno.EPERM,
            errno.EACCES,
            getattr(errno, "ENOTSUP", -1),
            getattr(errno, "EOPNOTSUPP", -1),
        }
        if error.errno in unsupported_errors:
            raise UnsafeOutputError(
                "The destination filesystem does not support atomic no-clobber "
                f"publication for: {destination}"
            ) from error
        raise
    else:
        temporary_path.unlink()


def _validate_destination(destination: Path, *, overwrite: bool) -> None:
    if destination.is_symlink():
        raise UnsafeOutputError(
            f"Refusing to write through symlink output path: {destination}"
        )

    if destination.exists() and not destination.is_file():
        raise UnsafeOutputError(f"Output path is not a regular file: {destination}")

    if destination.exists() and not overwrite:
        raise UnsafeOutputError(
            f"Output already exists; pass --overwrite to replace it: {destination}"
        )


def _reject_protected_destination(
    destination: Path,
    protected_paths: Iterable[str | Path | None],
) -> None:
    destination_identity = _path_identity(destination)

    for protected_path in protected_paths:
        if protected_path is None:
            continue
        protected = Path(protected_path)
        if destination_identity == _path_identity(protected):
            raise UnsafeOutputError(
                "Output path collides with a protected input/config path: "
                f"{destination}"
            )


def _path_identity(path: Path) -> str:
    resolved = path.resolve(strict=False)
    return os.path.normcase(os.path.abspath(os.fspath(resolved)))


def _ensure_private_directory(directory: Path) -> None:
    missing: list[Path] = []
    current = directory

    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent

    if current.exists() and not current.is_dir():
        raise UnsafeOutputError(f"Output parent is not a directory: {current}")

    for path in reversed(missing):
        try:
            path.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            if not path.is_dir():
                raise UnsafeOutputError(
                    f"Output parent is not a directory: {path}"
                )
        else:
            try:
                os.chmod(path, PRIVATE_DIRECTORY_MODE)
            except OSError:
                # Windows ACLs do not map cleanly to POSIX mode bits. The file
                # boundary still uses exclusive/atomic publication semantics.
                pass


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return

    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
