from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from qstriage.file_output import UnsafeOutputError, write_private_text


def test_write_private_text_creates_owner_only_file(tmp_path: Path) -> None:
    output = tmp_path / "private" / "report.txt"

    written = write_private_text(output, "decision evidence\n")

    assert written == output
    assert output.read_text(encoding="utf-8") == "decision evidence\n"
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700


def test_write_private_text_refuses_existing_file_without_overwrite(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.txt"
    output.write_text("original", encoding="utf-8")

    with pytest.raises(UnsafeOutputError, match="pass --overwrite"):
        write_private_text(output, "replacement")

    assert output.read_text(encoding="utf-8") == "original"


def test_write_private_text_replaces_existing_file_only_when_explicit(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.txt"
    output.write_text("original", encoding="utf-8")

    write_private_text(output, "replacement", overwrite=True)

    assert output.read_text(encoding="utf-8") == "replacement"
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_write_private_text_refuses_protected_input_collision(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "inventory.yaml"
    input_path.write_text("assets: []\n", encoding="utf-8")

    with pytest.raises(UnsafeOutputError, match="protected input/config path"):
        write_private_text(
            input_path,
            "replacement",
            overwrite=True,
            protected_paths=(input_path,),
        )

    assert input_path.read_text(encoding="utf-8") == "assets: []\n"


def test_write_private_text_refuses_symlink_and_preserves_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("protected", encoding="utf-8")
    output = tmp_path / "report.txt"

    try:
        output.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("Symlink creation is not available in this environment")

    with pytest.raises(UnsafeOutputError, match="symlink output path"):
        write_private_text(output, "replacement", overwrite=True)

    assert target.read_text(encoding="utf-8") == "protected"
    assert output.is_symlink()


def test_failed_atomic_replace_preserves_existing_file_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.txt"
    output.write_text("original", encoding="utf-8")

    def fail_replace(source: object, destination: object) -> None:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replacement failure"):
        write_private_text(output, "replacement", overwrite=True)

    assert output.read_text(encoding="utf-8") == "original"
    assert list(tmp_path.glob(".report.txt.*.tmp")) == []


def test_atomic_no_clobber_publication_resists_destination_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.txt"
    real_link = os.link

    def race_link(source: object, destination: object) -> None:
        Path(destination).write_text("racing writer", encoding="utf-8")
        real_link(source, destination)

    monkeypatch.setattr(os, "link", race_link)

    with pytest.raises(UnsafeOutputError, match="already exists"):
        write_private_text(output, "qstriage output")

    assert output.read_text(encoding="utf-8") == "racing writer"
    assert list(tmp_path.glob(".report.txt.*.tmp")) == []


def test_write_private_text_refuses_directory_destination(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()

    with pytest.raises(UnsafeOutputError, match="not a regular file"):
        write_private_text(output, "replacement", overwrite=True)
