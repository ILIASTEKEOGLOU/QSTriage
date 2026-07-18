from pathlib import Path

import pytest

from scripts.normalize_dev_lock import normalize_dev_lock


def test_committed_dev_lock_marks_pywin32_as_windows_only() -> None:
    lock = Path("requirements/py311.lock").read_text(encoding="utf-8")

    assert 'pywin32==312 ; sys_platform == "win32" \\' in lock


def test_normalizer_adds_marker_and_is_byte_idempotent(tmp_path: Path) -> None:
    lock = tmp_path / "dev.lock"
    lock.write_bytes(
        b"package==1.0 \\\n"
        b"    --hash=sha256:aaa\n"
        b"pywin32==312 \\\n"
        b"    --hash=sha256:bbb\n"
        b"    # via mcp\n"
    )

    assert normalize_dev_lock(lock) is True
    first = lock.read_bytes()
    assert b'pywin32==312 ; sys_platform == "win32" \\\n' in first
    assert normalize_dev_lock(lock) is False
    assert lock.read_bytes() == first
    assert b"\r\n" not in first


@pytest.mark.parametrize(
    "line",
    [
        'pywin32==312 ; sys_platform == "linux" \\\n',
        'pywin32==312 ; python_version >= "3.11" \\\n',
    ],
)
def test_normalizer_rejects_conflicting_marker(tmp_path: Path, line: str) -> None:
    lock = tmp_path / "dev.lock"
    lock.write_text(line, encoding="utf-8", newline="")

    with pytest.raises(ValueError, match="conflicting marker"):
        normalize_dev_lock(lock)


@pytest.mark.parametrize(
    "content, expected",
    [
        ("package==1.0\n", "found none"),
        ("pywin32==311 \\\npywin32==312 \\\n", "found 2"),
    ],
)
def test_normalizer_rejects_missing_or_duplicate_entries(
    tmp_path: Path,
    content: str,
    expected: str,
) -> None:
    lock = tmp_path / "dev.lock"
    lock.write_text(content, encoding="utf-8", newline="")

    with pytest.raises(ValueError, match=expected):
        normalize_dev_lock(lock)
