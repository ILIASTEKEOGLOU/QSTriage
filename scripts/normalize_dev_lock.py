from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


DEFAULT_LOCK_PATH = Path("requirements/py311.lock")
WINDOWS_MARKER = '; sys_platform == "win32"'
_REQUIREMENT_LINE = re.compile(r"^pywin32[^\r\n]*$", re.MULTILINE)
_UNMARKED_LINE = re.compile(r"^(pywin32==[^\s;]+)(\s+\\)$")
_MARKED_LINE = re.compile(
    r'^pywin32==[^\s;]+ ; sys_platform == "win32"\s+\\$'
)


def normalize_dev_lock(lock_path: str | Path = DEFAULT_LOCK_PATH) -> bool:
    """Add the canonical Windows marker to exactly one pywin32 requirement."""

    path = Path(lock_path)
    original = path.read_bytes()
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"Lock file is not valid UTF-8: {path}") from error

    matches = list(_REQUIREMENT_LINE.finditer(text))
    if not matches:
        raise ValueError("Expected exactly one pywin32 requirement; found none.")
    if len(matches) > 1:
        raise ValueError(
            f"Expected exactly one pywin32 requirement; found {len(matches)}."
        )

    line = matches[0].group(0)
    if _MARKED_LINE.fullmatch(line):
        return False
    unmarked = _UNMARKED_LINE.fullmatch(line)
    if unmarked is None:
        raise ValueError(
            f"pywin32 requirement has an unexpected or conflicting marker: {line}"
        )

    normalized_line = f"{unmarked.group(1)} {WINDOWS_MARKER}{unmarked.group(2)}"
    normalized = text[: matches[0].start()] + normalized_line + text[matches[0].end() :]
    path.write_bytes(normalized.encode("utf-8"))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preserve the Windows-only marker in the development lock."
    )
    parser.add_argument("lock_path", nargs="?", default=DEFAULT_LOCK_PATH)
    arguments = parser.parse_args()
    try:
        normalize_dev_lock(arguments.lock_path)
    except (OSError, ValueError) as error:
        print(f"normalize_dev_lock.py: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
