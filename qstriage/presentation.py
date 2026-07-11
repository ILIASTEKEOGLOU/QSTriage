from __future__ import annotations

import html
import re
import unicodedata
from typing import Any


_MARKDOWN_INLINE_SPECIALS = re.compile(r"([`*_\[\]|])")
_BACKTICK_RUN = re.compile(r"`+")


def sanitize_terminal_text(value: Any) -> str:
    """Return a visible, single-line representation safe for terminal output.

    Untrusted control and Unicode format characters are rendered as explicit
    escape sequences instead of being emitted to the terminal. Newlines and
    tabs are represented visibly so a value cannot forge additional rows or
    lines in analyst-facing output.
    """

    return _neutralize_controls(str(value), preserve_newlines=False)


def markdown_inline(value: Any) -> str:
    """Escape untrusted text for a Markdown inline context."""

    text = sanitize_terminal_text(value)
    text = html.escape(text, quote=False)
    return _MARKDOWN_INLINE_SPECIALS.sub(r"\\\1", text)


def markdown_table_cell(value: Any) -> str:
    """Escape untrusted text for a Markdown table cell."""

    return markdown_inline(value)


def markdown_code_span(value: Any) -> str:
    """Render untrusted single-line text as a safely delimited code span."""

    text = sanitize_terminal_text(value)
    fence = "`" * max(1, _longest_backtick_run(text) + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def markdown_code_block(value: Any, *, language: str = "text") -> str:
    """Render text in a fence longer than every backtick run in the content."""

    text = _neutralize_controls(str(value), preserve_newlines=True)
    fence = "`" * max(3, _longest_backtick_run(text) + 1)
    return f"{fence}{language}\n{text}\n{fence}"


def _neutralize_controls(value: str, *, preserve_newlines: bool) -> str:
    rendered: list[str] = []

    for character in value:
        codepoint = ord(character)
        category = unicodedata.category(character)

        if character == "\n" and preserve_newlines:
            rendered.append("\n")
        elif character == "\n":
            rendered.append(r"\n")
        elif character == "\r":
            rendered.append(r"\r")
        elif character == "\t":
            rendered.append(r"\t")
        elif category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            rendered.append(_escape_codepoint(codepoint))
        else:
            rendered.append(character)

    return "".join(rendered)


def _escape_codepoint(codepoint: int) -> str:
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04x}"
    return f"\\U{codepoint:08x}"


def _longest_backtick_run(value: str) -> int:
    return max((len(match.group(0)) for match in _BACKTICK_RUN.finditer(value)), default=0)
