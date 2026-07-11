from qstriage.presentation import (
    markdown_code_block,
    markdown_code_span,
    markdown_inline,
    markdown_table_cell,
    sanitize_terminal_text,
)


def test_sanitize_terminal_text_makes_controls_visible() -> None:
    value = "name\x1b[2J\nnext\t\u202eend\u200d"

    sanitized = sanitize_terminal_text(value)

    assert sanitized == r"name\x1b[2J\nnext\t\u202eend\u200d"
    assert "\x1b" not in sanitized
    assert "\u202e" not in sanitized


def test_sanitize_terminal_text_neutralizes_osc_hyperlinks() -> None:
    value = "open\x1b]8;;https://evil.example\x07click\x1b]8;;\x07close"

    sanitized = sanitize_terminal_text(value)

    assert "\x1b" not in sanitized
    assert "\x07" not in sanitized
    assert r"\x1b]8;;https://evil.example\x07click" in sanitized


def test_markdown_inline_neutralizes_structure_and_raw_html() -> None:
    value = "</td>\n## Forged | [link](x) *bold* _italics_"

    escaped = markdown_inline(value)

    assert "</td>" not in escaped
    assert "\n## Forged" not in escaped
    assert "&lt;/td&gt;" in escaped
    assert r"\|" in escaped
    assert r"\[link\]" in escaped
    assert r"\*bold\*" in escaped
    assert r"\_italics\_" in escaped


def test_markdown_table_cell_escapes_column_delimiters() -> None:
    assert markdown_table_cell("left|right") == r"left\|right"


def test_markdown_code_span_uses_a_longer_delimiter() -> None:
    rendered = markdown_code_span("value```tail")

    assert rendered.startswith("````")
    assert rendered.endswith("````")
    assert "value```tail" in rendered


def test_markdown_code_block_cannot_be_closed_by_content() -> None:
    rendered = markdown_code_block("line\n```text\nforged")

    lines = rendered.splitlines()
    assert lines[0] == "````text"
    assert lines[-1] == "````"
    assert "```text" in rendered
