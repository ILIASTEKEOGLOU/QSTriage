from pathlib import Path

import pytest

from qstriage.limits import (
    MAX_YAML_NESTING_DEPTH,
    ResourceLimitError,
    TraversalBudget,
    load_yaml_limited,
    read_text_limited,
)


def test_read_text_limited_rejects_file_larger_than_budget(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    path.write_bytes(b"x" * 9)

    with pytest.raises(ResourceLimitError, match="supported size limit of 8 bytes"):
        read_text_limited(path, max_bytes=8, label="Test file")


def test_read_text_limited_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "invalid.txt"
    path.write_bytes(b"\xff")

    with pytest.raises(ValueError, match="valid UTF-8"):
        read_text_limited(path, max_bytes=8, label="Test file")


def test_load_yaml_limited_rejects_aliases() -> None:
    payload = "base: &base\n  value: 1\ncopy: *base\n"

    with pytest.raises(ResourceLimitError, match="YAML aliases"):
        load_yaml_limited(payload, label="Inventory YAML")


def test_load_yaml_limited_rejects_excessive_nesting() -> None:
    payload = "value: " + ("[" * (MAX_YAML_NESTING_DEPTH + 1)) + "0" + ("]" * (MAX_YAML_NESTING_DEPTH + 1))

    with pytest.raises(ResourceLimitError, match="nesting depth"):
        load_yaml_limited(payload, label="Inventory YAML")


def test_traversal_budget_rejects_excess_work() -> None:
    budget = TraversalBudget(limit=2)
    budget.consume(operation="Test graph operation")
    budget.consume(operation="Test graph operation")

    with pytest.raises(ResourceLimitError, match="graph traversal budget"):
        budget.consume(operation="Test graph operation")


def test_load_yaml_limited_rejects_duplicate_mapping_keys() -> None:
    payload = "assets: []\nassets: []\n"

    with pytest.raises(ValueError, match="duplicate mapping key 'assets'"):
        load_yaml_limited(payload, label="Inventory YAML")
