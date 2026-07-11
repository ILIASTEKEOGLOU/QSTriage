from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent, MappingEndEvent, MappingStartEvent, SequenceEndEvent, SequenceStartEvent


MIB = 1024 * 1024

MAX_INVENTORY_FILE_BYTES = 10 * MIB
MAX_CBOM_FILE_BYTES = 32 * MIB
MAX_CONFIG_FILE_BYTES = 1 * MIB

MAX_ASSETS = 1_000
MAX_DEPENDENCIES = 10_000
MAX_SCENARIOS = 100
MAX_SIMULATION_RESULTS = 20_000
MAX_CBOM_COMPONENTS = 10_000

MAX_IDENTIFIER_LENGTH = 256
MAX_TEXT_LENGTH = 512
MAX_NOTES_LENGTH = 4_096

MAX_YAML_EVENTS = 200_000
MAX_YAML_NESTING_DEPTH = 64

MAX_GRAPH_TRAVERSAL_STATES = 250_000
MAX_GRAPH_RENDER_LINES = 5_000
MAX_CRITICAL_PATHS = 10_000




class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ValueError("YAML mapping keys must be scalar and hashable.") from error
        if duplicate:
            raise ValueError(f"YAML contains duplicate mapping key {key!r}.")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class ResourceLimitError(ValueError):
    """Raised when untrusted input exceeds a documented processing budget."""


def read_bytes_limited(
    path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read one file once without exceeding ``max_bytes``.

    The size is checked before and during the read so a file that changes after
    ``stat`` cannot cause an unbounded allocation. The returned bytes are the
    exact material that callers may both parse and hash.
    """

    source = Path(path)
    size = source.stat().st_size
    if size > max_bytes:
        raise ResourceLimitError(
            f"{label} exceeds the supported size limit of {max_bytes} bytes "
            f"(observed {size} bytes)."
        )

    with source.open("rb") as file:
        data = file.read(max_bytes + 1)

    if len(data) > max_bytes:
        raise ResourceLimitError(
            f"{label} exceeds the supported size limit of {max_bytes} bytes."
        )

    return data


def decode_utf8(data: bytes, *, label: str) -> str:
    """Decode previously captured source bytes as UTF-8."""

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be valid UTF-8 text.") from error


def read_text_limited(
    path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> str:
    """Read and decode one bounded UTF-8 text file."""

    data = read_bytes_limited(path, max_bytes=max_bytes, label=label)
    return decode_utf8(data, label=label)


def load_yaml_limited(text: str, *, label: str) -> Any:
    """Parse YAML after enforcing event, nesting, and alias limits."""

    depth = 0
    event_count = 0

    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        event_count += 1
        if event_count > MAX_YAML_EVENTS:
            raise ResourceLimitError(
                f"{label} exceeds the supported YAML event limit of "
                f"{MAX_YAML_EVENTS}."
            )

        if isinstance(event, AliasEvent):
            raise ResourceLimitError(
                f"{label} uses YAML aliases, which are not supported for "
                "untrusted input. Expand the referenced value explicitly."
            )

        if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
            depth += 1
            if depth > MAX_YAML_NESTING_DEPTH:
                raise ResourceLimitError(
                    f"{label} exceeds the supported YAML nesting depth of "
                    f"{MAX_YAML_NESTING_DEPTH}."
                )
        elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
            depth = max(0, depth - 1)

    return yaml.load(text, Loader=_UniqueKeySafeLoader)


class TraversalBudget:
    """Shared deterministic budget for graph traversal work."""

    def __init__(self, limit: int = MAX_GRAPH_TRAVERSAL_STATES) -> None:
        if limit < 1:
            raise ValueError("Traversal budget limit must be positive.")
        self.limit = limit
        self.used = 0

    def consume(self, amount: int = 1, *, operation: str) -> None:
        if amount < 0:
            raise ValueError("Traversal budget amount cannot be negative.")
        self.used += amount
        if self.used > self.limit:
            raise ResourceLimitError(
                f"{operation} exceeded the supported graph traversal budget of "
                f"{self.limit} states. Reduce dependency density or split the inventory."
            )
