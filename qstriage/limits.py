from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from yaml.events import AliasEvent, MappingEndEvent, MappingStartEvent, SequenceEndEvent, SequenceStartEvent


MIB = 1024 * 1024

MAX_INVENTORY_FILE_BYTES = 10 * MIB
MAX_CBOM_FILE_BYTES = 32 * MIB
MAX_CONFIG_FILE_BYTES = 1 * MIB
# A legal patch covers up to MAX_ASSETS assets with seven fields and one
# relationship assertion each; with 256-character identifiers and
# 512-character source references that is about 6.9 MiB.
MAX_ENRICHMENT_PATCH_FILE_BYTES = 10 * MIB
MAX_PDR_FILE_BYTES = 64 * MIB

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
MAX_JSON_NESTING_DEPTH = 64

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


class InputStructureError(ValueError):
    """Raised when untrusted input contains text that is not valid Unicode."""


# One JSON string (escape aware) or one structural bracket. Possessive
# quantifiers keep the match linear; strings are skipped so brackets inside
# them are not counted.
_JSON_TOKEN = re.compile(r'"(?:[^"\\]++|\\.)*+"|[\[\]{}]', re.DOTALL)
_SURROGATE = re.compile("[\ud800-\udfff]")


def check_json_nesting(
    text: str,
    *,
    label: str,
    max_depth: int = MAX_JSON_NESTING_DEPTH,
) -> None:
    """Reject JSON text nested deeper than ``max_depth`` before it is parsed.

    The scan is iterative and runs before ``json.loads``, so excessive nesting
    is reported as a limit violation instead of exhausting the interpreter
    stack in the parser or in later processing.
    """

    depth = 0
    for match in _JSON_TOKEN.finditer(text):
        token = match.group()
        if token == "[" or token == "{":
            depth += 1
            if depth > max_depth:
                raise ResourceLimitError(
                    f"{label} exceeds the supported JSON nesting depth of "
                    f"{max_depth} (near character {match.start()})."
                )
        elif token == "]" or token == "}":
            depth = max(0, depth - 1)


def check_structure(value: Any, *, label: str, max_depth: int) -> None:
    """Walk parsed input iteratively and reject excessive depth or lone surrogates.

    Lone surrogate code points (U+D800 to U+DFFF) can be produced by JSON and
    YAML escape sequences but are not Unicode scalar values. They cannot be
    encoded as UTF-8 and RFC 8785 Section 3.2.2.2 requires a canonicalizer to
    stop on them, so they are rejected in keys and values with the location.
    """

    stack: list[tuple[Any, int, tuple[str | int, ...]]] = [(value, 0, ())]
    while stack:
        item, depth, path = stack.pop()
        if path and isinstance(path[-1], str):
            _reject_surrogates(path[-1], label=label, path=path[:-1], is_key=True)
        if isinstance(item, str):
            _reject_surrogates(item, label=label, path=path)
            continue
        if isinstance(item, dict):
            children: Any = item.items()
        elif isinstance(item, list):
            children = enumerate(item)
        else:
            continue
        if depth + 1 > max_depth:
            raise ResourceLimitError(
                f"{label} exceeds the supported nesting depth of {max_depth} "
                f"at {_format_path(path)}."
            )
        # Children are pushed in reverse so the first problem in document
        # order is reported.
        stack.extend(
            reversed([(child, depth + 1, (*path, key)) for key, child in children])
        )


def _reject_surrogates(
    text: str,
    *,
    label: str,
    path: tuple[str | int, ...],
    is_key: bool = False,
) -> None:
    if text.isascii():
        return
    match = _SURROGATE.search(text)
    if match is None:
        return
    where = "a key" if is_key else "a value"
    raise InputStructureError(
        f"{label} has invalid text in {where} at {_format_path(path)}: "
        f"\\u{ord(match.group()):04x} is half of a two-part character escape "
        "(an unpaired surrogate) and is not a character. Replace it with the "
        "intended character."
    )


def _format_path(path: tuple[str | int, ...]) -> str:
    parts = ["$"]
    for part in path:
        parts.append(f"[{part}]" if isinstance(part, int) else f".{part}")
    return "".join(parts)


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

    loader = _UniqueKeySafeLoader(text)
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    check_structure(data, label=label, max_depth=MAX_YAML_NESTING_DEPTH)
    return data


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
