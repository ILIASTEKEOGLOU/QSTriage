from __future__ import annotations

import errno
from pathlib import Path
from typing import Any, Callable, TypeVar

import yaml

try:
    # mcp 2.x renamed FastMCP to MCPServer.
    from mcp.server.mcpserver import MCPServer as _MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:
    # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer
    from mcp.server.fastmcp.exceptions import ToolError

from qstriage.closure import (
    build_gap_manifest,
    build_inventory_comparison,
    build_patch_template,
)
from qstriage.enrichment import (
    load_enrichment_patch,
    validate_enrichment_patch as validate_patch,
)
from qstriage.models import load_inventory


SERVER_INSTRUCTIONS = (
    "READ-ONLY. Never invent evidence. Never approve evidence. Never change risk "
    "scores. Never apply patches. Never authorize migration. Human approval and "
    "deterministic QSTriage remain authoritative. Use these tools only to inspect "
    "gaps, draft empty templates, validate proposed patches, and compare results."
)

mcp = _MCPServer(
    "QSTriage Evidence Closure",
    instructions=SERVER_INSTRUCTIONS,
    log_level="ERROR",
)

T = TypeVar("T")


MAX_ERROR_MESSAGE_LENGTH = 500
# The parser's own description is shortened first, so the file name, line,
# and column always fit in the message.
MAX_PARSER_DETAIL_LENGTH = 200

# Short causes for read failures; the client sees these instead of the
# operating system text, which names the server's absolute path.
_READ_FAILURE_REASONS = {
    errno.EACCES: "permission denied",
    errno.EPERM: "permission denied",
    errno.ENOENT: "file not found",
    errno.EISDIR: "is a directory",
}


def _one_line(text: str) -> str:
    return text.replace("\r", " ").replace("\n", " ")


def _client_message(text: str) -> str:
    return _one_line(text)[:MAX_ERROR_MESSAGE_LENGTH]


def _message_with_path(before: str, path_value: str, after: str) -> str:
    """Build a message that always ends with its cause.

    When the whole text is longer than the limit, only the path is shortened,
    keeping its end (the file name) after "...". The limit applies to the
    QSTriage message; the SDK may add its own prefix.
    """

    before, path_text, after = _one_line(before), _one_line(path_value), _one_line(after)
    room = MAX_ERROR_MESSAGE_LENGTH - len(before) - len(after)
    if len(path_text) > room:
        keep = max(room - 3, 0)
        path_text = "..." + (path_text[-keep:] if keep else "")
    return _client_message(before + path_text + after)


def _safe_call(operation: Callable[[], T]) -> T:
    """Run a tool and turn expected failures into ``ToolError``.

    Both supported SDK majors pass a ``ToolError`` message to the client as
    the tool result (``isError: true``). Any other exception is reported by
    the SDK as an unexpected failure.
    """

    try:
        return operation()
    except ToolError:
        raise
    except ValueError as error:
        raise ToolError(_client_message(str(error))) from None
    except OSError:
        raise ToolError("File access failed.") from None


def _read_confined(path_value: str, loader: Callable[[Path], T]) -> T:
    """Check the path, then read and parse it, naming the file as the client gave it."""

    resolved = _confined_file(path_value)
    try:
        return loader(resolved)
    except OSError as error:
        reason = _READ_FAILURE_REASONS.get(error.errno, "the file could not be read")
        raise ToolError(_message_with_path("Cannot read ", path_value, f": {reason}.")) from None
    except yaml.YAMLError as error:
        raise ToolError(_message_with_path("YAML is malformed in ", path_value, _yaml_detail(error))) from None


def _yaml_detail(error: yaml.YAMLError) -> str:
    mark = getattr(error, "problem_mark", None)
    problem = getattr(error, "problem", None)
    where = f" near line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
    if not problem:
        return f"{where}."
    problem = _one_line(problem)
    if len(problem) > MAX_PARSER_DETAIL_LENGTH:
        return f"{where}: {problem[: MAX_PARSER_DETAIL_LENGTH - 3]}..."
    return f"{where}: {problem}."


def _confined_file(path_value: str) -> Path:
    root = Path.cwd().resolve(strict=True)
    candidate = Path(path_value)
    unresolved = candidate if candidate.is_absolute() else root / candidate
    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise ToolError(
            _message_with_path(
                "File is unavailable inside the working directory: ", path_value, ""
            )
        ) from error
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("Path resolves outside the MCP working directory.") from None
    if not resolved.is_file():
        raise ToolError(
            _message_with_path("Path is not an existing regular file: ", path_value, "")
        )
    return resolved


@mcp.tool()
def inspect_evidence_gaps(inventory_path: str) -> dict[str, Any]:
    """Return the structured unresolved evidence-gap manifest for an inventory."""
    return _safe_call(
        lambda: build_gap_manifest(
            _read_confined(inventory_path, load_inventory)
        ).model_dump(mode="json")
    )


@mcp.tool()
def generate_patch_template(inventory_path: str) -> str:
    """Return deterministic YAML containing empty skeletons for unresolved gaps."""
    return _safe_call(
        lambda: build_patch_template(_read_confined(inventory_path, load_inventory))
    )


@mcp.tool()
def validate_enrichment_patch(
    inventory_path: str,
    patch_path: str,
) -> dict[str, Any]:
    """Validate a patch against an inventory without applying or writing it."""
    def validate() -> dict[str, Any]:
        inventory = _read_confined(inventory_path, load_inventory)
        patch = _read_confined(patch_path, load_enrichment_patch)
        validate_patch(inventory, patch)
        return {
            "valid": True,
            "source_inventory_hash": patch.source_inventory_hash,
        }

    return _safe_call(validate)


@mcp.tool()
def compare_inventories(
    before_path: str,
    after_path: str,
) -> dict[str, Any]:
    """Return a deterministic before/after decision and evidence comparison."""
    return _safe_call(
        lambda: build_inventory_comparison(
            _read_confined(before_path, load_inventory),
            _read_confined(after_path, load_inventory),
        ).model_dump(mode="json")
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
