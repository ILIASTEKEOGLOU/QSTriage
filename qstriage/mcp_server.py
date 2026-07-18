from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, TypeVar

from mcp.server.fastmcp import FastMCP

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

mcp = FastMCP(
    "QSTriage Evidence Closure",
    instructions=SERVER_INSTRUCTIONS,
    log_level="ERROR",
)

T = TypeVar("T")


def _safe_call(operation: Callable[[], T]) -> T:
    try:
        return operation()
    except (OSError, ValueError) as error:
        message = str(error).replace("\r", " ").replace("\n", " ")[:500]
        raise ValueError(message) from None


def _confined_file(path_value: str) -> Path:
    root = Path.cwd().resolve(strict=True)
    candidate = Path(path_value)
    unresolved = candidate if candidate.is_absolute() else root / candidate
    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise ValueError(
            f"File is unavailable inside the working directory: {path_value}"
        ) from error
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("Path resolves outside the MCP working directory.") from None
    if not resolved.is_file():
        raise ValueError(f"Path is not an existing regular file: {path_value}")
    return resolved


@mcp.tool()
def inspect_evidence_gaps(inventory_path: str) -> dict[str, Any]:
    """Return the structured unresolved evidence-gap manifest for an inventory."""
    return _safe_call(
        lambda: build_gap_manifest(
            load_inventory(_confined_file(inventory_path))
        ).model_dump(mode="json")
    )


@mcp.tool()
def generate_patch_template(inventory_path: str) -> str:
    """Return deterministic YAML containing empty skeletons for unresolved gaps."""
    return _safe_call(
        lambda: build_patch_template(load_inventory(_confined_file(inventory_path)))
    )


@mcp.tool()
def validate_enrichment_patch(
    inventory_path: str,
    patch_path: str,
) -> dict[str, Any]:
    """Validate a patch against an inventory without applying or writing it."""
    def validate() -> dict[str, Any]:
        inventory = load_inventory(_confined_file(inventory_path))
        patch = load_enrichment_patch(_confined_file(patch_path))
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
            load_inventory(_confined_file(before_path)),
            load_inventory(_confined_file(after_path)),
        ).model_dump(mode="json")
    )


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
