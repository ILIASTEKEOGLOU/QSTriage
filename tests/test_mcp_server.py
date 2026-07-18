import asyncio
import json
import os
from pathlib import Path
import sys

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from qstriage.cbom import import_cbom_inventory
from qstriage.closure import inventory_hash


EXPECTED_TOOLS = {
    "inspect_evidence_gaps",
    "generate_patch_template",
    "validate_enrichment_patch",
    "compare_inventories",
}


def _write_inventory(directory: Path, name: str = "inventory.yaml") -> Path:
    inventory = import_cbom_inventory("tests/fixtures/sample_cbom.json")
    path = directory / name
    path.write_text(
        yaml.safe_dump(inventory.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return path


def _write_patch(directory: Path, inventory_path: Path) -> Path:
    from qstriage.models import load_inventory

    inventory = load_inventory(inventory_path)
    patch = directory / "patch.yaml"
    patch.write_text(
        yaml.safe_dump(
            {
                "patch_version": "0.1",
                "source_inventory_hash": inventory_hash(inventory),
                "assertions": [{
                    "asset_id": "crypto-rsa-2048",
                    "field": "retention_years",
                    "value": 0,
                    "state": "declared",
                    "provenance": "user_declared",
                }],
                "relationship_assertions": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return patch


def test_read_only_tools_return_structured_results_without_writes(tmp_path, monkeypatch) -> None:
    inventory_path = _write_inventory(tmp_path)
    patch_path = _write_patch(tmp_path, inventory_path)
    monkeypatch.chdir(tmp_path)
    from qstriage import mcp_server

    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    manifest = mcp_server.inspect_evidence_gaps("inventory.yaml")
    template = mcp_server.generate_patch_template("inventory.yaml")
    validation = mcp_server.validate_enrichment_patch("inventory.yaml", "patch.yaml")
    comparison = mcp_server.compare_inventories("inventory.yaml", "inventory.yaml")

    assert manifest["version"] == "0.1" and manifest["gaps"]
    template_data = yaml.safe_load(template)
    assert all(item["value"] is None for item in template_data["assertions"])
    assert validation == {"valid": True, "source_inventory_hash": inventory_hash(load_inventory_for_test(inventory_path))}
    assert comparison["before_inventory_hash"] == comparison["after_inventory_hash"]
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def load_inventory_for_test(path: Path):
    from qstriage.models import load_inventory
    return load_inventory(path)


def test_mcp_paths_are_confined_to_working_directory(tmp_path, monkeypatch) -> None:
    _write_inventory(tmp_path)
    outside = tmp_path.parent / "outside-inventory.yaml"
    _write_inventory(tmp_path.parent, outside.name)
    monkeypatch.chdir(tmp_path)
    from qstriage import mcp_server

    for unsafe in (str(outside.resolve()), f"..{os.sep}{outside.name}"):
        with pytest.raises(ValueError, match="working directory"):
            mcp_server.inspect_evidence_gaps(unsafe)

    link = tmp_path / "outside-link.yaml"
    try:
        link.symlink_to(outside)
    except OSError:
        return  # Linux CI exercises the symlink boundary when Windows disallows creation.
    with pytest.raises(ValueError, match="working directory"):
        mcp_server.inspect_evidence_gaps(link.name)


def test_official_stdio_protocol_exposes_exact_read_only_contract(tmp_path) -> None:
    _write_inventory(tmp_path, "before.yaml")
    _write_inventory(tmp_path, "after.yaml")
    initial_files = sorted(path.name for path in tmp_path.iterdir())

    async def exercise_protocol() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "qstriage.mcp_server"],
            cwd=str(tmp_path),
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == EXPECTED_TOOLS
                assert not any(
                    forbidden in tool.name
                    for tool in tools.tools
                    for forbidden in ("apply", "write", "mutate", "shell", "network", "discover", "production")
                )
                inspected = await session.call_tool(
                    "inspect_evidence_gaps", {"inventory_path": "before.yaml"}
                )
                compared = await session.call_tool(
                    "compare_inventories",
                    {"before_path": "before.yaml", "after_path": "after.yaml"},
                )
                assert not inspected.isError
                assert not compared.isError
                assert json.loads(inspected.content[0].text)["version"] == "0.1"

    asyncio.run(exercise_protocol())
    assert sorted(path.name for path in tmp_path.iterdir()) == initial_files
