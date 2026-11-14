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


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _server_command(script: str) -> list[str]:
    """Arguments that run the server from this checkout.

    The SDK starts the server with a minimal environment (no PYTHONPATH), so
    without this the subprocess would import whatever qstriage is installed,
    which may be another checkout.
    """

    return ["-c", f"import sys; sys.path.insert(0, {str(REPOSITORY_ROOT)!r})\n" + script]


_SERVER = "import runpy; runpy.run_module('qstriage.mcp_server', run_name='__main__')"


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
        with pytest.raises(mcp_server.ToolError, match="working directory"):
            mcp_server.inspect_evidence_gaps(unsafe)

    link = tmp_path / "outside-link.yaml"
    try:
        link.symlink_to(outside)
    except OSError:
        return  # Linux CI exercises the symlink boundary when Windows disallows creation.
    with pytest.raises(mcp_server.ToolError, match="working directory"):
        mcp_server.inspect_evidence_gaps(link.name)


def _is_error(result: object) -> object:
    # mcp 2.x exposes `is_error`; mcp 1.x exposes `isError`.
    return getattr(result, "is_error", getattr(result, "isError", None))


def test_official_stdio_protocol_exposes_exact_read_only_contract(tmp_path) -> None:
    _write_inventory(tmp_path, "before.yaml")
    _write_inventory(tmp_path, "after.yaml")
    initial_files = sorted(path.name for path in tmp_path.iterdir())

    async def exercise_protocol() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=_server_command(_SERVER),
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
                assert _is_error(inspected) is False
                assert _is_error(compared) is False
                assert json.loads(inspected.content[0].text)["version"] == "0.1"

    asyncio.run(exercise_protocol())
    assert sorted(path.name for path in tmp_path.iterdir()) == initial_files


def test_tool_error_comes_from_the_installed_sdk() -> None:
    import importlib.metadata

    from qstriage import mcp_server

    major = importlib.metadata.version("mcp").split(".")[0]
    expected_module = (
        "mcp.server.mcpserver.exceptions" if major == "2" else "mcp.server.fastmcp.exceptions"
    )
    assert mcp_server.ToolError.__module__ == expected_module
    assert mcp_server.ToolError.__name__ == "ToolError"


def test_read_failure_names_the_requested_file_not_the_server_path(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    (tmp_path / "blocked.yaml").write_text("assets: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(mcp_server, "load_inventory", denied)
    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps("blocked.yaml")

    assert str(caught.value) == "Cannot read blocked.yaml: permission denied."
    assert str(tmp_path) not in str(caught.value)


def test_other_file_access_failures_do_not_reveal_server_paths(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    _write_inventory(tmp_path)
    monkeypatch.chdir(tmp_path)

    def fails(_inventory):
        raise OSError(5, "Input/output error", str(tmp_path / "cache.bin"))

    monkeypatch.setattr(mcp_server, "build_gap_manifest", fails)
    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps("inventory.yaml")

    assert str(caught.value) == "File access failed."


def test_error_messages_are_one_line_and_bounded(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    monkeypatch.chdir(tmp_path)
    requested = "line\r\nbreak-" + "x" * 600 + ".yaml"
    (tmp_path / "placeholder").write_text("", encoding="utf-8")

    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps(requested)

    message = str(caught.value)
    assert "\r" not in message and "\n" not in message
    assert len(message) <= mcp_server.MAX_ERROR_MESSAGE_LENGTH


def test_long_parser_detail_is_shortened_before_the_file_name(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    (tmp_path / "long-tag.yaml").write_text("assets: !" + "x" * 640 + " value\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps("long-tag.yaml")

    message = str(caught.value)
    prefix = "YAML is malformed in long-tag.yaml near line 1, column 9: "
    assert message.startswith(prefix + "could not determine a constructor for the tag")
    assert message.endswith("xxx...")
    assert len(message) == len(prefix) + mcp_server.MAX_PARSER_DETAIL_LENGTH


def test_long_path_is_shortened_so_the_cause_stays(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    (tmp_path / "blocked.yaml").write_text("assets: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    requested = "nested/" * 93 + "blocked.yaml"  # 663 characters
    monkeypatch.setattr(mcp_server, "_confined_file", lambda _value: tmp_path / "blocked.yaml")

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(mcp_server, "load_inventory", denied)
    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps(requested)

    message = str(caught.value)
    assert len(requested) > mcp_server.MAX_ERROR_MESSAGE_LENGTH
    assert len(message) == mcp_server.MAX_ERROR_MESSAGE_LENGTH
    assert message.startswith("Cannot read ...")
    assert message.endswith("nested/blocked.yaml: permission denied.")


def test_malformed_yaml_names_file_line_and_column(tmp_path, monkeypatch) -> None:
    from qstriage import mcp_server

    inventory_path = _write_inventory(tmp_path)
    (tmp_path / "broken.yaml").write_text("assets: [\n", encoding="utf-8")
    (tmp_path / "broken.patch.yaml").write_text('patch_version: "0.1"\nassertions: [\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.inspect_evidence_gaps("broken.yaml")
    assert str(caught.value) == (
        "YAML is malformed in broken.yaml near line 2, column 1: "
        "expected the node content, but found '<stream end>'."
    )

    with pytest.raises(mcp_server.ToolError) as caught:
        mcp_server.validate_enrichment_patch(inventory_path.name, "broken.patch.yaml")
    assert str(caught.value).startswith("YAML is malformed in broken.patch.yaml near line 3, column 1:")


# The server under test, with a read failure simulated after the path check
# for files named blocked.yaml, so the case runs the same on Linux and Windows.
# A request starting with "nested/" is mapped to blocked.yaml, so a path longer
# than the message limit needs no deep directories (Windows path limits).
_SERVER_WITH_BLOCKED_READ = """
from pathlib import Path
import qstriage.mcp_server as server

original_load = server.load_inventory
original_confined = server._confined_file

def load_inventory(path):
    if Path(path).name == "blocked.yaml":
        raise PermissionError(13, "Permission denied", str(path))
    return original_load(path)

def confined_file(path_value):
    if path_value.startswith("nested/"):
        return original_confined("blocked.yaml")
    return original_confined(path_value)

server.load_inventory = load_inventory
server._confined_file = confined_file
server.main()
"""


def test_stdio_server_runs_from_this_checkout(tmp_path) -> None:
    import subprocess

    probe = "import qstriage, pathlib; print(pathlib.Path(qstriage.__file__).resolve().parents[1])"
    result = subprocess.run(
        [sys.executable, *_server_command(probe)],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
        capture_output=True,
        text=True,
        check=True,
    )
    assert Path(result.stdout.strip()) == REPOSITORY_ROOT


def test_stdio_client_receives_the_cause_of_expected_failures(tmp_path) -> None:
    inventory_path = _write_inventory(tmp_path)
    patch_path = _write_patch(tmp_path, inventory_path)
    data = yaml.safe_load(patch_path.read_text(encoding="utf-8"))
    data["assertions"][0].update({"field": "criticality", "value": "hgh"})
    (tmp_path / "bad_patch.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    (tmp_path / "blocked.yaml").write_text("assets: []\n", encoding="utf-8")
    (tmp_path / "broken.yaml").write_text("assets: [\n", encoding="utf-8")
    (tmp_path / "broken.patch.yaml").write_text('patch_version: "0.1"\nassertions: [\n', encoding="utf-8")
    (tmp_path / "long-tag.yaml").write_text("assets: !" + "x" * 640 + " value\n", encoding="utf-8")
    long_request = "nested/" * 93 + "blocked.yaml"
    outside = tmp_path.parent / f"{tmp_path.name}-outside.yaml"
    _write_inventory(tmp_path.parent, outside.name)

    calls = [
        (
            "validate_enrichment_patch",
            {"inventory_path": "inventory.yaml", "patch_path": "bad_patch.yaml"},
            "criticality must be low, medium, high, or critical.",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": "missing.yaml"},
            "File is unavailable inside the working directory: missing.yaml",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": f"..{os.sep}{outside.name}"},
            "Path resolves outside the MCP working directory.",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": "blocked.yaml"},
            "Cannot read blocked.yaml: permission denied.",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": "broken.yaml"},
            "YAML is malformed in broken.yaml near line 2, column 1:",
        ),
        (
            "validate_enrichment_patch",
            {"inventory_path": "inventory.yaml", "patch_path": "broken.patch.yaml"},
            "YAML is malformed in broken.patch.yaml near line 3, column 1:",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": long_request},
            "nested/blocked.yaml: permission denied.",
        ),
        (
            "inspect_evidence_gaps",
            {"inventory_path": "long-tag.yaml"},
            "YAML is malformed in long-tag.yaml near line 1, column 9: "
            "could not determine a constructor for the tag",
        ),
    ]
    results = []

    async def exercise() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=_server_command(_SERVER_WITH_BLOCKED_READ),
            cwd=str(tmp_path),
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                for name, arguments, _ in calls:
                    results.append(await session.call_tool(name, arguments))

    asyncio.run(exercise())

    for (name, _, cause), result in zip(calls, results, strict=True):
        text = " ".join(item.text for item in result.content)
        assert _is_error(result) is True, name
        assert cause in text, (name, text)
        assert str(tmp_path) not in text, (name, text)
