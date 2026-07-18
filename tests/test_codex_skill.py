from pathlib import Path
import tomllib

import yaml


SKILL = Path(".agents/skills/qstriage-evidence-closure/SKILL.md")
CONFIG = Path(".codex/config.toml")
TOOLS = [
    "inspect_evidence_gaps",
    "generate_patch_template",
    "validate_enrichment_patch",
    "compare_inventories",
]


def test_repository_skill_has_exact_valid_frontmatter() -> None:
    text = SKILL.read_text(encoding="utf-8")
    _, frontmatter, body = text.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert metadata == {
        "name": "qstriage-evidence-closure",
        "description": (
            "Guide a human through unresolved QSTriage CBOM evidence gaps, draft a "
            "provenance-aware enrichment patch, validate it, stop for human approval, "
            "and compare deterministic results after the human applies it. Never invent "
            "evidence or run patch application."
        ),
    }
    required = [
        "inspect_evidence_gaps", "only about unresolved fields", "Never infer values",
        "Accept unknown", "source_reference", "declared", "verified", "complete draft patch",
        "validate", "every claimed fact", "STOP", "Never execute `qstriage closure apply`",
        "exact apply command", "compare_inventories", "only differences returned",
        "production authorization",
    ]
    assert all(phrase.lower() in body.lower() for phrase in required)


def test_project_mcp_config_allowlists_only_read_only_tools() -> None:
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    server = config["mcp_servers"]["qstriage"]

    assert server["command"] == "python"
    assert server["args"] == ["-m", "qstriage.mcp_server"]
    assert server["enabled"] is True
    assert server["enabled_tools"] == TOOLS
    assert not any("apply" in tool for tool in server["enabled_tools"])
    assert server["default_tools_approval_mode"] == "approve"
