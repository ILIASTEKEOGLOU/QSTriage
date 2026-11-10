"""The enrichment patch loader applies the limits for untrusted YAML.

A patch is reviewed by a person and then applied. Duplicate mapping keys would
let the reviewed value differ from the applied value, so they are rejected,
as are aliases, excessive nesting, and oversized files.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qstriage import enrichment, mcp_server
from qstriage.cli import app
from qstriage.enrichment import load_enrichment_patch
from qstriage.limits import MAX_YAML_NESTING_DEPTH, ResourceLimitError


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "evidence-closure"
APPROVED_PATCH = DEMO / "approved_enrichment.patch.yaml"

runner = CliRunner()


def _flat(output: str) -> str:
    """Join lines so assertions do not depend on the console width."""
    return " ".join(output.split())


def _duplicate_value_patch(directory: Path) -> Path:
    """Approved demo patch with a second ``value`` key after the reviewed one."""
    text = APPROVED_PATCH.read_text(encoding="utf-8")
    reviewed = "  value: customer_pii\n"
    assert text.count(reviewed) == 1
    path = directory / "duplicate.patch.yaml"
    path.write_text(text.replace(reviewed, reviewed + "  value: public\n"), encoding="utf-8")
    return path


def _alias_patch(directory: Path) -> Path:
    lines = ["a: &a [x, x, x, x, x, x, x, x, x]"]
    for level in range(1, 10):
        previous = chr(ord("a") + level - 1)
        current = chr(ord("a") + level)
        lines.append(f"{current}: &{current} [{', '.join(['*' + previous] * 9)}]")
    path = directory / "alias.patch.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_approved_demo_patch_still_loads() -> None:
    patch = load_enrichment_patch(APPROVED_PATCH)

    assert patch.assertions[0].value == "customer_pii"


def test_duplicate_key_is_rejected_by_the_loader(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="duplicate mapping key 'value'"):
        load_enrichment_patch(_duplicate_value_patch(tmp_path))


def test_closure_validate_rejects_duplicate_key(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["closure", "validate", str(DEMO / "imported.yaml"), str(_duplicate_value_patch(tmp_path))],
    )

    assert result.exit_code == 1
    assert "Enrichment patch validation failed" in _flat(result.output)
    assert "duplicate mapping key 'value'" in _flat(result.output)
    assert "Enrichment patch is valid." not in _flat(result.output)


def test_closure_apply_rejects_duplicate_key_and_writes_nothing(tmp_path: Path) -> None:
    output = tmp_path / "enriched.yaml"
    result = runner.invoke(
        app,
        [
            "closure", "apply", str(DEMO / "imported.yaml"),
            str(_duplicate_value_patch(tmp_path)), "--output", str(output),
        ],
    )

    assert result.exit_code == 1
    assert "duplicate mapping key 'value'" in _flat(result.output)
    assert not output.exists()


def test_mcp_validate_rejects_duplicate_key(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "imported.yaml").write_bytes((DEMO / "imported.yaml").read_bytes())
    _duplicate_value_patch(tmp_path)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="duplicate mapping key 'value'"):
        mcp_server.validate_enrichment_patch("imported.yaml", "duplicate.patch.yaml")


def test_alias_expansion_is_rejected_before_construction(tmp_path: Path) -> None:
    path = _alias_patch(tmp_path)

    started = time.perf_counter()
    with pytest.raises(ResourceLimitError, match="aliases"):
        load_enrichment_patch(path)
    assert time.perf_counter() - started < 5.0


def test_closure_validate_reports_alias_rejection(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["closure", "validate", str(DEMO / "imported.yaml"), str(_alias_patch(tmp_path))]
    )

    assert result.exit_code == 1
    assert "uses YAML aliases" in _flat(result.output)


def test_nesting_beyond_the_limit_is_rejected(tmp_path: Path) -> None:
    depth = MAX_YAML_NESTING_DEPTH + 1
    path = tmp_path / "deep.patch.yaml"
    path.write_text("[" * depth + "]" * depth + "\n", encoding="utf-8")

    with pytest.raises(ResourceLimitError, match="nesting depth"):
        load_enrichment_patch(path)


def test_patch_size_limit_is_its_own_constant(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(enrichment, "MAX_ENRICHMENT_PATCH_FILE_BYTES", 64)
    path = tmp_path / "large.patch.yaml"
    path.write_text("patch_version: '0.1'\n" + "# padding\n" * 10, encoding="utf-8")

    with pytest.raises(ResourceLimitError, match="Enrichment patch exceeds"):
        load_enrichment_patch(path)


def test_package_parses_yaml_only_through_the_limited_loader() -> None:
    direct_load = re.compile(r"\byaml\.(safe_load|load|full_load|unsafe_load|load_all|safe_load_all)\(")
    offenders = [
        str(path.relative_to(ROOT))
        for path in sorted((ROOT / "qstriage").glob("*.py"))
        if direct_load.search(path.read_text(encoding="utf-8"))
    ]

    assert offenders == []
