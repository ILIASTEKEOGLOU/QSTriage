from __future__ import annotations

from pathlib import Path

import yaml


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "security-alert.yml"
)


def _workflow() -> dict[object, object]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _triggers(workflow: dict[object, object]) -> dict[str, object]:
    # PyYAML parses the bare key `on` as boolean True.
    return workflow.get("on", workflow.get(True))  # type: ignore[return-value]


def test_alert_runs_only_after_completed_security_workflow() -> None:
    triggers = _triggers(_workflow())

    assert set(triggers) == {"workflow_run"}
    assert triggers["workflow_run"] == {
        "workflows": ["Security"],
        "types": ["completed"],
    }


def test_alert_holds_only_issue_write_permission() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]

    assert workflow["permissions"] == {}
    assert set(jobs) == {"open-issue"}
    assert jobs["open-issue"]["permissions"] == {"issues": "write"}


def test_alert_is_limited_to_failed_scheduled_runs_on_main() -> None:
    condition = _workflow()["jobs"]["open-issue"]["if"]

    assert "github.event.workflow_run.conclusion == 'failure'" in condition
    assert "github.event.workflow_run.event == 'schedule'" in condition
    assert "github.event.workflow_run.head_branch == 'main'" in condition


def test_alert_runs_no_repository_code_or_third_party_actions() -> None:
    steps = _workflow()["jobs"]["open-issue"]["steps"]

    assert len(steps) == 1
    assert all("uses" not in step for step in steps)
    assert "${{" not in steps[0]["run"]
