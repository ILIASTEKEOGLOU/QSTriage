"""Dependabot must not raise package lower bounds that already allow a release."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_pip_updates_raise_requirements_only_when_necessary() -> None:
    config = yaml.safe_load(
        (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    )
    [pip] = [
        update for update in config["updates"] if update["package-ecosystem"] == "pip"
    ]

    assert pip["versioning-strategy"] == "increase-if-necessary"
