from typer.testing import CliRunner

from qstriage.cli import app


def test_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "QSTriage 0.1.0" in result.output
