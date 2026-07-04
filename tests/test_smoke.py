from typer.testing import CliRunner

from qstriage import __version__
from qstriage.cli import app


def test_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert f"QSTriage {__version__}" in result.output
