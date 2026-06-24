"""Tests for CLI commands and options."""

from click.testing import CliRunner

from iam_security_scanner.cli import cli
from iam_security_scanner import __version__


class TestCLI:
    def test_help_shows_banner(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "IAM Security Scanner" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_security_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["security", "--help"])
        assert result.exit_code == 0
        assert "44 security checks" in result.output
        assert "128 controls" in result.output

    def test_security_help_has_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["security", "--help"])
        assert "--profile" in result.output
        assert "--region" in result.output
        assert "--output-format" in result.output
        assert "--output-dir" in result.output
        assert "--max-workers" in result.output
        assert "--compliance-only" in result.output
        assert "--quiet" in result.output
        assert "--debug" in result.output

    def test_invalid_format(self):
        runner = CliRunner()
        result = runner.invoke(
            cli, ["security", "--output-format", "xml"]
        )
        assert result.exit_code != 0

    def test_max_workers_range(self):
        runner = CliRunner()
        # Over max
        result = runner.invoke(
            cli, ["security", "--max-workers", "20"]
        )
        assert result.exit_code != 0

    def test_help_option_shorthand(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["-h"])
        assert result.exit_code == 0
        assert "IAM Security Scanner" in result.output
