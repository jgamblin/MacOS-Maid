"""Tests for CLI."""

from click.testing import CliRunner

from macos_maid.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_cli_list():
    runner = CliRunner()
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0


def test_cli_init_creates_config(tmp_path):
    runner = CliRunner()
    config_path = tmp_path / ".maid.yml"
    result = runner.invoke(main, ["init", "--path", str(config_path)])
    assert result.exit_code == 0
    assert config_path.exists()
    content = config_path.read_text()
    assert "homebrew" in content


def test_cli_clean_dry_run_default():
    """Clean without config should default to dry-run."""
    runner = CliRunner()
    result = runner.invoke(main, ["clean", "--config", "/nonexistent/path.yml"])
    assert result.exit_code == 0
    output_lower = result.output.lower()
    assert "dry run" in output_lower or "preview" in output_lower or "no config" in output_lower


def test_cli_audit():
    """Test audit command runs without crashing.

    Exit code may be 1 if audit finds real failures (e.g. firewall disabled
    on CI runners), so we just check it doesn't crash (exit code 0 or 1).
    """
    runner = CliRunner()
    result = runner.invoke(main, ["audit"])
    assert result.exit_code in (0, 1)


def test_cli_log_no_previous_run():
    runner = CliRunner()
    result = runner.invoke(main, ["log", "--log-dir", "/nonexistent"])
    assert result.exit_code == 0
    assert "No previous run" in result.output or "not found" in result.output.lower()


def test_cli_report_dry_run_nonexistent_config():
    """Test report command with dry-run and nonexistent config."""
    runner = CliRunner()
    result = runner.invoke(main, ["report", "--dry-run", "--config", "/nonexistent/path.yml"])
    assert result.exit_code == 0
    # Should show dry-run preview output
    output_lower = result.output.lower()
    assert "dry run" in output_lower or "preview" in output_lower or "no config" in output_lower


def test_cli_config_command():
    """Test config command shows not found message for defaults."""
    runner = CliRunner()
    result = runner.invoke(main, ["config"])
    assert result.exit_code == 0
    assert "not found, using defaults" in result.output
