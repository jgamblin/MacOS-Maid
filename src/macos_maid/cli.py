"""CLI entry point for MacOS Maid."""

from __future__ import annotations

import json
from pathlib import Path

import click

from macos_maid import __version__
from macos_maid.audit_log import AuditLog
from macos_maid.config import generate_default_config_yaml, load_config
from macos_maid.modules import get_all_modules
from macos_maid.reporter import Reporter
from macos_maid.runner import ModuleRunner
from macos_maid.system import detect_platform

DEFAULT_CONFIG_PATH = Path.home() / ".maid.yml"
DEFAULT_LOG_DIR = Path.home() / ".maid"


@click.group()
def main() -> None:
    """MacOS Maid — macOS cleanup and security auditing tool."""
    pass


@main.command()
def version() -> None:
    """Show version."""
    click.echo(f"macos-maid {__version__}")


@main.command(name="list")
def list_modules() -> None:
    """List all available modules."""
    modules = get_all_modules()
    click.echo(f"{'Module':<20} {'Category':<12} {'Sudo?':<8}")
    click.echo("-" * 40)
    for mod in modules:
        sudo = "yes" if mod.requires_sudo else "no"
        click.echo(f"{mod.name:<20} {mod.category:<12} {sudo:<8}")


@main.command()
@click.option("--path", type=click.Path(), default=None, help="Path to write config file")
def init(path: str | None) -> None:
    """Generate default config file."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    content = generate_default_config_yaml()
    config_path.write_text(content)
    click.echo(f"Config written to {config_path}")


@main.command()
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path")
@click.option("--dev", is_flag=True, help="Run dev modules only")
@click.option("--security", is_flag=True, help="Run security modules only")
@click.option("--modules", "module_names", default=None, help="Comma-separated module names")
@click.option("--dry-run", is_flag=True, help="Preview changes without executing")
@click.option("--sudo", "allow_sudo", is_flag=True, help="Allow modules that require root")
@click.option("--output", type=click.Choice(["terminal", "json", "markdown"]), default=None)
def clean(
    config_path: str | None,
    dev: bool,
    security: bool,
    module_names: str | None,
    dry_run: bool,
    allow_sudo: bool,
    output: str | None,
) -> None:
    """Run cleanup modules."""
    cfg_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    config = load_config(cfg_path if cfg_path.exists() else None)

    # First run without config defaults to dry-run
    if not cfg_path.exists() and not dry_run:
        click.echo("No config file found. Running in dry-run mode.")
        click.echo(f"Run 'maid init' to generate {DEFAULT_CONFIG_PATH}\n")
        dry_run = True

    platform = detect_platform()
    output_fmt = output or config.report.get("output", "terminal")
    reporter = Reporter(platform=platform, output_format=output_fmt)
    audit_log = AuditLog()

    categories = None
    if dev:
        categories = ["dev"]
    elif security:
        categories = ["security"]

    parsed_modules = module_names.split(",") if module_names else None

    runner = ModuleRunner(
        modules=get_all_modules(),
        dry_run=dry_run,
        allow_sudo=allow_sudo,
        audit_log=audit_log,
        categories=categories,
        module_names=parsed_modules,
    )

    skipped = runner.get_sudo_modules()
    if skipped:
        names = ", ".join(m.name for m in skipped)
        click.echo(f"Skipping privileged modules (use --sudo to enable): {names}\n")

    results = runner.run_clean()

    if dry_run:
        click.echo(reporter.format_dry_run(results))
    else:
        click.echo(reporter.format_clean(results))
        audit_log.save(DEFAULT_LOG_DIR)


@main.command()
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--sudo", "allow_sudo", is_flag=True, help="Allow privileged audit checks")
@click.option("--output", type=click.Choice(["terminal", "json", "markdown"]), default=None)
def audit(
    config_path: str | None,
    allow_sudo: bool,
    output: str | None,
) -> None:
    """Run security audit (read-only)."""
    cfg_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    config = load_config(cfg_path if cfg_path.exists() else None)

    platform = detect_platform()
    output_fmt = output or config.report.get("output", "terminal")
    reporter = Reporter(platform=platform, output_format=output_fmt)
    audit_log = AuditLog()

    runner = ModuleRunner(
        modules=get_all_modules(),
        dry_run=False,
        allow_sudo=allow_sudo,
        audit_log=audit_log,
        categories=["security"],
    )

    results = runner.run_audit()
    click.echo(reporter.format_audit(results))


@main.command()
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--dry-run", is_flag=True)
@click.option("--sudo", "allow_sudo", is_flag=True)
@click.option("--output", type=click.Choice(["terminal", "json", "markdown"]), default=None)
def report(
    config_path: str | None,
    dry_run: bool,
    allow_sudo: bool,
    output: str | None,
) -> None:
    """Run cleanup + security audit and produce full report."""
    cfg_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    config = load_config(cfg_path if cfg_path.exists() else None)

    if not cfg_path.exists() and not dry_run:
        click.echo("No config file found. Running in dry-run mode.\n")
        dry_run = True

    platform = detect_platform()
    output_fmt = output or config.report.get("output", "terminal")
    reporter = Reporter(platform=platform, output_format=output_fmt)
    audit_log = AuditLog()

    runner = ModuleRunner(
        modules=get_all_modules(),
        dry_run=dry_run,
        allow_sudo=allow_sudo,
        audit_log=audit_log,
    )

    clean_results = runner.run_clean()
    audit_results = runner.run_audit()

    if dry_run:
        click.echo(reporter.format_dry_run(clean_results))
    else:
        click.echo(reporter.format_clean(clean_results))

    click.echo("")
    click.echo(reporter.format_audit(audit_results))

    if not dry_run:
        audit_log.save(DEFAULT_LOG_DIR)


@main.command()
@click.option("--log-dir", type=click.Path(), default=None)
def log(log_dir: str | None) -> None:
    """Show the last run log."""
    log_path = Path(log_dir) / "last_run.json" if log_dir else DEFAULT_LOG_DIR / "last_run.json"
    if not log_path.exists():
        click.echo("No previous run found.")
        return

    data = json.loads(log_path.read_text())
    click.echo(json.dumps(data, indent=2))


@main.command()
@click.option("--path", type=click.Path(), default=None, help="Config file path")
def config(path: str | None) -> None:
    """Show active configuration."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    config_obj = load_config(cfg_path if cfg_path.exists() else None)
    click.echo(
        f"Config file: {cfg_path} ({'found' if cfg_path.exists() else 'not found, using defaults'})"
    )
    click.echo(f"Categories: {', '.join(config_obj.categories)}")
    click.echo(f"Output format: {config_obj.report.get('output', 'terminal')}")
