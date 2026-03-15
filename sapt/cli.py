"""
SAPT CLI — Click-based command line interface.
All commands: pentest, recon, scan, exploit, report, check, config.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from sapt import __version__
from sapt.core.config import SAPTConfig
from sapt.core.logger import (
    get_console, get_logger, print_banner, setup_logger,
    log_phase, log_success, log_error,
)


# ── Helper ───────────────────────────────────────────────────────────────────

def _run_async(coro):
    """Run async coroutine from sync Click context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ── Main Group ───────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--target", "-t", default=None, help="Target domain/IP")
@click.option("--config", "config_path", default="sapt.yaml", help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--debug", is_flag=True, help="Debug mode (very verbose)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.version_option(version=__version__, prog_name="SAPT")
@click.pass_context
def main(ctx, target, config_path, verbose, debug, quiet, no_color):
    """SAPT — Semi-Automated Pentest Tool v0.1.0

    A CLI-based security testing framework for web applications.

    \b
    Usage:
      sapt --target example.com pentest --mode bb
      sapt --target example.com recon --all
      sapt check --verbose
      sapt config init
    """
    ctx.ensure_object(dict)

    # Setup logger
    setup_logger(
        verbose=verbose, debug=debug, quiet=quiet, no_color=no_color,
    )

    # Load config
    config = SAPTConfig.load(config_path)
    if target:
        config.set("target.domain", target)

    ctx.obj["config"] = config
    ctx.obj["target"] = target
    ctx.obj["verbose"] = verbose
    ctx.obj["debug"] = debug
    ctx.obj["quiet"] = quiet

    # Show banner on bare `sapt` call
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: pentest — Full automated pipeline
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--mode", type=click.Choice(["bb", "stealth", "mass"]), default="bb", help="Testing mode")
@click.option("--time", "time_limit", type=int, default=180, help="Max runtime in minutes")
@click.option("--output", "output_dir", default=None, help="Output directory")
@click.option("--scope", default=None, help="File with in-scope domains/IPs")
@click.option("--notify", type=click.Choice(["telegram", "slack", "none"]), default=None, help="Notification channel")
@click.option("--skip-recon", is_flag=True, help="Skip Phase 1 (use existing recon data)")
@click.option("--skip-scan", is_flag=True, help="Skip Phase 2")
@click.option("--skip-exploit", is_flag=True, help="Skip Phase 3 (recon+scan only)")
@click.option("--resume", is_flag=True, help="Resume from last checkpoint")
@click.pass_context
def pentest(ctx, mode, time_limit, output_dir, scope, notify, skip_recon, skip_scan, skip_exploit, resume):
    """Full automated pentest pipeline (Phases 1-4)."""
    config = ctx.obj["config"]
    target = ctx.obj["target"]

    if not target:
        log_error("Target is required. Use: sapt --target <domain> pentest")
        raise SystemExit(1)

    print_banner()
    console = get_console()

    console.print(Panel(
        f"[bold cyan]Target:[/] {target}\n"
        f"[bold cyan]Mode:[/]   {mode}\n"
        f"[bold cyan]Time:[/]   {time_limit} minutes\n"
        f"[bold cyan]Output:[/] {output_dir or f'./output/{target}'}",
        title="[bold]SAPT Pentest Configuration[/]",
        border_style="cyan",
    ))

    # Update config with CLI flags
    config.set("mode.default", mode)
    config.set("mode.time_limit", time_limit)
    if scope:
        config.set("target.scope_file", scope)
    if output_dir:
        config.set("output.base_dir", output_dir)

    async def _run_pentest():
        from sapt.core.orchestrator import Orchestrator
        orchestrator = Orchestrator(config, target)
        await orchestrator.run(
            skip_recon=skip_recon,
            skip_scan=skip_scan,
            skip_exploit=skip_exploit,
            resume=resume,
        )

    _run_async(_run_pentest())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: recon — Phase 1 only
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--subdomain", is_flag=True, help="Run subdomain enumeration")
@click.option("--http-probe", is_flag=True, help="Probe live hosts")
@click.option("--js-analysis", is_flag=True, help="Extract + analyze JavaScript")
@click.option("--tech-detect", is_flag=True, help="Detect tech stack")
@click.option("--all", "run_all", is_flag=True, help="Run all recon modules")
@click.option("--wordlist", default=None, help="Custom wordlist for DNS brute")
@click.option("--output", "output_dir", default=None, help="Output directory")
@click.pass_context
def recon(ctx, subdomain, http_probe, js_analysis, tech_detect, run_all, wordlist, output_dir):
    """Run reconnaissance phase (Phase 1 only)."""
    config = ctx.obj["config"]
    target = ctx.obj["target"]

    if not target:
        log_error("Target is required. Use: sapt --target <domain> recon")
        raise SystemExit(1)

    print_banner()
    log_phase("Recon", f"Starting reconnaissance on {target}")

    if run_all:
        subdomain = http_probe = js_analysis = tech_detect = True

    # Update config
    config.set("recon.subdomain.enabled", subdomain)
    config.set("recon.http_probe.enabled", http_probe)
    config.set("recon.js_analysis.enabled", js_analysis)
    config.set("recon.tech_detection.enabled", tech_detect)

    if wordlist:
        config.set("recon.subdomain.wordlist", wordlist)
    if output_dir:
        config.set("output.base_dir", output_dir)

    async def _run_recon():
        from sapt.phases.recon import ReconPhase
        phase = ReconPhase(config, target)
        results = await phase.run()
        return results

    _run_async(_run_recon())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: scan — Phase 2 only
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--hosts", default=None, help="Input file of live hosts")
@click.option("--owasp", default=None, help="Comma-separated OWASP categories (A01–A10)")
@click.option("--nuclei", "run_nuclei", is_flag=True, help="Run Nuclei template scanning")
@click.option("--severity", default=None, help="Filter: critical,high,medium,low,info")
@click.option("--api-test", is_flag=True, help="Enable API-specific tests")
@click.option("--graphql", is_flag=True, help="Enable GraphQL testing")
@click.option("--rate", type=int, default=None, help="Requests per second override")
@click.option("--output", "output_dir", default=None, help="Output directory")
@click.pass_context
def scan(ctx, hosts, owasp, run_nuclei, severity, api_test, graphql, rate, output_dir):
    """Run vulnerability scanning phase (Phase 2 only)."""
    config = ctx.obj["config"]
    target = ctx.obj["target"]

    if not target:
        log_error("Target is required. Use: sapt --target <domain> scan")
        raise SystemExit(1)

    print_banner()
    log_phase("Scan", f"Starting vulnerability scan on {target}")

    if owasp:
        config.set("scanning.owasp.enabled", owasp.split(","))
    if severity:
        config.set("scanning.nuclei.severity", severity.split(","))
    if rate:
        config.set("scanning.nuclei.rate_limit", rate)
    if output_dir:
        config.set("output.base_dir", output_dir)

    async def _run_scan():
        from sapt.phases.scan import ScanPhase
        phase = ScanPhase(config, target, hosts_file=hosts)
        results = await phase.run()
        return results

    _run_async(_run_scan())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: exploit — Phase 3 only
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--findings", required=True, help="JSON file from scan phase")
@click.option("--verify", is_flag=True, help="Verify each finding")
@click.option("--poc-gen", is_flag=True, help="Generate PoC scripts")
@click.option("--impact", is_flag=True, help="Run impact assessment")
@click.option("--safe", is_flag=True, help="Skip destructive tests")
@click.option("--output", "output_dir", default=None, help="Output directory")
@click.pass_context
def exploit(ctx, findings, verify, poc_gen, impact, safe, output_dir):
    """Run exploitation/verification phase (Phase 3 only)."""
    config = ctx.obj["config"]
    target = ctx.obj["target"]

    if not target:
        log_error("Target is required. Use: sapt --target <domain> exploit")
        raise SystemExit(1)

    print_banner()
    log_phase("Exploit", f"Starting exploitation on {target}")

    config.set("exploitation.verify_findings", verify)
    config.set("exploitation.poc_generation", poc_gen)
    config.set("exploitation.impact_assessment", impact)
    if safe:
        config.set("exploitation.safe_mode", True)
    if output_dir:
        config.set("output.base_dir", output_dir)

    async def _run_exploit():
        from sapt.phases.exploit import ExploitPhase
        phase = ExploitPhase(config, target, findings_file=findings)
        results = await phase.run()
        return results

    _run_async(_run_exploit())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: report — Phase 4 only
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--data", required=True, help="Path to sapt_state.db")
@click.option("--format", "report_format", default="html,json", help="Output formats: html,json,md")
@click.option("--executive-summary", is_flag=True, help="Include executive summary")
@click.option("--compliance", default=None, help="Compliance mapping: pci-dss,owasp,nist")
@click.option("--output", "output_dir", default=None, help="Output directory")
@click.pass_context
def report(ctx, data, report_format, executive_summary, compliance, output_dir):
    """Generate security report (Phase 4 only)."""
    config = ctx.obj["config"]
    target = ctx.obj["target"]

    if not target:
        log_error("Target is required. Use: sapt --target <domain> report")
        raise SystemExit(1)

    print_banner()
    log_phase("Report", f"Generating report for {target}")

    config.set("reporting.formats", report_format.split(","))
    config.set("reporting.executive_summary", executive_summary)
    if compliance:
        config.set("reporting.compliance_mapping", compliance.split(","))
    if output_dir:
        config.set("output.base_dir", output_dir)

    async def _run_report():
        from sapt.phases.report import ReportPhase
        phase = ReportPhase(config, target, state_db=data)
        results = await phase.run()
        return results

    _run_async(_run_report())


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: check — Tool availability check
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--install-missing", is_flag=True, help="Auto-install missing tools (Go tools only)")
@click.option("--verbose", "check_verbose", is_flag=True, help="Show tool paths and versions")
@click.option("--json", "json_output", is_flag=True, help="Output in JSON format")
@click.pass_context
def check(ctx, install_missing, check_verbose, json_output):
    """Check availability of external security tools."""
    from sapt.tools.registry import check_all_tools, TOOL_METADATA

    print_banner()
    console = get_console()

    console.print("[bold]Checking tool availability...[/]\n")

    results = check_all_tools()

    if json_output:
        import json
        click.echo(json.dumps(results, indent=2))
        return

    # Build table
    table = Table(
        title="SAPT Tool Status",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Status", width=6, justify="center")
    table.add_column("Tool", style="bold")
    table.add_column("Category", style="dim")
    table.add_column("Description")
    if check_verbose:
        table.add_column("Version")
        table.add_column("Path", style="dim")
    table.add_column("Install Command", style="yellow")

    available_count = 0
    critical_missing = []

    for name, info in results.items():
        status = info.get("status", "not_found")
        is_critical = info.get("critical", False)

        if status == "available":
            icon = "✅"
            available_count += 1
        elif is_critical:
            icon = "❌"
            critical_missing.append(name)
        else:
            icon = "⚠️"

        row = [
            icon,
            name,
            info.get("category", ""),
            info.get("desc", ""),
        ]
        if check_verbose:
            row.append(info.get("version") or "—")
            row.append(info.get("path") or "—")
        row.append(info.get("install_cmd") or "—")

        table.add_row(*row)

    console.print(table)
    console.print()

    # Summary
    total = len(results)
    readiness = "FULL" if available_count == total else (
        "PARTIAL" if available_count > 0 else "NONE"
    )

    readiness_color = {
        "FULL": "green",
        "PARTIAL": "yellow",
        "NONE": "red",
    }

    console.print(Panel(
        f"[bold]SAPT Readiness:[/] {available_count}/{total} tools available "
        f"([{readiness_color[readiness]}]{readiness}[/])\n"
        + (f"[bold red]Missing critical tools:[/] {', '.join(critical_missing)}" if critical_missing else "[green]All critical tools available ✓[/]"),
        border_style=readiness_color[readiness],
    ))

    if install_missing:
        _install_missing_tools(results, console)


def _install_missing_tools(results: dict, console: Console):
    """Attempt to install missing Go-based tools."""
    import subprocess

    missing_go_tools = {
        name: info for name, info in results.items()
        if info["status"] == "not_found"
        and info.get("install_cmd", "").startswith("go install")
    }

    if not missing_go_tools:
        console.print("[green]No Go tools to install.[/]")
        return

    console.print(f"\n[bold]Installing {len(missing_go_tools)} Go tools...[/]\n")

    for name, info in missing_go_tools.items():
        cmd = info["install_cmd"]
        console.print(f"  [cyan]→[/] Installing {name}: {cmd}")
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                console.print(f"    [green]✅ {name} installed successfully[/]")
            else:
                console.print(f"    [red]❌ {name} installation failed: {result.stderr[:100]}[/]")
        except Exception as e:
            console.print(f"    [red]❌ {name} installation error: {e}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND: config — Config management
# ─────────────────────────────────────────────────────────────────────────────

@main.group()
@click.pass_context
def config(ctx):
    """Configuration management commands."""
    pass


@config.command()
@click.argument("output_path", default="sapt.yaml")
def init(output_path):
    """Create a default sapt.yaml configuration file."""
    console = get_console()

    path = Path(output_path)
    if path.exists():
        if not click.confirm(f"'{output_path}' already exists. Overwrite?"):
            console.print("[yellow]Cancelled.[/]")
            return

    result_path = SAPTConfig.generate_default(output_path)
    console.print(f"[green]✅ Default config created at:[/] {result_path}")


@config.command()
@click.pass_context
def show(ctx):
    """Show active configuration."""
    cfg = ctx.obj.get("config")
    if not cfg:
        cfg = SAPTConfig.load()

    console = get_console()
    console.print(Panel(
        cfg.to_yaml(),
        title="[bold]Active Configuration[/]",
        border_style="cyan",
    ))


@config.command()
@click.argument("config_file")
def validate(config_file):
    """Validate a configuration file."""
    console = get_console()
    try:
        cfg = SAPTConfig.load(config_file)
        cfg.validate()
        console.print(f"[green]✅ Config '{config_file}' is valid.[/]")
    except Exception as e:
        console.print(f"[red]❌ Config validation failed: {e}[/]")
        raise SystemExit(1)


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a configuration value. E.g.: sapt config set notify.telegram.bot_token TOKEN"""
    console = get_console()
    cfg = SAPTConfig.load()

    # Auto-convert types
    if value.lower() in ("true", "false"):
        value = value.lower() == "true"
    elif value.isdigit():
        value = int(value)

    cfg.set(key, value)

    # Save back
    path = Path("sapt.yaml")
    path.write_text(cfg.to_yaml(), encoding="utf-8")
    console.print(f"[green]✅ Set {key} = {value}[/]")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
