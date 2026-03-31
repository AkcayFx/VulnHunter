"""VulnHunter CLI — Command-line interface."""
from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path

# Fix Windows cp1252 console encoding before Rich Console is created
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnhunter import __version__
from vulnhunter.config import apply_scan_sandbox_cli, load_config
from vulnhunter.models import AgentAction, ScanPhase, ScanTarget

console = Console()

BANNER = f"""
[bold red]
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold red]
[dim]  Autonomous AI Penetration Testing Platform v{__version__}[/dim]
"""


@click.group()
@click.version_option(version=__version__, prog_name="VulnHunter")
def main():
    """VulnHunter — Autonomous AI-powered penetration testing platform."""
    pass


@main.command()
@click.argument("target")
@click.option("--config", "-c", "config_path", type=click.Path(exists=True), default=None, help="Path to YAML config")
@click.option("--ports", "-p", default=None, help="Ports to scan (e.g., 22,80,443 or 1-1024)")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis")
@click.option("--output-dir", "-o", default="./reports", help="Report output directory")
@click.option("--output", "output_file", default=None, help="Output JSON file path (for CI mode)")
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None, help="Path to scope YAML (bug bounty boundaries)")
@click.option("--ci", is_flag=True, help="CI mode — minimal output, exit code based on findings")
@click.option("--fail-on", "fail_on", default="high", help="Minimum severity to fail CI: low, medium, high, critical")
@click.option("--sarif", "sarif_path", default=None, help="Output SARIF file for GitHub Security tab")
@click.option("--lightweight", is_flag=True, help="Lightweight mode — Python-native tools only, no Docker")
@click.option("--sandbox", is_flag=True, help="Enable Docker sandbox for Nmap, Nuclei, ffuf, sqlmap, etc.")
@click.option("--nuclei-only", is_flag=True, help="Run only Nuclei template scanning (implies --sandbox)")
@click.option("--severity", default=None, help="Filter by severity (e.g., critical,high)")
def scan(
    target: str, config_path: str | None, ports: str | None, no_ai: bool,
    output_dir: str, output_file: str | None, scope_path: str | None,
    ci: bool, fail_on: str, sarif_path: str | None,
    lightweight: bool, sandbox: bool, nuclei_only: bool, severity: str | None,
):
    """Run a penetration test against TARGET."""
    if not ci:
        console.print(BANNER)

    if nuclei_only and lightweight:
        if ci:
            import json as _json
            print(_json.dumps({"error": "--nuclei-only cannot be combined with --lightweight", "pass": False}))
        else:
            console.print("  [bold red]Error:[/bold red] --nuclei-only cannot be used with --lightweight")
        raise SystemExit(2)

    cfg = load_config(Path(config_path) if config_path else None)
    cfg = apply_scan_sandbox_cli(cfg, lightweight=lightweight, sandbox=sandbox or nuclei_only)

    # Parse ports
    port_list: list[int] = []
    if ports:
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                s, e = part.split("-", 1)
                port_list.extend(range(int(s), int(e) + 1))
            else:
                port_list.append(int(part))

    scan_target = ScanTarget(host=target, ports=port_list)

    # Load scope if provided
    scope_manager = None
    if scope_path:
        from vulnhunter.scope import ScopeManager
        scope_manager = ScopeManager.from_yaml(Path(scope_path))
        allowed, reason = scope_manager.check_target(target)
        if not allowed:
            if ci:
                import json as _json
                print(_json.dumps({"error": f"OUT OF SCOPE: {reason}", "pass": False}))
            else:
                console.print(f"  [bold red]ABORT:[/bold red] Target is out of scope — {reason}")
            raise SystemExit(1)

    if not ci:
        console.print(f"  [bold cyan]Target:[/bold cyan] {target}")
        if scope_manager:
            console.print(f"  [bold cyan]Scope:[/bold cyan] {scope_manager.scope.program_name} ({scope_manager.scope.platform})")
            console.print(f"  [bold cyan]Max RPS:[/bold cyan] {scope_manager.max_rps}")
        console.print(f"  [bold cyan]AI Model:[/bold cyan] {cfg.ai.model}")
        console.print(f"  [bold cyan]Stealth:[/bold cyan] {cfg.stealth_mode}")
        if lightweight:
            console.print(f"  [bold cyan]Mode:[/bold cyan] Lightweight (Python-native only)")
        elif cfg.sandbox.enabled:
            console.print(f"  [bold cyan]Docker sandbox:[/bold cyan] enabled ({cfg.sandbox.image})")
        console.print()

    # Action callback
    def on_action(action: AgentAction):
        if ci:
            return
        if action.action_type == "tool_call":
            console.print(f"  [cyan]>[/cyan] Calling [bold]{action.tool_name}[/bold]...")
        elif action.action_type == "tool_result":
            console.print(f"  [green]>[/green] {action.tool_name} complete")
        elif action.action_type == "thinking":
            console.print(f"  [yellow]>[/yellow] {action.thought[:100]}")
        elif action.action_type == "result":
            console.print(f"  [green]>[/green] Analysis complete")

    def on_phase(phase: ScanPhase):
        if ci:
            return
        phase_names = {
            ScanPhase.INIT: "Initializing",
            ScanPhase.RECON: "Reconnaissance",
            ScanPhase.ANALYSIS: "Analysis",
            ScanPhase.REPORTING: "Reporting",
            ScanPhase.DONE: "Complete",
        }
        console.print(f"\n  [bold magenta]Phase:[/bold magenta] {phase_names.get(phase, phase.value)}")

    from vulnhunter.agents.orchestrator import OrchestratorAgent
    from vulnhunter.reporting import save_html_report, save_json_report

    orchestrator = OrchestratorAgent(
        config=cfg,
        on_action=on_action,
        on_phase=on_phase,
        scope_manager=scope_manager,
    )

    report = asyncio.run(orchestrator.run(scan_target))

    # SARIF output
    if sarif_path:
        from vulnhunter.reporting.ci_output import save_sarif
        save_sarif(report, sarif_path)
        if not ci:
            console.print(f"  [green]>[/green] SARIF report: {sarif_path}")

    # CI mode: JSON output and exit code
    if ci:
        import json as _json
        from vulnhunter.reporting.ci_output import generate_ci_summary

        summary = generate_ci_summary(report)

        severity_order = ["info", "low", "medium", "high", "critical"]
        fail_idx = severity_order.index(fail_on.lower()) if fail_on.lower() in severity_order else 3
        has_failing = any(
            severity_order.index(v.severity.value) >= fail_idx
            for v in report.vulnerabilities
        )
        summary["pass"] = not has_failing

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            Path(output_file).write_text(_json.dumps(summary, indent=2), encoding="utf-8")

        print(_json.dumps(summary, indent=2))
        raise SystemExit(1 if has_failing else 0)

    # Interactive mode output
    console.print()
    console.print(Panel(
        f"[bold]Risk Score:[/bold] {report.risk_score:.1f}/10.0  |  "
        f"[bold]Threat Level:[/bold] {report.threat_level}  |  "
        f"[bold]Vulnerabilities:[/bold] {report.total_vulns}  |  "
        f"[bold]Attack Chains:[/bold] {len(report.attack_chains)}",
        title="Scan Results",
        border_style="red",
    ))

    if report.ai_summary:
        console.print(Panel(report.ai_summary, title="AI Assessment", border_style="cyan"))

    # Attack chains
    if report.attack_chains:
        chain_table = Table(title="Attack Chains", border_style="yellow")
        chain_table.add_column("Chain", style="bold")
        chain_table.add_column("Steps")
        chain_table.add_column("CVSS")
        chain_table.add_column("Impact")
        for chain in report.attack_chains:
            chain_table.add_row(
                chain.name,
                str(len(chain.steps)),
                Text(f"{chain.combined_cvss:.1f}", style="red" if chain.combined_cvss >= 9 else "yellow"),
                chain.impact[:80] + ("..." if len(chain.impact) > 80 else ""),
            )
        console.print(chain_table)

    # Vulnerability table
    if report.vulnerabilities:
        table = Table(title="Vulnerabilities", border_style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Tool")
        table.add_column("CWE")
        table.add_column("CVSS")

        severity_colors = {
            "critical": "red", "high": "yellow", "medium": "orange3",
            "low": "blue", "info": "green",
        }

        for v in sorted(report.vulnerabilities,
                        key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)):
            color = severity_colors.get(v.severity.value, "white")
            table.add_row(
                Text(v.severity.value.upper(), style=color),
                v.title,
                v.tool,
                v.cwe_id or "N/A",
                f"{v.cvss_score:.1f}" if v.cvss_score > 0 else "—",
            )
        console.print(table)

    # MITRE ATT&CK
    if report.mitre_tactics:
        mitre_table = Table(title="MITRE ATT&CK Mapping", border_style="cyan")
        mitre_table.add_column("Tactic", style="bold cyan")
        mitre_table.add_column("Techniques")
        for tactic, techniques in report.mitre_tactics.items():
            mitre_table.add_row(tactic, ", ".join(techniques))
        console.print(mitre_table)

    # Save reports
    json_path = save_json_report(report, output_dir)
    html_path = save_html_report(report, output_dir)
    console.print(f"\n  [green]>[/green] JSON report: {json_path}")
    console.print(f"  [green]>[/green] HTML report: {html_path}")
    console.print(f"\n  [dim]Total scan time: {report.total_duration_seconds:.1f}s[/dim]\n")


@main.command()
@click.argument("target")
@click.option("--config", "-c", "config_path", type=click.Path(exists=True), default=None, help="Path to YAML config")
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None, help="Path to scope YAML")
@click.option("--output", "-o", "output_file", default="recon.json", help="Output file for recon results")
@click.option("--lightweight", is_flag=True, help="Python-native tools only, no Docker sandbox")
@click.option("--sandbox", is_flag=True, help="Enable Docker sandbox for pro tools")
def recon(
    target: str,
    config_path: str | None,
    scope_path: str | None,
    output_file: str,
    lightweight: bool,
    sandbox: bool,
):
    """Run only the reconnaissance pipeline against TARGET."""
    console.print(BANNER)
    console.print(f"  [bold cyan]Recon-only mode:[/bold cyan] {target}\n")

    cfg = load_config(Path(config_path) if config_path else None)
    cfg = apply_scan_sandbox_cli(cfg, lightweight=lightweight, sandbox=sandbox)
    if lightweight:
        console.print("  [bold cyan]Mode:[/bold cyan] Lightweight (Python-native only)\n")
    elif cfg.sandbox.enabled:
        console.print(f"  [bold cyan]Docker sandbox:[/bold cyan] enabled ({cfg.sandbox.image})\n")
    scan_target = ScanTarget(host=target)

    scope_manager = None
    if scope_path:
        from vulnhunter.scope import ScopeManager
        scope_manager = ScopeManager.from_yaml(Path(scope_path))

    def on_action(action: AgentAction):
        if action.action_type == "tool_call":
            console.print(f"  [cyan]>[/cyan] {action.tool_name}...")
        elif action.action_type == "thinking":
            console.print(f"  [yellow]>[/yellow] {action.thought[:100]}")

    from vulnhunter.agents.orchestrator import OrchestratorAgent

    orchestrator = OrchestratorAgent(config=cfg, on_action=on_action, scope_manager=scope_manager)
    report = asyncio.run(orchestrator.run(scan_target))

    import json
    results = {
        "target": target,
        "vulnerabilities": [
            {"title": v.title, "severity": v.severity.value, "tool": v.tool}
            for v in report.vulnerabilities
        ],
        "tool_results": [
            {"tool": tr.tool_name, "success": tr.success, "data": tr.data}
            for tr in report.tool_results
        ],
    }
    Path(output_file).write_text(json.dumps(results, indent=2), encoding="utf-8")
    console.print(f"\n  [green]>[/green] Results saved to {output_file}")


@main.command()
@click.option("--scan-id", required=True, help="Scan ID to generate report from")
@click.option("--format", "fmt", default="hackerone", type=click.Choice(["hackerone", "bugcrowd"]), help="Report format")
@click.option("--output", "-o", "output_file", default=None, help="Output file path")
def report(scan_id: str, fmt: str, output_file: str | None):
    """Generate a bug bounty submission report from an existing scan."""
    console.print(f"  [bold cyan]Generating {fmt} report for scan {scan_id}...[/bold cyan]")
    console.print("  [dim]This requires database access. Use the web UI for easier report generation.[/dim]")


@main.command()
@click.option("--host", default="127.0.0.1", help="Server host")
@click.option("--port", default=8477, help="Server port")
def ui(host: str, port: int):
    """Launch the VulnHunter web dashboard."""
    try:
        console.print(BANNER)
    except Exception:
        print("VulnHunter - AI Penetration Testing")
    console.print(f"  [bold green]Starting VulnHunter Web UI...[/bold green]")
    console.print(f"  [bold cyan]Dashboard:[/bold cyan] http://{host}:{port}")
    console.print(f"  [dim]Press Ctrl+C to stop[/dim]\n")

    from vulnhunter.ui.server import run_server
    run_server(host=host, port=port)


if __name__ == "__main__":
    main()
