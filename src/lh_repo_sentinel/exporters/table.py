# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table output formatter for sentinel findings."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_repo_sentinel.models import Finding, Severity

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def build_findings_table(findings: Sequence[Finding]) -> Table:
    """Construct a rich Table displaying individual security findings.

    Args:
        findings: Sequence of findings to render.

    Returns:
        Populated rich Table object.
    """
    table = Table(
        title="[bold cyan]lh-repo-sentinel Findings Report[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )

    table.add_column("Rule ID", style="cyan", no_wrap=True, min_width=16)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Location", style="green", no_wrap=False)
    table.add_column("Snippet / Target", style="dim")
    table.add_column("Description")

    for f in findings:
        sev_style = SEVERITY_STYLES.get(f.severity, "white")
        location = f"{f.file_path}:{f.line_number}" if f.line_number > 0 else f.file_path
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            location,
            f.secret_snippet or f.line_content[:30],
            f.description,
        )

    return table


def build_summary_panel(findings: Sequence[Finding]) -> Panel:
    """Build a summary panel highlighting finding totals and severity distribution.

    Args:
        findings: Sequence of findings to summarize.

    Returns:
        Rich Panel containing summary details.
    """
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(findings)
    lines = [
        f"[bold]Total Findings:[/bold] {total}",
        f"[bold red]Critical:[/bold red] {counts[Severity.CRITICAL]}  |  "
        f"[red]High:[/red] {counts[Severity.HIGH]}  |  "
        f"[yellow]Medium:[/yellow] {counts[Severity.MEDIUM]}  |  "
        f"[cyan]Low/Info:[/cyan] {counts[Severity.LOW] + counts[Severity.INFO]}",
    ]

    border_color = "red" if counts[Severity.CRITICAL] > 0 else "green"
    return Panel(
        "\n".join(lines),
        title="Scan Summary",
        border_style=border_color,
        expand=False,
    )


def render_findings_table(
    findings: Sequence[Finding],
    console: Console | None = None,
) -> None:
    """Print findings table and summary directly to terminal console.

    Args:
        findings: Sequence of findings to display.
        console: Optional existing Rich console instance.
    """
    con = console or Console()
    if not findings:
        con.print(
            Panel(
                "[bold green]No security secrets or unpinned dependencies detected![/bold green]",
                title="lh-repo-sentinel",
                border_style="green",
            )
        )
        return

    table = build_findings_table(findings)
    summary = build_summary_panel(findings)

    con.print(table)
    con.print()
    con.print(summary)


def export_table(
    findings: Sequence[Finding],
    output_path: Path | None = None,
    console: Console | None = None,
) -> str:
    """Export formatted findings table to string and optionally write to file.

    Args:
        findings: Sequence of findings.
        output_path: Optional file path to write rendered text.
        console: Optional Rich console.

    Returns:
        Plain rendered text representation.
    """
    buffer = io.StringIO()
    file_console = Console(file=buffer, force_terminal=False, width=120)

    if not findings:
        file_console.print("No security secrets or unpinned dependency risks detected.")
    else:
        table = build_findings_table(findings)
        summary = build_summary_panel(findings)
        file_console.print(table)
        file_console.print()
        file_console.print(summary)

    output_str = buffer.getvalue()

    if output_path:
        output_path.write_text(output_str, encoding="utf-8")
    elif console:
        render_findings_table(findings, console)

    return output_str
