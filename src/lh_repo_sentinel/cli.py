"""Command-line interface for lh-repo-sentinel."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from lh_repo_sentinel.exporters import (
    export_json,
    export_sarif,
    export_table,
    render_findings_table,
)
from lh_repo_sentinel.git_staged import (
    get_git_repo_root,
    get_staged_diff,
    install_pre_commit_hook,
    scan_staged_diff,
)
from lh_repo_sentinel.models import Severity
from lh_repo_sentinel.scanner import scan_directory

app = typer.Typer(
    name="lh-sentinel",
    help="Static analysis CLI and Git pre-commit scanner by Logihertz Systems.",
    add_completion=False,
)
console = Console()


class OutputFormat(str, Enum):
    """Supported output formats for scan reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


@app.command(name="scan")
def scan_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Directory or file path to scan.",
            exists=True,
            file_okay=True,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    entropy_threshold: Annotated[
        float,
        typer.Option(
            "--entropy-threshold",
            "-e",
            help="Shannon entropy threshold to flag candidate credentials.",
            min=1.0,
            max=8.0,
        ),
    ] = 4.5,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Report output format.",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Optional file path to write findings report.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Fail with non-zero exit code on any finding rather than only critical.",
        ),
    ] = False,
) -> None:
    """Scan source code files or directories for hardcoded secrets and unpinned dependencies."""
    findings = scan_directory(
        target_path=path,
        entropy_threshold=entropy_threshold,
        respect_gitignore=True,
    )

    if output_format == OutputFormat.TABLE:
        if output:
            export_table(findings, output_path=output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            render_findings_table(findings, console)
    elif output_format == OutputFormat.JSON:
        json_output = export_json(findings, output_path=output)
        if output:
            console.print(f"[green]JSON report written to {output}[/green]")
        else:
            typer.echo(json_output)
    elif output_format == OutputFormat.SARIF:
        sarif_output = export_sarif(findings, output_path=output)
        if output:
            console.print(f"[green]SARIF report written to {output}[/green]")
        else:
            typer.echo(sarif_output)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    should_fail = (strict and bool(findings)) or has_critical

    if should_fail:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="staged")
def staged_command(
    entropy_threshold: Annotated[
        float,
        typer.Option(
            "--entropy-threshold",
            "-e",
            help="Shannon entropy threshold to flag candidate credentials.",
            min=1.0,
            max=8.0,
        ),
    ] = 4.5,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Report output format.",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Optional file path to write findings report.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--no-strict",
            help="Fail with exit code 1 if any findings are discovered.",
        ),
    ] = True,
) -> None:
    """Scan staged Git diff changes before commit."""
    repo_root = get_git_repo_root()
    diff_text = get_staged_diff(repo_root)

    findings = scan_staged_diff(
        diff_text=diff_text,
        repo_root=repo_root,
        entropy_threshold=entropy_threshold,
    )

    if output_format == OutputFormat.TABLE:
        if output:
            export_table(findings, output_path=output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            render_findings_table(findings, console)
    elif output_format == OutputFormat.JSON:
        json_output = export_json(findings, output_path=output)
        if output:
            console.print(f"[green]JSON report written to {output}[/green]")
        else:
            typer.echo(json_output)
    elif output_format == OutputFormat.SARIF:
        sarif_output = export_sarif(findings, output_path=output)
        if output:
            console.print(f"[green]SARIF report written to {output}[/green]")
        else:
            typer.echo(sarif_output)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    should_fail = (strict and bool(findings)) or has_critical

    if should_fail:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="install-hook")
def install_hook_command() -> None:
    """Install lh-sentinel as a Git pre-commit hook in the current repository."""
    try:
        hook_path = install_pre_commit_hook()
        console.print(
            f"[bold green]Successfully installed pre-commit hook at {hook_path}[/bold green]"
        )
    except RuntimeError as exc:
        console.print(f"[bold red]Failed to install hook:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


def main() -> None:
    """Entry point for lh-sentinel CLI."""
    app()


if __name__ == "__main__":
    main()
