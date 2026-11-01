# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

# lh-sentinel: ignore-file
"""Unit tests for lh-sentinel CLI commands and options."""

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_repo_sentinel.cli import app

runner = CliRunner()


def test_cli_help():
    """Verify CLI help message output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "lh-sentinel" in result.output
    assert "scan" in result.output
    assert "staged" in result.output
    assert "install-hook" in result.output


def test_cli_scan_clean_dir(tmp_path: Path):
    """Verify exit code 0 when scanning a clean directory."""
    clean_file = tmp_path / "hello.py"
    clean_file.write_text("print('clean code without secrets')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No security secrets or unpinned dependencies detected" in result.output


def test_cli_scan_with_secrets_fails(tmp_path: Path):
    """Verify exit code 1 when critical secrets are discovered."""
    dirty_file = tmp_path / "creds.py"
    dirty_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "AWS_" in result.output
    assert "Critical: 1" in result.output


def test_cli_scan_json_and_sarif_export(tmp_path: Path):
    """Verify JSON and SARIF export options via CLI."""
    dirty_file = tmp_path / "creds.py"
    dirty_file.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    # JSON output to stdout
    result_json = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result_json.exit_code == 1
    data = json.loads(result_json.output)
    assert data["summary"]["total_findings"] >= 1

    # SARIF output to file
    sarif_file = tmp_path / "report.sarif"
    result_sarif = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "sarif", "--output", str(sarif_file)]
    )
    assert result_sarif.exit_code == 1
    assert sarif_file.is_file()
    sarif_content = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_content["version"] == "2.1.0"


def test_cli_install_hook(tmp_path: Path, monkeypatch):
    """Verify pre-commit hook installer creates executable hook script."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    # Point get_git_repo_root to tmp_path
    mock_hook = git_dir / "hooks" / "pre-commit"
    monkeypatch.setattr("lh_repo_sentinel.cli.install_pre_commit_hook", lambda: mock_hook)

    result = runner.invoke(app, ["install-hook"])
    assert result.exit_code == 0
    assert "Successfully installed pre-commit hook" in result.output
