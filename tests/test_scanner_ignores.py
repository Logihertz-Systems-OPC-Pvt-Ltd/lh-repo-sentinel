# lh-sentinel: ignore-file
"""Unit tests for ignore directives, gitignore filtering, and directory scanner."""

import json
from pathlib import Path

from lh_repo_sentinel.exporters import export_json, export_sarif
from lh_repo_sentinel.gitignore import is_binary_file
from lh_repo_sentinel.models import Finding, FindingType, Severity
from lh_repo_sentinel.scanner import scan_directory, scan_file, scan_line


def test_inline_ignore_comment():
    """Verify inline ignore comments prevent secret detection."""
    secret_line = 'API_KEY = "AKIAIOSFODNN7EXAMPLE" # lh-sentinel: ignore'
    findings = scan_line("test.py", 1, secret_line)
    assert len(findings) == 0


def test_file_level_ignore_header(tmp_path: Path):
    """Verify ignore-file directive in header suppresses all findings."""
    f = tmp_path / "legacy_keys.py"
    f.write_text(
        '# lh-sentinel: ignore-file\n# Legacy credentials file\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        encoding="utf-8",
    )
    findings = scan_file(f)
    assert len(findings) == 0


def test_gitignore_filtering(tmp_path: Path):
    """Verify directory scanner respects .gitignore rules."""
    # Create gitignore
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("ignored_dir/\n*.secret.txt\n", encoding="utf-8")

    # Create ignored file in ignored dir
    ignored_dir = tmp_path / "ignored_dir"
    ignored_dir.mkdir()
    (ignored_dir / "key.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    # Create ignored extension file
    (tmp_path / "foo.secret.txt").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    # Create scanned file
    scanned_file = tmp_path / "clean.py"
    scanned_file.write_text("x = 42\n", encoding="utf-8")

    findings = scan_directory(tmp_path, respect_gitignore=True)
    assert len(findings) == 0


def test_binary_file_detection(tmp_path: Path):
    """Verify binary files containing null bytes are ignored."""
    bin_file = tmp_path / "binary_asset.bin"
    bin_file.write_bytes(b"some text \x00 with null bytes and AKIAIOSFODNN7EXAMPLE")

    assert is_binary_file(bin_file) is True
    findings = scan_file(bin_file)
    assert len(findings) == 0


def test_exporters():
    """Verify JSON and SARIF export output formatting."""
    dummy_finding = Finding(
        rule_id="AWS_ACCESS_KEY",
        description="Identified AWS Key",
        file_path="src/config.py",
        line_number=10,
        line_content="KEY = AKIA...",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SECRET,
        secret_snippet="AKIA****MPLE",
    )

    # Test JSON export
    json_str = export_json([dummy_finding])
    data = json.loads(json_str)
    assert data["tool"]["name"] == "lh-repo-sentinel"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["rule_id"] == "AWS_ACCESS_KEY"

    # Test SARIF export
    sarif_str = export_sarif([dummy_finding])
    sarif_data = json.loads(sarif_str)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["level"] == "error"
