# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        tests.test_scanner_ignores
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

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


def test_sentinelignore_filtering(tmp_path: Path):
    """Verify directory scanner respects .sentinelignore rules."""
    sentinelignore = tmp_path / ".sentinelignore"
    sentinelignore.write_text("mock_tests/\n*.fixture.py\n", encoding="utf-8")

    # Directory matching pattern
    mock_dir = tmp_path / "mock_tests"
    mock_dir.mkdir()
    (mock_dir / "test_keys.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    # File matching pattern
    (tmp_path / "creds.fixture.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )

    # Clean file
    (tmp_path / "app.py").write_text("x = 100\n", encoding="utf-8")

    findings = scan_directory(tmp_path, respect_gitignore=True)
    assert len(findings) == 0


def test_file_level_ignore_header_with_long_banner(tmp_path: Path):
    """Verify ignore-file directive is recognized even following a long header comment."""
    banner = "\n".join([f"# Header comment line {i}" for i in range(15)])
    content = f'{banner}\n# lh-sentinel: ignore-file\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    target = tmp_path / "flagged_module.py"
    target.write_text(content, encoding="utf-8")

    findings = scan_file(target)
    assert len(findings) == 0


def test_alternate_ignore_markers():
    """Verify alternative inline and whole-file ignore markers."""
    # Inline nosec
    line_nosec = 'KEY = "AKIAIOSFODNN7EXAMPLE" # nosec'
    assert len(scan_line("test.py", 1, line_nosec)) == 0

    # Inline sentinel: ignore
    line_sentinel = 'KEY = "AKIAIOSFODNN7EXAMPLE" # sentinel: ignore'
    assert len(scan_line("test.py", 1, line_sentinel)) == 0
