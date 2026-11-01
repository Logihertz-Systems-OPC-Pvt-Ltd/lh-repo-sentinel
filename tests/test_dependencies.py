# lh-sentinel: ignore-file
"""Unit tests for dependency manifest auditor."""

from lh_repo_sentinel.dependencies import (
    audit_dependency_file,
    audit_package_json,
    audit_pyproject_toml,
    audit_requirements_txt,
)
from lh_repo_sentinel.models import FindingType, Severity


def test_audit_requirements_txt_unpinned(tmp_path):
    """Test auditing unpinned and wildcard dependencies in requirements.txt."""
    req_file = tmp_path / "requirements.txt"
    content = (
        "# Dependencies\n"
        "requests\n"
        "flask==*\n"
        "fastapi==0.110.0\n"
        "pytest>=*\n"
        "black # lh-sentinel: ignore\n"
        "-r other.txt\n"
    )
    req_file.write_text(content, encoding="utf-8")

    findings = audit_requirements_txt(req_file)

    rule_ids = [f.rule_id for f in findings]
    assert "UNPINNED_DEPENDENCY" in rule_ids
    assert "UNPINNED_WILDCARD_DEPENDENCY" in rule_ids

    # fastapi is pinned, should not be flagged
    assert not any(f.secret_snippet == "fastapi" for f in findings)
    # black has ignore comment, should not be flagged
    assert not any(f.secret_snippet == "black" for f in findings)


def test_audit_package_json_wildcards(tmp_path):
    """Test auditing npm package.json for wildcard versions."""
    pkg_file = tmp_path / "package.json"
    content = """{
  "name": "sample-app",
  "dependencies": {
    "react": "18.2.0",
    "lodash": "*",
    "express": "latest",
    "axios": "^1.x",
    "ignored-lib": "*" // lh-sentinel: ignore
  }
}"""
    pkg_file.write_text(content, encoding="utf-8")

    findings = audit_package_json(pkg_file)

    # react is pinned
    assert not any("react" in f.secret_snippet for f in findings)
    # ignored-lib is ignored
    assert not any("ignored-lib" in f.secret_snippet for f in findings)

    # lodash and express should trigger wildcard
    assert any("lodash" in f.secret_snippet for f in findings)
    assert any("express" in f.secret_snippet for f in findings)
    assert any("axios" in f.secret_snippet for f in findings)


def test_audit_pyproject_toml_unpinned(tmp_path):
    """Test auditing pyproject.toml for unpinned dependencies."""
    pyproject_file = tmp_path / "pyproject.toml"
    content = """[project]
name = "sample-tool"
version = "0.1.0"
dependencies = [
    "requests",
    "rich>=13.0.0",
    "typer=*"
]

[tool.poetry.dependencies]
python = "^3.11"
flask = "*"
"""
    pyproject_file.write_text(content, encoding="utf-8")

    findings = audit_pyproject_toml(pyproject_file)

    snippets = [f.secret_snippet for f in findings]
    assert "requests" in snippets
    assert any("typer" in s for s in snippets)
    assert any("flask" in s for s in snippets)
    assert not any("rich" in s for s in snippets)


def test_audit_dependency_file_dispatcher(tmp_path):
    """Verify audit_dependency_file dispatcher behavior for different manifest types."""
    req_file = tmp_path / "requirements-dev.txt"
    req_file.write_text("flake8\n", encoding="utf-8")

    findings = audit_dependency_file(req_file)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.DEPENDENCY
    assert findings[0].severity == Severity.MEDIUM
