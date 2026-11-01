# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.dependencies
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Dependency manifest auditor checking for unpinned wildcard packages."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from lh_repo_sentinel.models import Finding, FindingType, Severity

INLINE_IGNORE_MARKER = "lh-sentinel: ignore"

# Match Python package specifier without version or with wildcard
REQ_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.]+")
WILDCARD_PATTERN = re.compile(r"\*|\.x\b|\.X\b")


def _is_ignored_line(line: str) -> bool:
    """Return True if the line contains sentinel ignore directive."""
    return INLINE_IGNORE_MARKER in line


def audit_requirements_txt(file_path: Path) -> list[Finding]:
    """Audit requirements.txt format file for unpinned or wildcard dependencies.

    Args:
        file_path: Path to the requirements.txt file.

    Returns:
        List of findings for unpinned or wildcard requirements.
    """
    findings: list[Finding] = []
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if _is_ignored_line(line):
            continue

        # Strip inline comment
        comment_split = line.split("#", 1)
        entry = comment_split[0].strip()

        # Skip pip flags
        if entry.startswith(("-", "--", "@")):
            continue

        # Check for wildcard versions (e.g., pkg==*, pkg>=*, pkg*)
        if "*" in entry or ".x" in entry.lower():
            findings.append(
                Finding(
                    rule_id="UNPINNED_WILDCARD_DEPENDENCY",
                    description=f"Dependency '{entry}' specifies an unsafe wildcard version",
                    file_path=str(file_path),
                    line_number=idx,
                    line_content=line,
                    severity=Severity.HIGH,
                    finding_type=FindingType.DEPENDENCY,
                    secret_snippet=entry,
                )
            )
            continue

        # Check for completely unpinned package names without comparison operators
        if not any(op in entry for op in ["==", ">=", "<=", "~=", "!=", "==="]):
            name_match = REQ_NAME_PATTERN.match(entry)
            if name_match:
                pkg_name = name_match.group(0)
                findings.append(
                    Finding(
                        rule_id="UNPINNED_DEPENDENCY",
                        description=f"Dependency '{pkg_name}' has no pinned version constraint",
                        file_path=str(file_path),
                        line_number=idx,
                        line_content=line,
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.DEPENDENCY,
                        secret_snippet=pkg_name,
                    )
                )

    return findings


def _clean_json_comments(text: str) -> str:
    """Strip JavaScript-style comments to support JSON with comments."""
    cleaned = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    return cleaned


def audit_package_json(file_path: Path) -> list[Finding]:
    """Audit package.json for unpinned or wildcard dependencies.

    Args:
        file_path: Path to package.json.

    Returns:
        List of findings for unpinned or wildcard npm packages.
    """
    findings: list[Finding] = []
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        sanitized_json = _clean_json_comments(raw_text)
        data = json.loads(sanitized_json)
    except (OSError, json.JSONDecodeError):
        return findings

    lines = raw_text.splitlines()

    def find_line_for_key(key: str) -> tuple[int, str]:
        escaped_key = f'"{key}"'
        for i, line in enumerate(lines, start=1):
            if escaped_key in line:
                return i, line.strip()
        return 1, ""

    dep_sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ]

    for section in dep_sections:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue

        for pkg_name, version in deps.items():
            if not isinstance(version, str):
                continue

            v_clean = version.strip()
            line_no, line_content = find_line_for_key(pkg_name)

            if _is_ignored_line(line_content):
                continue

            if v_clean in ("*", "latest", ""):
                findings.append(
                    Finding(
                        rule_id="UNPINNED_WILDCARD_DEPENDENCY",
                        description=(
                            f"NPM package '{pkg_name}' in '{section}' uses wildcard "
                            f"or latest version '{version}'"
                        ),
                        file_path=str(file_path),
                        line_number=line_no,
                        line_content=line_content or f'"{pkg_name}": "{version}"',
                        severity=Severity.HIGH,
                        finding_type=FindingType.DEPENDENCY,
                        secret_snippet=f"{pkg_name}@{version}",
                    )
                )
            elif WILDCARD_PATTERN.search(v_clean):
                findings.append(
                    Finding(
                        rule_id="UNPINNED_WILDCARD_DEPENDENCY",
                        description=(
                            f"NPM package '{pkg_name}' in '{section}' uses wildcard "
                            f"pattern '{version}'"
                        ),
                        file_path=str(file_path),
                        line_number=line_no,
                        line_content=line_content or f'"{pkg_name}": "{version}"',
                        severity=Severity.MEDIUM,
                        finding_type=FindingType.DEPENDENCY,
                        secret_snippet=f"{pkg_name}@{version}",
                    )
                )

    return findings


def audit_pyproject_toml(file_path: Path) -> list[Finding]:
    """Audit pyproject.toml for unpinned or wildcard dependencies.

    Args:
        file_path: Path to pyproject.toml.

    Returns:
        List of findings for unpinned or wildcard python packages in pyproject.toml.
    """
    findings: list[Finding] = []
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(raw_text)
    except (OSError, tomllib.TOMLDecodeError):
        return findings

    lines = raw_text.splitlines()

    def find_line_for_pkg(pkg_str: str) -> tuple[int, str]:
        for i, line in enumerate(lines, start=1):
            if pkg_str in line:
                return i, line.strip()
        return 1, ""

    # Check project.dependencies (PEP 621)
    project_table = data.get("project", {})
    if isinstance(project_table, dict):
        dependencies = project_table.get("dependencies", [])
        if isinstance(dependencies, list):
            for dep in dependencies:
                if not isinstance(dep, str):
                    continue
                line_no, line_content = find_line_for_pkg(dep)
                if _is_ignored_line(line_content):
                    continue

                if "*" in dep:
                    findings.append(
                        Finding(
                            rule_id="UNPINNED_WILDCARD_DEPENDENCY",
                            description=f"Python dependency '{dep}' uses unsafe wildcard",
                            file_path=str(file_path),
                            line_number=line_no,
                            line_content=line_content or dep,
                            severity=Severity.HIGH,
                            finding_type=FindingType.DEPENDENCY,
                            secret_snippet=dep,
                        )
                    )
                elif not any(op in dep for op in ["==", ">=", "<=", "~=", "!=", "==="]):
                    name_match = REQ_NAME_PATTERN.match(dep)
                    if name_match:
                        findings.append(
                            Finding(
                                rule_id="UNPINNED_DEPENDENCY",
                                description=(
                                    f"Dependency '{name_match.group(0)}' "
                                    f"has no pinned version constraint"
                                ),
                                file_path=str(file_path),
                                line_number=line_no,
                                line_content=line_content or dep,
                                severity=Severity.MEDIUM,
                                finding_type=FindingType.DEPENDENCY,
                                secret_snippet=name_match.group(0),
                            )
                        )

    # Check Poetry tool.poetry.dependencies
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for pkg, spec in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            line_no, line_content = find_line_for_pkg(pkg)
            if _is_ignored_line(line_content):
                continue

            if isinstance(spec, str) and (spec == "*" or "*" in spec):
                findings.append(
                    Finding(
                        rule_id="UNPINNED_WILDCARD_DEPENDENCY",
                        description=f"Poetry dependency '{pkg}' uses wildcard version '{spec}'",
                        file_path=str(file_path),
                        line_number=line_no,
                        line_content=line_content or f"{pkg} = {spec}",
                        severity=Severity.HIGH,
                        finding_type=FindingType.DEPENDENCY,
                        secret_snippet=f"{pkg} = {spec}",
                    )
                )

    return findings


def audit_dependency_file(file_path: Path) -> list[Finding]:
    """Dispatch file to corresponding dependency manifest auditor based on name.

    Args:
        file_path: Path to the target dependency file.

    Returns:
        List of findings discovered in the file.
    """
    name = file_path.name.lower()
    if name == "package.json":
        return audit_package_json(file_path)
    if name == "pyproject.toml":
        return audit_pyproject_toml(file_path)
    if name == "requirements.txt" or (name.startswith("requirements") and name.endswith(".txt")):
        return audit_requirements_txt(file_path)
    return []
