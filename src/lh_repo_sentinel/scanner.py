# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Core repository and file scanner integrating secret rules, entropy, and dependency checks."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from lh_repo_sentinel.dependencies import audit_dependency_file
from lh_repo_sentinel.entropy import calculate_entropy, find_high_entropy_tokens
from lh_repo_sentinel.gitignore import (
    is_binary_file,
    load_gitignore_patterns,
    should_ignore_path,
)
from lh_repo_sentinel.models import Finding, FindingType, Severity
from lh_repo_sentinel.rules import DEFAULT_RULES, SecretRule, mask_secret

INLINE_IGNORE_MARKER = "lh-sentinel: ignore"
FILE_IGNORE_MARKER = "lh-sentinel: ignore-file"


def is_ignored_line(line: str) -> bool:
    """Check if the line contains an inline sentinel ignore directive."""
    return INLINE_IGNORE_MARKER in line


def scan_line(
    file_path: str,
    line_number: int,
    line_content: str,
    entropy_threshold: float = 4.5,
    rules: Sequence[SecretRule] = DEFAULT_RULES,
) -> list[Finding]:
    """Inspect an individual line of source code for regex secrets and high entropy tokens.

    Args:
        file_path: File path string for reporting.
        line_number: 1-based line number.
        line_content: The text content of the line.
        entropy_threshold: Threshold above which high entropy strings are reported.
        rules: Set of secret rules to evaluate against the line.

    Returns:
        A list of Finding objects found on this line.
    """
    if is_ignored_line(line_content):
        return []

    findings: list[Finding] = []
    matched_secrets: set[str] = set()

    # 1. Regex rules
    for rule in rules:
        for match in rule.pattern.finditer(line_content):
            if (
                rule.group_index > 0
                and match.lastindex is not None
                and rule.group_index <= match.lastindex
            ):
                secret_val = match.group(rule.group_index)
            else:
                secret_val = match.group(0)

            if not secret_val or secret_val in matched_secrets:
                continue

            matched_secrets.add(secret_val)
            token_entropy = calculate_entropy(secret_val)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line_content.strip(),
                    severity=rule.severity,
                    finding_type=FindingType.SECRET,
                    entropy=token_entropy,
                    secret_snippet=mask_secret(secret_val),
                )
            )

    # 2. Shannon entropy analysis for unidentified tokens
    high_entropy_tokens = find_high_entropy_tokens(
        line_content, threshold=entropy_threshold, min_length=16
    )
    for token, entropy_val in high_entropy_tokens:
        # Avoid duplicate alert if already captured by a specific regex rule
        if any(token in matched or matched in token for matched in matched_secrets):
            continue

        findings.append(
            Finding(
                rule_id="HIGH_ENTROPY_TOKEN",
                description=(
                    f"Identified high-entropy candidate credential (entropy: {entropy_val:.2f})"
                ),
                file_path=file_path,
                line_number=line_number,
                line_content=line_content.strip(),
                severity=Severity.HIGH if entropy_val >= 5.0 else Severity.MEDIUM,
                finding_type=FindingType.HIGH_ENTROPY,
                entropy=entropy_val,
                secret_snippet=mask_secret(token),
            )
        )

    return findings


def scan_file(
    file_path: Path,
    entropy_threshold: float = 4.5,
    rules: Sequence[SecretRule] = DEFAULT_RULES,
) -> list[Finding]:
    """Scan a single file for secrets, high-entropy tokens, and dependency risks.

    Args:
        file_path: Absolute or relative Path to the file.
        entropy_threshold: Shannon entropy threshold.
        rules: Secret detection rules.

    Returns:
        List of findings detected in the file.
    """
    if not file_path.is_file():
        return []

    if is_binary_file(file_path):
        return []

    findings: list[Finding] = []

    # Check for dependency manifest risks first
    dep_findings = audit_dependency_file(file_path)
    findings.extend(dep_findings)

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Check for whole-file ignore directive in header
    lines = content.splitlines()
    for header_line in lines[:5]:
        if FILE_IGNORE_MARKER in header_line:
            return []

    file_str = str(file_path)
    for idx, line in enumerate(lines, start=1):
        line_findings = scan_line(
            file_path=file_str,
            line_number=idx,
            line_content=line,
            entropy_threshold=entropy_threshold,
            rules=rules,
        )
        findings.extend(line_findings)

    return findings


def scan_directory(
    target_path: Path,
    entropy_threshold: float = 4.5,
    respect_gitignore: bool = True,
    rules: Sequence[SecretRule] = DEFAULT_RULES,
) -> list[Finding]:
    """Recursively scan a directory for hardcoded secrets and unpinned dependencies.

    Args:
        target_path: Root directory path to scan.
        entropy_threshold: Shannon entropy cutoff.
        respect_gitignore: Whether to load and apply .gitignore exclusion rules.
        rules: Secret detection rules.

    Returns:
        Consolidated list of findings sorted by severity.
    """
    findings: list[Finding] = []
    root = target_path.resolve()

    if root.is_file():
        return scan_file(root, entropy_threshold=entropy_threshold, rules=rules)

    gitignore_patterns = load_gitignore_patterns(root) if respect_gitignore else []

    for item in root.rglob("*"):
        if should_ignore_path(item, root, gitignore_patterns):
            continue

        if item.is_file():
            file_findings = scan_file(
                item,
                entropy_threshold=entropy_threshold,
                rules=rules,
            )
            findings.extend(file_findings)

    # Sort findings by severity descending, then file path and line number
    findings.sort(key=lambda f: (-f.severity.level, f.file_path, f.line_number))
    return findings
