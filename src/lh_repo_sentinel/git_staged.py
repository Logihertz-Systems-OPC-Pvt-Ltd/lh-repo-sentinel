# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.git_staged
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Git staged diff scanner and pre-commit hook management."""

from __future__ import annotations

import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Sequence

from lh_repo_sentinel.dependencies import audit_dependency_file
from lh_repo_sentinel.models import Finding
from lh_repo_sentinel.rules import DEFAULT_RULES, SecretRule
from lh_repo_sentinel.scanner import scan_line

HUNK_HEADER_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def get_git_repo_root(cwd: Path | None = None) -> Path | None:
    """Find the top-level directory of the active Git repository.

    Args:
        cwd: Directory from which to search (defaults to current working directory).

    Returns:
        Path to repo root, or None if not within a git repository.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except OSError:
        pass
    return None


def get_staged_diff(cwd: Path | None = None) -> str:
    """Retrieve unified diff of all staged changes from git.

    Args:
        cwd: Directory context for git command execution.

    Returns:
        Unified diff string output from git diff --cached.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "diff", "--cached", "--unified=0"],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
    except OSError:
        pass
    return ""


def get_staged_files(cwd: Path | None = None) -> list[str]:
    """List relative paths of all staged files in the git index.

    Args:
        cwd: Directory context for git command execution.

    Returns:
        List of staged file paths.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["git", "diff", "--cached", "--name-only"],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except OSError:
        pass
    return []


def scan_staged_diff(
    diff_text: str,
    repo_root: Path | None = None,
    entropy_threshold: float = 4.5,
    rules: Sequence[SecretRule] = DEFAULT_RULES,
) -> list[Finding]:
    """Parse git unified diff output and scan added/modified lines for secrets.

    Args:
        diff_text: Output from git diff --cached.
        repo_root: Path to repository root.
        entropy_threshold: Shannon entropy threshold.
        rules: Secret detection rules.

    Returns:
        List of findings detected within staged lines.
    """
    findings: list[Finding] = []
    current_file: str | None = None
    current_line_no = 0

    for raw_line in diff_text.splitlines():
        # Track file name
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue
        if raw_line.startswith("+++ /dev/null"):
            current_file = None
            continue

        # Track hunk position
        hunk_match = HUNK_HEADER_PATTERN.match(raw_line)
        if hunk_match:
            current_line_no = int(hunk_match.group(1))
            continue

        # Check added lines
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_content = raw_line[1:]
            if current_file:
                line_findings = scan_line(
                    file_path=current_file,
                    line_number=current_line_no,
                    line_content=line_content,
                    entropy_threshold=entropy_threshold,
                    rules=rules,
                )
                findings.extend(line_findings)
            current_line_no += 1
        elif not raw_line.startswith("-"):
            # Context lines increment line number
            current_line_no += 1

    # Also audit staged dependency files completely if staged
    if repo_root:
        for staged_rel in get_staged_files(repo_root):
            staged_path = repo_root / staged_rel
            if staged_path.is_file() and staged_path.name.lower() in (
                "package.json",
                "pyproject.toml",
                "requirements.txt",
            ):
                dep_findings = audit_dependency_file(staged_path)
                for df in dep_findings:
                    if not any(
                        f.file_path == df.file_path and f.line_number == df.line_number
                        for f in findings
                    ):
                        findings.append(df)

    findings.sort(key=lambda f: (-f.severity.level, f.file_path, f.line_number))
    return findings


def install_pre_commit_hook(repo_root: Path | None = None) -> Path:
    """Install git pre-commit hook into .git/hooks directory.

    Args:
        repo_root: Root directory of repository (auto-detected if None).

    Returns:
        Path to installed hook file.

    Raises:
        RuntimeError: If not within a valid git repository.
    """
    root = repo_root or get_git_repo_root()
    if not root:
        raise RuntimeError("No Git repository found in current directory tree.")

    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_file = hooks_dir / "pre-commit"
    hook_script = (
        "#!/bin/sh\n# Logihertz Sentinel pre-commit security check\nlh-sentinel staged --strict\n"
    )

    hook_file.write_text(hook_script, encoding="utf-8")
    # Make executable
    mode = hook_file.stat().st_mode
    hook_file.chmod(mode | 0o755)

    return hook_file
