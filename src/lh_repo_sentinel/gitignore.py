# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.gitignore
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Gitignore rule parser and path filtering utilities."""

from __future__ import annotations

import fnmatch
from pathlib import Path

DEFAULT_IGNORED_NAMES: set[str] = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".DS_Store",
}


def is_binary_file(file_path: Path, sample_size: int = 8192) -> bool:
    """Determine whether a file is binary by checking for null bytes in initial sample.

    Args:
        file_path: Path to the target file.
        sample_size: Number of bytes to sample from the beginning of the file.

    Returns:
        True if null byte is present, False otherwise.
    """
    try:
        with file_path.open("rb") as f:
            chunk = f.read(sample_size)
            return b"\x00" in chunk
    except OSError:
        return True


def load_gitignore_patterns(root_dir: Path) -> list[str]:
    """Load and normalize ignore patterns from .gitignore and .sentinelignore if present.

    Args:
        root_dir: Root directory of the repository or scan target.

    Returns:
        A list of cleaned ignore patterns.
    """
    patterns: list[str] = []
    for fname in [".gitignore", ".sentinelignore"]:
        ignore_file = root_dir / fname
        if not ignore_file.is_file():
            continue

        try:
            with ignore_file.open("r", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    patterns.append(line)
        except OSError:
            pass

    return patterns


def should_ignore_path(
    path: Path,
    root_dir: Path,
    extra_patterns: list[str] | None = None,
) -> bool:
    """Check if a path matches built-in ignore lists or loaded gitignore patterns.

    Args:
        path: Path of the file or directory to check.
        root_dir: Root directory of the scan.
        extra_patterns: Optional list of .gitignore patterns.

    Returns:
        True if the path should be ignored, False otherwise.
    """
    # Check default ignored names against all path parts
    for part in path.parts:
        if part in DEFAULT_IGNORED_NAMES or part.endswith(".egg-info"):
            return True

    patterns = extra_patterns or []
    if not patterns:
        return False

    try:
        relative = path.relative_to(root_dir)
        rel_str = relative.as_posix()
        rel_parts = relative.parts
    except ValueError:
        rel_str = path.as_posix()
        rel_parts = path.parts

    for pattern in patterns:
        clean_pat = pattern.rstrip("/")
        # If pattern starts with '/', match against relative path directly
        if pattern.startswith("/"):
            clean_root_pat = clean_pat.lstrip("/")
            if fnmatch.fnmatch(rel_str, clean_root_pat):
                return True
            if fnmatch.fnmatch(rel_str, clean_root_pat + "/*"):
                return True
        else:
            # Match anywhere in path
            if fnmatch.fnmatch(path.name, clean_pat):
                return True
            if fnmatch.fnmatch(rel_str, clean_pat):
                return True
            if fnmatch.fnmatch(rel_str, f"*/{clean_pat}"):
                return True
            if fnmatch.fnmatch(rel_str, f"*/{clean_pat}/*"):
                return True
            if fnmatch.fnmatch(rel_str, f"{clean_pat}/*"):
                return True
            # Also check individual relative path parts for directory exclusion
            if any(fnmatch.fnmatch(part, clean_pat) for part in rel_parts):
                return True

    return False
