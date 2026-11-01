# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.exporters.json_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""JSON format exporter for sentinel scan findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from lh_repo_sentinel import __version__
from lh_repo_sentinel.models import Finding, Severity


def generate_json_dict(findings: Sequence[Finding]) -> dict[str, Any]:
    """Generate structured dictionary representing the scan findings.

    Args:
        findings: Sequence of detected findings.

    Returns:
        Dictionary formatted for JSON serialization.
    """
    counts = {sev.value.lower(): 0 for sev in Severity}
    for f in findings:
        key = f.severity.value.lower()
        counts[key] = counts.get(key, 0) + 1

    return {
        "tool": {
            "name": "lh-repo-sentinel",
            "version": __version__,
            "vendor": "Logihertz Systems OPC Pvt Ltd",
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
        },
        "findings": [f.to_dict() for f in findings],
    }


def export_json(
    findings: Sequence[Finding],
    output_path: Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize findings to JSON string and optionally write to file.

    Args:
        findings: Sequence of findings.
        output_path: Optional destination file path.
        indent: JSON indentation spacing.

    Returns:
        Serialized JSON string.
    """
    data = generate_json_dict(findings)
    json_str = json.dumps(data, indent=indent, ensure_ascii=False)

    if output_path:
        output_path.write_text(json_str, encoding="utf-8")

    return json_str
