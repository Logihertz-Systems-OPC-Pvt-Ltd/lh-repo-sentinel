"""SARIF (Static Analysis Results Interchange Format) v2.1.0 exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from lh_repo_sentinel import __version__
from lh_repo_sentinel.models import Finding, Severity

SARIF_SCHEMA_V2 = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def severity_to_sarif_level(severity: Severity) -> str:
    """Map internal Severity enum to official SARIF v2.1.0 level string.

    Args:
        severity: Finding severity.

    Returns:
        One of 'error', 'warning', 'note', or 'none'.
    """
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def generate_sarif_dict(findings: Sequence[Finding]) -> dict[str, Any]:
    """Build a complete SARIF v2.1.0 document dictionary.

    Args:
        findings: Sequence of findings to include in report.

    Returns:
        Dictionary adhering to SARIF v2.1.0 schema.
    """
    rule_ids_seen: dict[str, dict[str, Any]] = {}

    results: list[dict[str, Any]] = []
    for f in findings:
        sarif_level = severity_to_sarif_level(f.severity)

        if f.rule_id not in rule_ids_seen:
            rule_ids_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("_", " ").title(),
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {"level": sarif_level},
            }

        start_line = max(1, f.line_number)
        result_item: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": sarif_level,
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(f.file_path).as_posix(),
                        },
                        "region": {
                            "startLine": start_line,
                            "snippet": {
                                "text": f.secret_snippet or f.line_content,
                            },
                        },
                    }
                }
            ],
            "fingerprints": {
                "contextHash/v1": f.fingerprint,
            },
        }
        results.append(result_item)

    return {
        "$schema": SARIF_SCHEMA_V2,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-repo-sentinel",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-repo-sentinel",
                        "semanticVersion": __version__,
                        "rules": list(rule_ids_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(
    findings: Sequence[Finding],
    output_path: Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize findings to SARIF v2.1.0 JSON format and optionally write to file.

    Args:
        findings: Sequence of findings.
        output_path: Optional file path to write results.
        indent: Indentation spaces for JSON formatting.

    Returns:
        SARIF JSON string.
    """
    data = generate_sarif_dict(findings)
    sarif_str = json.dumps(data, indent=indent, ensure_ascii=False)

    if output_path:
        output_path.write_text(sarif_str, encoding="utf-8")

    return sarif_str
