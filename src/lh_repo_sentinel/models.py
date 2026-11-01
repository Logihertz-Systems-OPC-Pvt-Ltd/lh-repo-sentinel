# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        src.lh_repo_sentinel.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and enumerations for lh-repo-sentinel."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Finding severity levels ordered by criticality."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level(self) -> int:
        """Numeric rank for severity comparison (higher means more severe)."""
        ranks = {
            Severity.CRITICAL: 50,
            Severity.HIGH: 40,
            Severity.MEDIUM: 30,
            Severity.LOW: 20,
            Severity.INFO: 10,
        }
        return ranks.get(self, 0)

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.level >= other.level
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.level > other.level
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.level <= other.level
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.level < other.level
        return NotImplemented


class FindingType(str, Enum):
    """Categorical type for scanner findings."""

    SECRET = "SECRET"  # nosec B105
    HIGH_ENTROPY = "HIGH_ENTROPY"
    DEPENDENCY = "DEPENDENCY"


@dataclass
class Finding:
    """Represents a single security or compliance issue detected by sentinel."""

    rule_id: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    severity: Severity
    finding_type: FindingType
    entropy: float | None = None
    secret_snippet: str = ""
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        """Calculate fingerprint if none was explicitly provided."""
        if not self.fingerprint:
            raw_id = f"{self.file_path}:{self.line_number}:{self.rule_id}:{self.secret_snippet}"
            self.fingerprint = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a plain dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "severity": self.severity.value,
            "finding_type": self.finding_type.value,
            "entropy": round(self.entropy, 4) if self.entropy is not None else None,
            "secret_snippet": self.secret_snippet,
            "fingerprint": self.fingerprint,
        }
