"""Pre-configured detection rules and regex patterns for secrets and tokens."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from lh_repo_sentinel.models import Severity


@dataclass(frozen=True)
class SecretRule:
    """Detection rule definition matching high-risk credentials and tokens."""

    rule_id: str
    name: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    group_index: int = 0


def mask_secret(secret: str) -> str:
    """Mask sensitive secret substrings for safe presentation in reports.

    Args:
        secret: Raw secret string to mask.

    Returns:
        Partially redacted string showing only boundary characters.
    """
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix_len = 4
    suffix_len = 4
    masked_middle = "*" * min(12, len(secret) - (prefix_len + suffix_len))
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


DEFAULT_RULES: Sequence[SecretRule] = [
    SecretRule(
        rule_id="AWS_ACCESS_KEY",
        name="AWS Access Key ID",
        description="Identified AWS Access Key ID credential",
        pattern=re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        severity=Severity.CRITICAL,
        group_index=1,
    ),
    SecretRule(
        rule_id="AWS_SECRET_KEY",
        name="AWS Secret Access Key",
        description="Identified AWS Secret Access Key credential assignment",
        pattern=re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s:=]+["']?([A-Za-z0-9/+=]{40})["']?"""
        ),
        severity=Severity.CRITICAL,
        group_index=1,
    ),
    SecretRule(
        rule_id="GCP_API_KEY",
        name="GCP API Key",
        description="Identified Google Cloud Platform API Key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity=Severity.CRITICAL,
        group_index=1,
    ),
    SecretRule(
        rule_id="GCP_SERVICE_ACCOUNT",
        name="GCP Service Account Credential",
        description="Identified Google Cloud Service Account Private Key configuration",
        pattern=re.compile(
            r"""(?:"type":\s*"service_account"|"private_key_id":\s*"[a-f0-9]{40}")"""
        ),
        severity=Severity.CRITICAL,
        group_index=0,
    ),
    SecretRule(
        rule_id="GITHUB_TOKEN",
        name="GitHub Personal Access Token",
        description="Identified GitHub Personal, OAuth, or App Access Token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{82})\b"),
        severity=Severity.HIGH,
        group_index=1,
    ),
    SecretRule(
        rule_id="JWT_TOKEN",
        name="JSON Web Token (JWT)",
        description="Identified JSON Web Token containing sensitive claims or signatures",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        severity=Severity.HIGH,
        group_index=1,
    ),
    SecretRule(
        rule_id="DATABASE_URI",
        name="Database Connection URI with Credentials",
        description="Identified database connection string containing embedded credentials",
        pattern=re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|cockroachdb):\/\/[^:\s\/]+:[^@\s\/]+@[^\s\/]+)\b"
        ),
        severity=Severity.CRITICAL,
        group_index=1,
    ),
    SecretRule(
        rule_id="PEM_PRIVATE_KEY",
        name="PEM Encoded Private Key",
        description="Identified unencrypted PEM formatted cryptographic private key header",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        group_index=0,
    ),
]
