# ==============================================================================
# Product:       lh-repo-sentinel (lh-repo)
# Module:        tests.test_rules
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

# lh-sentinel: ignore-file
"""Unit tests for secret detection rules and masking logic."""

from lh_repo_sentinel.models import FindingType, Severity
from lh_repo_sentinel.rules import DEFAULT_RULES, mask_secret
from lh_repo_sentinel.scanner import scan_line


def test_mask_secret():
    """Verify that sensitive secrets are properly redacted."""
    assert mask_secret("short") == "*****"
    assert mask_secret("12345678") == "********"

    masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "IOSFODNN7EXA" not in masked
    assert "*" in masked


def test_aws_access_key_detection():
    """Verify AWS access key ID regex rule detection."""
    # nosec B105
    test_line = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_line("credentials.env", 1, test_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "AWS_ACCESS_KEY" for f in findings)
    matching = [f for f in findings if f.rule_id == "AWS_ACCESS_KEY"][0]
    assert matching.severity == Severity.CRITICAL
    assert matching.finding_type == FindingType.SECRET


def test_aws_secret_key_detection():
    """Verify AWS secret access key regex rule detection."""
    # nosec B105
    test_line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = scan_line("config.py", 12, test_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "AWS_SECRET_KEY" for f in findings)
    matching = [f for f in findings if f.rule_id == "AWS_SECRET_KEY"][0]
    assert matching.severity == Severity.CRITICAL


def test_gcp_api_key_detection():
    """Verify Google Cloud API key detection."""
    test_line = 'const gcpKey = "AIzaSyB_1234567890abcdefghijklmnopqrstu";'
    findings = scan_line("index.js", 5, test_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "GCP_API_KEY" for f in findings)
    matching = [f for f in findings if f.rule_id == "GCP_API_KEY"][0]
    assert matching.severity == Severity.CRITICAL


def test_gcp_service_account_detection():
    """Verify GCP Service Account private key JSON block detection."""
    test_line = '  "type": "service_account",'
    findings = scan_line("sa_key.json", 2, test_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "GCP_SERVICE_ACCOUNT" for f in findings)


def test_github_tokens_detection():
    """Verify GitHub PAT tokens detection."""
    # Classic PAT
    pat_line = 'GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    findings = scan_line("ci.yml", 10, pat_line, rules=DEFAULT_RULES)
    assert any(f.rule_id == "GITHUB_TOKEN" for f in findings)

    # Fine-grained PAT
    fine_pat = "github_pat_" + "A" * 82
    fine_line = f'export TOKEN="{fine_pat}"'
    fine_findings = scan_line(".env", 1, fine_line, rules=DEFAULT_RULES)
    assert any(f.rule_id == "GITHUB_TOKEN" for f in fine_findings)


def test_jwt_detection():
    """Verify JSON Web Token pattern detection."""
    dummy_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    test_line = f'auth_header = "Bearer {dummy_jwt}"'
    findings = scan_line("auth.py", 42, test_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "JWT_TOKEN" for f in findings)
    matching = [f for f in findings if f.rule_id == "JWT_TOKEN"][0]
    assert matching.severity == Severity.HIGH


def test_database_uri_detection():
    """Verify database URIs containing embedded passwords."""
    # URI with credentials should match
    uri_line = 'DATABASE_URL = "postgresql://sentinel_admin:p@ssw0rd123@localhost:5432/production"'
    findings = scan_line("settings.py", 15, uri_line, rules=DEFAULT_RULES)
    assert any(f.rule_id == "DATABASE_URI" for f in findings)

    # URI without credentials should NOT match
    clean_uri = 'SITE_URL = "http://localhost:8000/api/v1"'
    clean_findings = scan_line("settings.py", 16, clean_uri, rules=DEFAULT_RULES)
    assert not any(f.rule_id == "DATABASE_URI" for f in clean_findings)


def test_pem_private_key_detection():
    """Verify PEM private key header detection."""
    pem_line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_line("id_rsa", 1, pem_line, rules=DEFAULT_RULES)

    assert any(f.rule_id == "PEM_PRIVATE_KEY" for f in findings)
    matching = [f for f in findings if f.rule_id == "PEM_PRIVATE_KEY"][0]
    assert matching.severity == Severity.CRITICAL
