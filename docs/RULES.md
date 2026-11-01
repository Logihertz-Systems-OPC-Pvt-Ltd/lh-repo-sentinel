# Security Rules Reference: lh-repo-sentinel

An enterprise git pre-commit secret scanner & dependency auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-repo-sentinel`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `AWS_ACCESS_KEY` | `CRITICAL` | Secret Hygiene | Identified Plaintext AWS Access Key ID |
| `AWS_SECRET_KEY` | `CRITICAL` | Secret Hygiene | Identified Plaintext AWS Secret Access Key |
| `GCP_API_KEY` | `CRITICAL` | Secret Hygiene | Identified Google Cloud Platform API Key |
| `GCP_SERVICE_ACCOUNT` | `CRITICAL` | Secret Hygiene | Identified GCP Service Account Private Key |
| `GITHUB_TOKEN` | `HIGH` | Secret Hygiene | Identified GitHub Personal, OAuth, or App Token |
| `JWT_TOKEN` | `HIGH` | Secret Hygiene | Identified High-Entropy JSON Web Token in Source |
| `DATABASE_URI` | `CRITICAL` | Secret Hygiene | Identified Database Connection URI with Credentials |
| `PEM_PRIVATE_KEY` | `CRITICAL` | Secret Hygiene | Identified Unencrypted PEM Formatted Private Key |
| `UNPINNED_DEPENDENCY` | `MEDIUM` | Supply Chain | Unpinned or Wildcard Dependency in Manifest |
| `HIGH_ENTROPY_TOKEN` | `HIGH` | Secret Hygiene | Generic High-Entropy Token Exceeding Shannon Threshold |

---

## Granular Rule Specifications

### `AWS_ACCESS_KEY`: Identified Plaintext AWS Access Key ID

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: AWS Access Key ID pattern detected in source code.
- **Remediation**: Revoke exposed key in AWS IAM console and migrate to environment variables or IAM roles.

---

### `AWS_SECRET_KEY`: Identified Plaintext AWS Secret Access Key

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: AWS Secret Access Key credential assignment detected.
- **Remediation**: Rotate secret key immediately and store in AWS Secrets Manager.

---

### `GCP_API_KEY`: Identified Google Cloud Platform API Key

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Google Cloud Platform API key detected in source code.
- **Remediation**: Restrict API key by IP/HTTP referrer in Google Cloud Console or externalize to secret store.

---

### `GCP_SERVICE_ACCOUNT`: Identified GCP Service Account Private Key

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: GCP Service Account private key JSON block committed to repository.
- **Remediation**: Delete compromised service account key in GCP IAM and adopt Workload Identity Federation.

---

### `GITHUB_TOKEN`: Identified GitHub Personal, OAuth, or App Token

- **Severity**: `HIGH`
- **Category**: `Secret Hygiene`
- **Description**: GitHub Personal Access Token or fine-grained token detected.
- **Remediation**: Revoke token in GitHub Developer Settings and use GitHub Actions secrets.

---

### `JWT_TOKEN`: Identified High-Entropy JSON Web Token in Source

- **Severity**: `HIGH`
- **Category**: `Secret Hygiene`
- **Description**: JWT containing sensitive claims committed to source files.
- **Remediation**: Purge token from history and generate ephemeral tokens at runtime.

---

### `DATABASE_URI`: Identified Database Connection URI with Credentials

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Database connection URI containing embedded username and password.
- **Remediation**: Externalize database credentials to environment variables.

---

### `PEM_PRIVATE_KEY`: Identified Unencrypted PEM Formatted Private Key

- **Severity**: `CRITICAL`
- **Category**: `Secret Hygiene`
- **Description**: Cryptographic private key header (BEGIN RSA/EC PRIVATE KEY) found in source.
- **Remediation**: Remove private key from git history and store in hardware security module or KMS.

---

### `UNPINNED_DEPENDENCY`: Unpinned or Wildcard Dependency in Manifest

- **Severity**: `MEDIUM`
- **Category**: `Supply Chain`
- **Description**: Package manifest declares floating or wildcard dependency version constraint.
- **Remediation**: Pin exact dependency versions in requirements.txt or pyproject.toml.

---

### `HIGH_ENTROPY_TOKEN`: Generic High-Entropy Token Exceeding Shannon Threshold

- **Severity**: `HIGH`
- **Category**: `Secret Hygiene`
- **Description**: High-entropy alphanumeric token exceeding Shannon threshold (4.5).
- **Remediation**: Verify whether token is a secret and externalize to secret management vault.

---
