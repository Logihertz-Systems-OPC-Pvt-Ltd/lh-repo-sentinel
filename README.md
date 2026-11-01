# lh-repo-sentinel

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-repo-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-repo-sentinel/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise git pre-commit secret scanner & dependency auditor developed by **Logihertz Systems (OPC) Private Limited**.

Static analysis CLI and Git pre-commit scanner detecting hardcoded secrets, high-entropy API tokens, cloud provider keys, database URIs, unencrypted private keys, and unpinned dependencies in source repositories.

---

## Key Features

- **High-Entropy Token Detection**: Uses Shannon entropy analysis and curated regex signatures to detect AWS/GCP keys, GitHub tokens, and JWTs.
- **Git Pre-Commit Hook Integration**: Installs zero-overhead pre-commit hooks to block secret leaks before commits reach remote repositories.
- **Inline Ignore Directives**: Respects `.gitignore` rules and inline comments (`# lh-sentinel: ignore`) for explicit false-positive suppression.
- **Unpinned Dependency Auditing**: Audits `pyproject.toml`, `requirements.txt`, and `package.json` for unpinned wildcard dependencies.
- **Multi-Format Reporting**: Outputs colored terminal tables via `rich`, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `AWS_ACCESS_KEY` | `CRITICAL` | Identified plaintext AWS Access Key ID credential assignment |
| `AWS_SECRET_KEY` | `CRITICAL` | Identified plaintext AWS Secret Access Key credential assignment |
| `GCP_API_KEY` | `CRITICAL` | Identified Google Cloud Platform API Key |
| `GCP_SERVICE_ACCOUNT` | `CRITICAL` | Identified Google Cloud Service Account Private Key configuration block |
| `GITHUB_TOKEN` | `HIGH` | Identified GitHub Personal, OAuth, or App Access Token |
| `JWT_TOKEN` | `HIGH` | Identified high-entropy JSON Web Token containing sensitive claims or signatures |
| `DATABASE_URI` | `CRITICAL` | Identified database connection string containing embedded plaintext credentials |
| `PEM_PRIVATE_KEY` | `CRITICAL` | Identified unencrypted PEM formatted cryptographic private key header |
| `UNPINNED_DEPENDENCY` | `MEDIUM` | Unpinned or floating wildcard dependency declared in package manifest |
| `HIGH_ENTROPY_TOKEN` | `HIGH` | Generic high-entropy cryptographic token exceeding Shannon threshold |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-repo-sentinel.git
cd lh-repo-sentinel

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-sentinel` (also accessible via `lh-sentinel`).

```bash
# Scan a repository directory for hardcoded secrets
lh-sentinel scan ./src/

# Scan staged Git changes before commit
lh-sentinel staged --strict

# Install pre-commit hook into current Git repository
lh-sentinel install-hook

# Export scan findings to OASIS SARIF v2.1.0
lh-sentinel scan . --format sarif --output secrets.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
