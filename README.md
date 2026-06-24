<p align="center">
  <img src="https://raw.githubusercontent.com/TocConsulting/iam-security-scanner/main/assets/iam-security-scanner-logo.png" alt="IAM Security Scanner" style="max-width: 100%; height: auto;">
</p>

<p align="center">
  <a href="https://pypi.org/project/iam-security-scanner/"><img src="https://img.shields.io/pypi/v/iam-security-scanner.svg" alt="PyPI version"></a>
  <a href="https://pepy.tech/project/iam-security-scanner"><img src="https://static.pepy.tech/badge/iam-security-scanner" alt="Downloads"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/iam-security-scanner"><img src="https://img.shields.io/docker/v/tarekcheikh/iam-security-scanner?label=docker&logo=docker" alt="Docker"></a>
  <a href="https://hub.docker.com/r/tarekcheikh/iam-security-scanner"><img src="https://img.shields.io/docker/pulls/tarekcheikh/iam-security-scanner" alt="Docker Pulls"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
  <a href="https://aws.amazon.com/iam/"><img src="https://img.shields.io/badge/AWS-IAM-orange.svg" alt="AWS"></a>
</p>

A comprehensive AWS IAM security scanner with 44 security checks across 7 categories and compliance mapping for 10 frameworks (128 controls). Includes privilege-escalation and confused-deputy detection, multi-threaded scanning, credential report analysis, and interactive HTML dashboards.

## Key Features

### **Comprehensive Security Analysis**
- **User Security**: Root access keys, MFA enforcement (hardware vs virtual), key rotation, unused credentials, console access without MFA
- **Password Policy**: Minimum length, complexity requirements, reuse prevention, max age validation
- **Policy Security**: Admin privilege detection, wildcard service permissions, PassRole on *, NotAction abuse, unused policies
- **Role Security**: Wildcard trust principals, overprivileged roles, unused roles, service-linked role exclusion
- **Privilege Escalation & Trust**: 22 documented privesc paths (managed + inline), permissive `sts:AssumeRole *`, confused-deputy / cross-account trust (Org-aware)
- **Group Security**: Admin groups, empty groups, users not assigned to groups
- **Account Settings**: IAM Access Analyzer (external + unused-access + findings), support role, expired certificates, CloudShell access, IAM server certificates

### **Compliance Frameworks**
- **AWS Foundational Security Best Practices (FSBP)**: 22 IAM-specific controls
- **CIS AWS Foundations Benchmark v5.0.0**: 13 controls
- **PCI DSS v4.0.1**: 12 controls
- **HIPAA Security Rule**: 11 controls
- **SOC 2**: 14 controls
- **ISO 27001:2022**: 13 controls
- **ISO 27017:2015**: 8 cloud security controls
- **ISO 27018:2019**: 6 PII protection controls
- **GDPR (EU) 2016/679**: 8 controls
- **NIST SP 800-53 Rev5**: 21 controls

### **Performance & Usability**
- **Multi-threaded Scanning**: Parallel category analysis with ThreadPoolExecutor (6 workers)
- **Rich Console Output**: Progress bars, colored output, and formatted tables
- **Multiple Report Formats**: JSON, CSV, HTML, and compliance-specific reports
- **Beautiful HTML Reports**: Interactive dashboard with Chart.js visualizations
- **Exponential Backoff**: Automatic retry with jitter for API throttling

### **Production Ready**
- **Modular Architecture**: Facade pattern with 8 dedicated checker modules
- **Thread-safe Sessions**: Session factory per-thread boto3 session management
- **Graceful Degradation**: AccessDenied errors don't crash scans
- **Non-stacking Scoring**: Overlapping MFA penalties (A.4/A.10) use highest only
- **Fail-safe Isolation**: One category failure doesn't crash other checks

## Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/TocConsulting/iam-security-scanner.git
cd iam-security-scanner
pip install .
```

### Docker Installation

```bash
# Build from source
docker build -t iam-security-scanner .
```

### Basic Usage

```bash
# Scan IAM configuration
iam-security-scanner security

# Scan with specific AWS profile
iam-security-scanner security --profile production

# Scan a specific region
iam-security-scanner security -r eu-west-1

# Compliance report only
iam-security-scanner security --compliance-only

# JSON report only, quiet mode (for CI/CD)
iam-security-scanner security -f json -q
```

## Commands

### Security Command

Scan IAM configuration for security vulnerabilities and compliance issues.

```bash
iam-security-scanner security [OPTIONS]

Options:
  -r, --region TEXT              AWS region (default: us-east-1)
  -p, --profile TEXT             AWS profile name
  -o, --output-dir TEXT          Output directory (default: ./output)
  -f, --output-format TEXT       Report format: json, csv, html, all (default: all)
  -w, --max-workers INTEGER      Worker threads 1-10 (default: 6)
  --compliance-only              Generate compliance report only
  -q, --quiet                    Suppress console output except errors
  -d, --debug                    Enable debug logging
  -h, --help                     Show help

# Top-level options (before the 'security' command):
#   iam-security-scanner --version
#   iam-security-scanner --help
```

**Examples:**
```bash
# Scan with all report formats
iam-security-scanner security -f all

# Fast compliance-only scan with HTML output
iam-security-scanner security --compliance-only -f html -p production

# Scan with more threads
iam-security-scanner security -w 10 -r eu-west-1

# JSON report only, quiet mode (for CI/CD)
iam-security-scanner security -f json -q
```

## Docker Usage

### Basic Docker Commands

```bash
# Show help
docker run --rm iam-security-scanner --help

# Show security command help
docker run --rm iam-security-scanner security --help
```

### Security Scanning with Docker

```bash
# Scan using mounted AWS credentials
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  iam-security-scanner security

# Scan with specific AWS profile
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/app/output \
  iam-security-scanner security --profile production
```

### Using Environment Variables for AWS Credentials

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  iam-security-scanner security

# With session token (for temporary credentials/assumed roles)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -v $(pwd)/output:/app/output \
  iam-security-scanner security
```

### Docker Volume Mounts

| Mount | Purpose |
|-------|---------|
| `-v ~/.aws:/root/.aws:ro` | Mount AWS credentials (read-only) |
| `-v $(pwd)/output:/app/output` | Save reports to local directory |

## Prerequisites

### Python Requirements
- Python 3.10 or higher
- Required packages (installed automatically):
  - `boto3>=1.28.0`
  - `botocore>=1.31.0`
  - `rich>=13.0.0`
  - `click>=8.1.0`
  - `jinja2>=3.1.0`

### AWS Requirements
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:ListPolicies",
                "iam:GetPolicyVersion",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:ListGroupPolicies",
                "iam:GetGroup",
                "iam:ListGroupsForUser",
                "iam:ListVirtualMFADevices",
                "iam:ListServerCertificates",
                "iam:ListEntitiesForPolicy",
                "iam:GetRolePolicy",
                "iam:GetGroupPolicy",
                "access-analyzer:ListAnalyzers",
                "access-analyzer:ListFindings",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Security Checks

### 44 Checks Across 7 Categories

| # | Category | Checks | Focus |
|---|----------|--------|-------|
| A | User & Credential Security | 12 | Root access keys, MFA (hardware/virtual), key rotation, unused credentials, console MFA, direct policies, direct admin |
| B | Password Policy | 8 | No policy, min length, uppercase, lowercase, numbers, symbols, reuse prevention, max age |
| C | Managed Policy Security | 5 | Admin privileges, wildcard service access, PassRole on *, NotAction abuse, unused policies |
| D | Role Security | 4 | Admin roles, wildcard trust principals, overprivileged roles, unused roles |
| E | Group Security | 3 | Admin groups, empty groups, users not in groups |
| F | Account Settings | 7 | Access Analyzer (external + unused-access + findings), support role, expired certs, CloudShell, IAM certificates |
| G | Privilege Escalation & Trust | 5 | Privesc (managed + inline), permissive AssumeRole, confused-deputy, cross-account trust |

See [security-checks.md](security-checks.md) for every check and [compliance.md](compliance.md) for framework mappings.

## Modular Architecture

```
iam_security_scanner/
├── scanner.py                  # Main scanner orchestration (facade pattern)
├── cli.py                      # Click CLI interface
├── compliance.py               # 128 controls across 10 frameworks
├── html_reporter.py            # Jinja2 HTML report generation
├── utils.py                    # Logging, scoring, formatting
├── checks/                     # Security check modules
│   ├── base.py                 # BaseChecker (session factory, backoff)
│   ├── user_security.py        # A.1-A.12: Root, MFA, keys, credentials, direct admin
│   ├── password_policy.py      # B.1-B.8: Password policy validation
│   ├── policy_security.py      # C.1-C.5: Managed policy analysis
│   ├── role_security.py        # D.1-D.5: Role trust and privilege
│   ├── group_security.py       # E.1-E.3: Group membership
│   ├── account_settings.py     # F.1-F.7: Access Analyzer, certs, CloudShell
│   ├── privilege_escalation.py # G.1-G.3: Privesc paths, permissive AssumeRole
│   └── trust_analysis.py       # G.4-G.5: Confused-deputy, cross-account trust
└── templates/
    └── report.html             # Interactive HTML dashboard
```

## Security Scoring

Each account receives a security score (0-100) starting at **100 points**:

| Security Issue | Points Deducted | Severity |
|----------------|-----------------|----------|
| Root access keys exist | -25 | CRITICAL |
| Root MFA not enabled | -25 | CRITICAL |
| Root virtual MFA (not hardware) | -5 | CRITICAL |
| Wildcard trust principal roles | -20 | CRITICAL |
| Privilege escalation paths (managed/inline, non-stacking) | -20 | CRITICAL |
| Admin policies (Action:* Resource:*) | -15 | HIGH |
| Users with AdministratorAccess attached directly | -15 | HIGH |
| Admin roles | -15 | HIGH |
| PassRole on * | -10 | HIGH |
| Access Analyzer disabled | -10 | HIGH |
| Admin groups | -10 | HIGH |
| Overprivileged roles | -10 | HIGH |
| Access Analyzer findings | -10 | HIGH |
| Permissive sts:AssumeRole on * | -10 | HIGH |
| Cross-account trust missing guard (confused-deputy) | -10 | HIGH |
| Users without MFA (non-stacking) | -10 | MEDIUM |
| Console users without MFA (non-stacking) | -15 | MEDIUM |
| Old access keys (>90 days) | -10 | MEDIUM |
| Unused credentials (>45 days) | -8 | MEDIUM |
| Users not in groups | -5 | MEDIUM |
| Cross-account roles | -5 | MEDIUM |
| Expired certificates | -5 | MEDIUM |
| CloudShell full access | -5 | MEDIUM |
| No unused-access Access Analyzer | -3 | MEDIUM |
| Password policy: weak length | -5 | MEDIUM |
| Password policy: no uppercase | -3 | MEDIUM |
| Password policy: no lowercase | -3 | MEDIUM |
| Password policy: no numbers | -3 | MEDIUM |
| Password policy: no symbols | -3 | MEDIUM |
| Wildcard service policies | -3 | MEDIUM |
| NotAction policies | -3 | MEDIUM |
| Direct attached user policies | -5 | LOW |
| Password policy: no reuse prevention | -2 | LOW |
| Password policy: no max age | -2 | LOW |
| Inline user policies | -2 | LOW |
| Multiple access keys | -2 | LOW |
| No support role | -2 | LOW |
| Empty groups | -2 | LOW |
| Unused policies | -2 | LOW |
| Unused roles | -2 | LOW |
| Root used recently | -2 | LOW |
| IAM server certificates | -1 | LOW |

### Non-stacking MFA Penalties

Overlapping MFA checks (A.4 users_without_mfa and A.10 console_no_mfa) use the **highest penalty only** to avoid double-counting:

- Users without MFA = -10, Console without MFA = -15 -> **only -15 applied**

### No Password Policy

If no password policy exists, all B.1-B.7 penalties apply simultaneously (-21 total).

**Formula**: `Score = max(0, 100 - total_deductions)`

### Score Interpretation

| Score Range | Level | Action |
|-------------|-------|--------|
| 90-100 | Excellent | Maintain current posture |
| 70-89 | Good | Address minor gaps |
| 50-69 | Needs Improvement | Fix medium-priority issues |
| 0-49 | Critical | Immediate action required |

## Output Files

The scanner generates reports in the specified output directory:

### JSON Report (`iam_scan_timestamp.json`)
```json
{
  "summary": {
    "scan_time": "2026-03-11T10:30:45",
    "region": "us-east-1",
    "account_id": "123456789012",
    "security_score": 78.5
  },
  "checks": {...},
  "issues": [...],
  "compliance": {...}
}
```

### CSV Report (`iam_scan_timestamp.csv`)
Spreadsheet-friendly format with all findings, severity levels, and compliance status.

### HTML Report (`iam_scan_timestamp.html`)
Interactive dashboard with:
- **Executive Summary**: Key metrics and risk indicators
- **Security Score**: Visual score card with color coding
- **Findings Table**: All issues sorted by severity
- **Compliance Grid**: Pass/fail status across all 10 frameworks
- **Score Breakdown**: Bar chart of deductions by category

## Development

### Setting Up Development Environment

```bash
git clone https://github.com/TocConsulting/iam-security-scanner.git
cd iam-security-scanner

python -m venv venv
source venv/bin/activate

pip install -e ".[dev]"
```

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_compliance.py -v

# Run with coverage
python -m pytest tests/ --cov=iam_security_scanner --cov-report=html
```

### Test Structure

```
tests/
├── test_cli.py                 # CLI option and command tests
├── test_compliance.py          # 128 controls, 10 frameworks validation
├── test_scoring.py             # Non-stacking scoring logic
├── test_user_security.py       # A.1-A.11 checks (root, MFA, keys)
├── test_password_policy.py     # B.1-B.7 checks (policy validation)
├── test_policy_security.py     # C.1-C.5 checks (admin, wildcard)
├── test_role_security.py       # D.1-D.5 checks (trust, cross-account)
├── test_group_security.py      # E.1-E.3 checks (membership)
├── test_account_settings.py    # F.1-F.6 checks (analyzer, certs)
└── test_scanner.py             # Scanner orchestration tests
```

Tests use `unittest.mock` for AWS service mocking, allowing comprehensive testing without AWS resources.

## Support & Contributing

### Getting Help
- **Documentation**: Check this README and inline help (`--help`)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/TocConsulting/iam-security-scanner/issues)

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Security Best Practices**: Based on official AWS security recommendations
- **CIS Benchmarks**: Implements CIS AWS Foundations Benchmark v5.0.0 controls
- **[ec2-security-scanner](https://github.com/TocConsulting/ec2-security-scanner)**: Architecture and design patterns
- **[s3-security-scanner](https://github.com/TocConsulting/s3-security-scanner)**: Original scanner framework

---

**Security Notice**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning AWS resources. The tool requires read-only permissions and does not modify any AWS resources.

**Performance Note**: The scanner uses account-level scanning with parallel category execution (6 threads). Credential report generation is async with polling. Exponential backoff handles API throttling automatically. Use `-w` to adjust parallelism.
