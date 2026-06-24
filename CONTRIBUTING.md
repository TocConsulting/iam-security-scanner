# Contributing to IAM Security Scanner

Thank you for your interest in contributing to the IAM Security Scanner! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- AWS CLI configured with appropriate credentials
- Good understanding of AWS IAM security concepts (users, roles, policies, trust relationships, the credential report)

### Development Setup

1. **Fork and Clone the Repository**
   ```bash
   git clone https://github.com/TocConsulting/iam-security-scanner.git
   cd iam-security-scanner
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   # Install all development dependencies from pyproject.toml
   pip install -e ".[dev]"

   # Or install manually if needed
   pip install pytest pytest-cov black flake8 mypy
   ```

## Development Workflow

### Code Style and Standards

We maintain high code quality standards using the following tools:

#### Code Formatting
```bash
# Format code with Black
black iam_security_scanner/
```

#### Code Linting
```bash
# Check code style with flake8
flake8 iam_security_scanner/

# Type checking with mypy
mypy iam_security_scanner/
```

#### Testing
```bash
# Run tests with pytest
pytest tests/

# Run tests with coverage
pytest --cov=iam_security_scanner tests/
```

### Code Quality Requirements

- **Line Length**: Maximum 79 characters (PEP8 standard)
- **Type Hints**: Required for all public functions and methods
- **Docstrings**: Required for all modules, classes, and public functions
- **Error Handling**: Proper exception handling with logging
- **Fail-Closed Defaults**: Missing fields must assume the worst (control fails), never the best
- **Security**: No hardcoded credentials or sensitive information

## Making Changes

### Branch Naming Convention

- `feature/description-of-feature` - New features
- `bugfix/description-of-bug` - Bug fixes
- `docs/description-of-changes` - Documentation updates
- `refactor/description-of-refactor` - Code refactoring

### Commit Message Format

```
type(scope): short description

Longer description if needed

- List any breaking changes
- Reference issues: Fixes #123
```

**Types:**
- `feat`: New feature (e.g. a new check, a new compliance framework)
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clean, well-documented code
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   black iam_security_scanner/
   flake8 iam_security_scanner/
   pytest tests/
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(checks): detect role trust policy missing ExternalId condition"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit Pull Request**
   - Provide clear description of changes
   - Reference any related issues
   - Include test results if applicable

## Testing Guidelines

### Test Structure

```
tests/
├── __init__.py
├── test_account_settings.py        # F.x checks (Access Analyzer, certs, CloudShell)
├── test_cli.py                     # CLI option and command tests
├── test_compliance.py              # 128 controls, 10 frameworks validation
├── test_group_security.py          # E.x checks (group membership)
├── test_new_checks_mocked.py       # Mocked end-to-end coverage for newer checks
├── test_password_policy.py         # B.x checks (policy validation)
├── test_password_policy_findings.py # B.x finding/issue emission
├── test_policy_security.py         # C.x checks (admin, wildcard, PassRole)
├── test_privilege_escalation.py    # G.1-G.3 checks (privesc paths, AssumeRole)
├── test_role_security.py           # D.x checks (trust, cross-account)
├── test_scanner.py                 # Orchestrator tests
├── test_scoring.py                 # Non-stacking scoring logic
├── test_trust_analysis.py          # G.4-G.5 checks (confused-deputy, cross-account)
└── test_user_security.py           # A.x checks (root, MFA, keys, credentials)
```

### Writing Tests

- Test individual checks in isolation; mock the boto3 IAM / Access Analyzer / STS clients
- Use `unittest` (Python standard library) or `pytest`
- Provide realistic AWS API response fixtures (the scanner reads exactly what `GetAccountAuthorizationDetails`, `GenerateCredentialReport` / `GetCredentialReport`, and `GetAccountPasswordPolicy` return)
- Always include a fail-closed test (control fails when the field is absent)
- Aim for >= 80% line coverage on new checkers

### Example Test

```python
import unittest
from unittest.mock import MagicMock

from iam_security_scanner.checks.password_policy import PasswordPolicyChecker


class TestPasswordPolicy(unittest.TestCase):

    def test_min_length_flags_weak_policy(self):
        iam_client = MagicMock()
        iam_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 6}
        }
        session = MagicMock()
        session.client.return_value = iam_client

        checker = PasswordPolicyChecker(session_factory=lambda: session)
        result = checker.check_password_policy()
        self.assertIn("weak_min_length", result["issues"])

    def test_fail_closed_when_no_policy(self):
        iam_client = MagicMock()
        iam_client.get_account_password_policy.side_effect = Exception(
            "NoSuchEntity"
        )
        session = MagicMock()
        session.client.return_value = iam_client

        checker = PasswordPolicyChecker(session_factory=lambda: session)
        result = checker.check_password_policy()
        # No policy is the worst case: every B.1-B.7 control fails.
        self.assertTrue(result["no_password_policy"])
```

## Architecture Guidelines

### Project Structure

```
iam_security_scanner/
├── __init__.py                 # Package metadata
├── cli.py                      # Click CLI interface
├── scanner.py                  # Main orchestrator (facade pattern, parallel categories)
├── compliance.py               # 10 frameworks, 128 lambda-based controls
├── utils.py                    # Scoring, logging, formatting
├── html_reporter.py            # Jinja2 HTML dashboard generator
├── checks/
│   ├── base.py                 # BaseChecker (session factory, backoff)
│   ├── user_security.py        # A.1-A.12: root, MFA, keys, credentials, direct admin
│   ├── password_policy.py      # B.1-B.8: password policy validation
│   ├── policy_security.py      # C.1-C.5: managed policy analysis
│   ├── role_security.py        # D.1-D.4: role trust and privilege
│   ├── group_security.py       # E.1-E.3: group membership
│   ├── account_settings.py     # F.1-F.7: Access Analyzer, certs, CloudShell
│   ├── privilege_escalation.py # G.1-G.3: privesc paths, permissive AssumeRole
│   └── trust_analysis.py       # G.4-G.5: confused-deputy, cross-account trust
└── templates/
    └── report.html             # HTML report template
```

The scanner runs a single account-level scan with parallel category execution.
Credential-report generation is asynchronous (poll until ready), and exponential
backoff handles API throttling. Findings are emitted into the top-level
`result["issues"]` list, and the security score is computed in `utils.py`.

### Adding New Features

#### New Security Checks

1. Add the check method to the appropriate `*Checker` class in `iam_security_scanner/checks/`
2. Wire it into the scan orchestration in `scanner.py` so its result feeds the merged result dict
3. Add the issue string to `result["issues"]` and a matching score deduction in `utils.py` (respect non-stacking rules for overlapping MFA penalties)
4. Map to compliance frameworks in `compliance.py` if applicable
5. Add the check to `security-checks.md` with a one-line description and severity
6. Add remediation steps to `remediation-guide.md`
7. Add tests for both pass and fail paths, including the fail-closed default

#### New Compliance Frameworks

1. Add the framework block to `ComplianceChecker.frameworks` in `compliance.py`
2. Each control is a lambda receiving the merged result dict and returning `True` (pass) / `False` (fail)
3. Default missing fields to the failing value (fail-closed)
4. Add the framework to `compliance.md`
5. Update the CLI `--compliance-only` table

#### New Report Formats

1. Create a new reporter module following `html_reporter.py`
2. Add an export method to the scanner (`_export_<format>`)
3. Wire it into report generation
4. Update the `--output-format` choices in `cli.py`

## Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Python version, scanner version (`iam-security-scanner --version`), AWS region
- **Steps to Reproduce**: Clear steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Error Messages**: Full error messages and stack traces
- **Sanitized API Response**: If the bug is in a check, paste the relevant slice of `GetAccountAuthorizationDetails` or the credential report with account IDs and ARNs redacted

## Feature Requests

When requesting features, please include:

- **Use Case**: Why this feature would be useful
- **Proposed Solution**: How you envision the feature working
- **Alternatives**: Alternative approaches you've considered
- **Compatibility**: Impact on existing functionality

## Documentation

### Documentation Types

- **Code Documentation**: Inline comments and docstrings
- **User Documentation**: `README.md`, `security-checks.md`, `compliance.md`, `remediation-guide.md`
- **Developer Documentation**: This `CONTRIBUTING.md`

### Documentation Standards

- Use clear, concise language
- Include code examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## Security Considerations

### Reporting Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please email security issues to: contact@tocconsulting.fr

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Guidelines

- Never commit AWS credentials or other secrets
- Use the standard boto3 credential resolver chain (env vars, profiles, instance metadata)
- The scanner requires read-only IAM permissions only - see README for the policy
- Validate all user inputs
- Use secure coding practices

## Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check README and inline documentation first

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Release Process

1. **Version Bumping**: Use semantic versioning (MAJOR.MINOR.PATCH)
2. **Release Notes**: Document new features and fixes in GitHub release notes
3. **Testing**: Run full test suite (`pytest tests/ -v`) and manual testing
4. **Documentation**: Update `README.md`, `security-checks.md`, `compliance.md`, `remediation-guide.md` as needed
5. **Release**: Create GitHub release with release notes
6. **Distribution**: Publish to PyPI (`python -m build && twine upload dist/*`)
7. **Docker**: Build and push to Docker Hub

Thank you for contributing to making AWS IAM environments more secure!
