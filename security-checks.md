# IAM Security Scanner - Security Checks

The scanner runs **44 security checks across 7 categories** and maps results to
**10 compliance frameworks (128 controls)**. This document lists every check.
Remediation steps are in [remediation-guide.md](remediation-guide.md); framework
mappings are in [compliance.md](compliance.md).

## Check categories

| # | Category | Checks | Focus |
|---|----------|:------:|-------|
| A | User & Credential Security | 12 | Root account, MFA, access keys, credential hygiene, direct admin |
| B | Password Policy | 8 | Account password policy strength |
| C | Managed Policy Security | 5 | Customer-managed policy permissiveness |
| D | Role Security | 4 | Admin access, wildcard trust, overly-permissive inline, unused roles |
| E | Group Security | 3 | Admin groups, empty groups, ungrouped users |
| F | Account Settings | 7 | Access Analyzer (external + unused-access + findings), support role, certificates, CloudShell |
| G | Privilege Escalation & Trust | 5 | Privesc paths, permissive AssumeRole, confused-deputy/cross-account trust |
| **Total** | | **44** | |

> **Deferred (low/info) checks not yet implemented:** access-key-at-initial-setup, per-user hardware MFA, and SAML/OIDC provider presence. Documented intentionally; not counted above.

---

## A - User & Credential Security

| ID | Severity | Detects |
|----|----------|---------|
| A.1 | CRITICAL | Root account has active access keys |
| A.2 | CRITICAL | Root account does not have MFA enabled |
| A.3 | CRITICAL | Root MFA is a virtual device, not hardware |
| A.4 | MEDIUM | IAM users without MFA enabled |
| A.5 | MEDIUM | Access keys older than 90 days |
| A.6 | MEDIUM | Credentials unused for 45+ days |
| A.7 | LOW | Users with multiple active access keys |
| A.8 | LOW | Users with directly-attached policies |
| A.9 | LOW | Users with inline policies |
| A.10 | HIGH | Console users without MFA |
| A.11 | LOW | Root account used in the last 90 days |
| A.12 | HIGH | Users with AWS-managed `AdministratorAccess` attached directly |

## B - Password Policy

Emitted from the account password policy. **B.1** is the umbrella (no policy);
**B.2-B.8** are only emitted when a policy exists but is weak.

| ID | Severity | Detects |
|----|----------|---------|
| B.1 | HIGH | No IAM account password policy is configured |
| B.2 | MEDIUM | Minimum length is less than 14 |
| B.3 | LOW | Does not require an uppercase letter |
| B.4 | LOW | Does not require a lowercase letter |
| B.5 | LOW | Does not require a number |
| B.6 | LOW | Does not require a symbol |
| B.7 | LOW | Reuse prevention is less than 24 |
| B.8 | LOW | Does not expire passwords within 90 days |

## C - Managed Policy Security (customer-managed)

| ID | Severity | Detects |
|----|----------|---------|
| C.1 | HIGH | Customer-managed policies granting full `*:*` admin |
| C.2 | LOW | Policies with wildcard service actions (`service:*`) |
| C.3 | HIGH | Policies allowing `iam:PassRole` on a wildcard resource |
| C.4 | MEDIUM | Policies using `NotAction` with `Allow` |
| C.5 | LOW | Unused customer-managed policies (0 attachments) |

## D - Role Security

| ID | Severity | Detects |
|----|----------|---------|
| D.1 | HIGH | Roles with full admin access |
| D.2 | CRITICAL | Roles with a wildcard principal (`*`) in the trust policy |
| D.4 | HIGH | Roles with overly-permissive inline policies |
| D.5 | LOW | Roles unused for 90+ days |

> Cross-account trust is covered by **G.4/G.5** (Org-aware). There is no `D.3`.

## E - Group Security

| ID | Severity | Detects |
|----|----------|---------|
| E.1 | HIGH | Groups with full admin access |
| E.2 | LOW | Empty IAM groups |
| E.3 | MEDIUM | Users not in any group |

## F - Account Settings

| ID | Severity | Detects |
|----|----------|---------|
| F.1 | HIGH | IAM Access Analyzer (external access) not enabled |
| F.2 | LOW | No support role with `AWSSupportAccess` |
| F.3 | MEDIUM | Expired SSL/TLS certificates in IAM |
| F.4 | MEDIUM | Identities with `AWSCloudShellFullAccess` |
| F.5 | LOW | Certificates managed in IAM (legacy; prefer ACM) |
| F.6 | HIGH | Access Analyzer has active findings |
| F.7 | MEDIUM | No Access Analyzer **unused-access** analyzer enabled |

## G - Privilege Escalation & Trust

| ID | Severity | Detects |
|----|----------|---------|
| G.1 | CRITICAL | Customer-managed policies enabling privilege escalation |
| G.2 | CRITICAL | Inline policies enabling privilege escalation |
| G.3 | HIGH | Policies allowing `sts:AssumeRole` on all resources |
| G.4 | HIGH | Cross-account trust missing `ExternalId`/`PrincipalOrgID` (confused-deputy) |
| G.5 | MEDIUM | Roles trusting another AWS account (Org membership unverifiable - review) |

**Privilege-escalation detection (G.1/G.2)** flags a policy when its effective
`Allow` set is a superset of any of 22 documented escalation paths (e.g.
`iam:CreatePolicyVersion`; `iam:PassRole`+`ec2:RunInstances`/`lambda:CreateFunction`;
`iam:AttachUserPolicy`; `iam:UpdateAssumeRolePolicy`+`sts:AssumeRole`). Wildcards
(`*`, `service:*`) and `NotAction`+`Allow` are honored. Based on Rhino Security
Labs' privesc research and Prowler's `iam_policy_allows_privilege_escalation`.

**Org-aware trust (G.4/G.5):** the scanner assumes it runs as a normal member
account, where there is no API to resolve another account's Organization. So any
cross-account trust is surfaced as a **review warning (G.5)**, and the reliably-
detectable defect - a cross-account trust **missing** `aws:PrincipalOrgID` /
`sts:ExternalId` - is flagged **HIGH (G.4)**. Service-principal trust is *not*
flagged generically (most execution roles legitimately omit `aws:SourceArn`).

---

## Security score

A 0-100 score starts at 100 and deducts per failing check by severity
(CRITICAL 20-25, HIGH 10-15, MEDIUM 3-10, LOW 1-5). Overlapping MFA checks
(A.4/A.10) and privesc (G.1/G.2) are **non-stacking** (highest single penalty
only). The score is clamped to a minimum of 0. The CLI exits non-zero when any
**CRITICAL** finding is present (CI-friendly).
