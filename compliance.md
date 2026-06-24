# IAM Security Scanner - Compliance Framework Mapping

> **Author:** Toc Consulting
> **Frameworks:** AWS-FSBP, CIS v5.0.0, PCI DSS v4.0.1, HIPAA, SOC 2, ISO 27001:2022, ISO 27017, ISO 27018, GDPR, NIST 800-53 Rev5
>
> **Disclaimer:** Mapping IAM-only checks to broad governance frameworks
> (HIPAA, GDPR, SOC 2, ISO) provides **partial technical evidence**, not a
> compliance attestation. Control IDs are verified against the authoritative
> standards - see the [`research/`](research/) folder for per-framework sources.

---

## Table of Contents

1. [Framework Summary](#1-framework-summary)
2. [AWS Foundational Security Best Practices (FSBP)](#2-aws-fsbp)
3. [CIS AWS Foundations Benchmark v5.0.0](#3-cis-v500)
4. [PCI DSS v4.0.1](#4-pci-dss-v401)
5. [HIPAA](#5-hipaa)
6. [SOC 2](#6-soc-2)
7. [ISO 27001:2022](#7-iso-270012022)
8. [ISO 27017](#8-iso-27017)
9. [ISO 27018](#9-iso-27018)
10. [GDPR](#10-gdpr)
11. [NIST 800-53 Rev5](#11-nist-800-53-rev5)

---

## 1. Framework Summary

| Framework | Controls | Focus Areas |
|-----------|----------|-------------|
| AWS-FSBP | 22 | Real FSBP IAM set is IAM.1-8, 21; plus related Security Hub IAM controls |
| CIS v5.0.0 | 13 | Section 1: Identity and Access Management (v5.0.0 numbering) |
| PCI DSS v4.0.1 | 12 | Requirements 2, 7, 8, 10 - configuration, access control, authentication |
| HIPAA | 11 | §164.312 Technical Safeguards, §164.308 Administrative Safeguards |
| SOC 2 | 14 | Trust Service Criteria CC5, CC6, CC7, CC8, A1, P6 |
| ISO 27001:2022 | 13 | Annex A.5, A.8 - access control, secure authentication, logging |
| ISO 27017 | 8 | Cloud-specific IAM controls (CLD.6, CLD.8, CLD.12, CLD.13) + A.9.4 |
| ISO 27018 | 6 | PII processor access controls (A.9, A.10, A.11, A.12) |
| GDPR | 8 | Articles 5, 25, 32, 33 - data protection, security measures |
| NIST 800-53 | 21 | AC, IA, AU, CM, SI families - access, identification, audit |
| **Total** | **128** | |

> **Design requirement:** Every key name referenced in compliance lambdas MUST exactly match the key name set in `scanner.py` and referenced in `utils.py:calculate_security_score()`. This is a build-time cross-reference contract - any mismatch is a bug.

---

## 2. AWS FSBP

### AWS Foundational Security Best Practices

| FSBP Control | Check ID | Description | Severity |
|-------------|----------|-------------|----------|
| IAM.1 | C.1 | IAM policies should not allow full "*" administrative privileges | HIGH |
| IAM.2 | A.8 | IAM users should not have IAM policies attached directly | LOW |
| IAM.3 | A.5 | IAM users' access keys should be rotated every 90 days or less | MEDIUM |
| IAM.4 | A.1 | IAM root user access key should not exist | CRITICAL |
| IAM.5 | A.10 | MFA should be enabled for all IAM users that have a console password | HIGH |
| IAM.6 | A.3 | Hardware MFA should be enabled for the root user | CRITICAL |
| IAM.8 | A.6 | Unused IAM user credentials should be removed | MEDIUM |
| IAM.9 | A.2 | MFA should be enabled for the root user | CRITICAL |
| IAM.11 | B.3 | Ensure IAM password policy requires at least one uppercase letter | MEDIUM |
| IAM.12 | B.4 | Ensure IAM password policy requires at least one lowercase letter | MEDIUM |
| IAM.13 | B.6 | Ensure IAM password policy requires at least one symbol | MEDIUM |
| IAM.14 | B.5 | Ensure IAM password policy requires at least one number | MEDIUM |
| IAM.15 | B.2 | Ensure IAM password policy requires minimum length of 14 | MEDIUM |
| IAM.16 | B.7 | Ensure IAM password policy prevents password reuse | LOW |
| IAM.17 | B.8 | Ensure IAM password policy expires passwords within 90 days | LOW |
| IAM.18 | F.2 | Ensure a support role has been created for AWS Support | LOW |
| IAM.19 | A.4 | MFA should be enabled for all IAM users | MEDIUM |
| IAM.21 | C.2 | IAM customer managed policies should not allow wildcard actions | LOW |
| IAM.22 | A.6 | IAM user credentials unused for 45 days should be removed | MEDIUM |
| IAM.26 | F.3 | Expired SSL/TLS certificates managed in IAM should be removed | MEDIUM |
| IAM.27 | F.4 | IAM identities should not have AWSCloudShellFullAccess | MEDIUM |
| IAM.28 | F.1 | IAM Access Analyzer external access analyzer should be enabled | HIGH |

> **Note on FSBP membership:** the *true* AWS FSBP IAM control set is small -
> IAM.1, IAM.2, IAM.3, IAM.4, IAM.5, IAM.6, IAM.7, IAM.8, IAM.21. The other
> IAM.x controls above are related AWS Security Hub IAM controls (belonging to
> CIS/NIST/PCI standards) that this tool also evaluates; they are listed here for
> coverage, not as a claim that they are FSBP-native.
>
> **Access Analyzer active findings (F.6)** is surfaced as a native scanner
> finding, not as a fabricated FSBP control ID. (The earlier `IAM.F6*` custom
> entry has been removed - no such AWS control exists.)
>
> **IAM.7** is AWS's consolidated password-policy control; this tool's granular
> password checks (B.1-B.8) provide equivalent coverage. **IAM.20** (avoid root
> user) was retired by AWS in April 2024 - root usage is covered by A.11.
> **IAM.23/24/25** (tagging) are out of scope - better enforced via AWS Config.

### Lambda Pattern for FSBP Controls

```python
"IAM.1": {
    "description": "IAM policies should not allow full admin privileges",
    "severity": "HIGH",
    "check": lambda r: r.get("admin_policies", {}).get("count", 1) == 0,
}
```

---

## 3. CIS v5.0.0

### CIS AWS Foundations Benchmark v5.0.0 - Section 1: Identity and Access Management

Control numbers are the **v5.0.0** numbering (verified against the AWS Security
Hub version-comparison table). v5.0.0 renumbered the IAM section and **removed**
three controls this tool previously listed under v3.0: root-daily-use, one-active-
access-key, and the `*:*`-admin-policy control. Those checks still run natively
(A.11, A.7, C.1) and map under NIST/ISO/SOC2.

| CIS Control | Check ID | Description | Severity |
|-------------|----------|-------------|----------|
| 1.3 | A.1 | Ensure no root user access key exists | CRITICAL |
| 1.4 | A.2 | Ensure MFA is enabled for the root user account | CRITICAL |
| 1.5 | A.3 | Ensure hardware MFA is enabled for the root user account | CRITICAL |
| 1.7 | B.2 | Ensure IAM password policy requires minimum length of 14 or greater | MEDIUM |
| 1.8 | B.7 | Ensure IAM password policy prevents password reuse | LOW |
| 1.9 | A.10 | Ensure MFA is enabled for all IAM users that have a console password | HIGH |
| 1.11 | A.6 | Ensure credentials unused for 45 days or greater are disabled | MEDIUM |
| 1.13 | A.5 | Ensure access keys are rotated every 90 days or less | MEDIUM |
| 1.14 | A.8, A.9 | Ensure IAM users receive permissions only through groups | LOW |
| 1.16 | F.2 | Ensure a support role has been created to manage incidents with AWS Support | LOW |
| 1.18 | F.3 | Ensure that expired SSL/TLS certificates stored in IAM are removed | MEDIUM |
| 1.19 | F.1 | Ensure that IAM Access Analyzer is enabled for all regions | HIGH |
| 1.21 | F.4 | Ensure access to AWSCloudShellFullAccess is restricted | MEDIUM |

> **CIS 1.14 scope:** Maps to both A.8 (no attached managed policies) and A.9 (no inline policies). The CIS control requires "permissions only through groups", which means no direct policy attachments of either type.
>
> **CIS v7.0.0** (Apr 2026) is the latest CIS release and moved IAM into Section 2; this tool uses the fully-verifiable v5.0.0 numbering and will adopt v7 once its official PDF numbering is confirmed.

---

## 4. PCI DSS v4.0.1

### Payment Card Industry Data Security Standard v4.0.1

| PCI DSS Req | Check IDs | Description |
|-------------|-----------|-------------|
| **2.2.1** | B.1-B.8 | System configuration standards - strong password policy for IAM |
| **7.2.1** | C.1, C.3, D.1, E.1 | Restrict access to system components by business need - least privilege policies, no admin unless required |
| **7.2.2** | A.8, A.9, E.3 | Access assigned based on job classification - group-based permissions, no direct attachments |
| **7.2.4** | C.5, D.5 | Review all user accounts and access privileges periodically - unused policies and roles |
| **7.2.6** | D.2, G.5 | All access to cardholder data is authorized - role trust policy review, cross-account access |
| **8.2.1** | A.1, A.2 | Root account security - no root access keys, MFA enabled |
| **8.2.4** | A.6, D.5 | User ID lifecycle - authorized access, timely deprovisioning of unused credentials and roles |
| **8.3.6** | B.2, B.6 | Password complexity requirements - minimum length, special characters |
| **8.3.7** | B.7 | Password history - prevent reuse of last 4+ passwords |
| **8.3.9** | A.5 | Change passwords/passphrases at least every 90 days - access key rotation |
| **8.6.1** | A.7, C.4 | Management of system/application accounts - no shared credentials, no NotAction |
| **10.2.1** | F.1, F.6 | Audit logs capture all access - Access Analyzer enabled with findings reviewed |

---

## 5. HIPAA

### Health Insurance Portability and Accountability Act - Technical and Administrative Safeguards

| HIPAA Rule | Check IDs | Description |
|------------|-----------|-------------|
| **§164.312(a)(1)** - Access Control | C.1, D.1, E.1 | Implement technical policies to allow access only to authorized persons - least privilege, no admin policies |
| **§164.312(a)(2)(i)** - Unique User ID | A.8, A.9, E.3 | Assign unique name/number to track user identity - no shared policies, group-based management |
| **§164.312(a)(2)(iii)** - Automatic Logoff | A.6, A.11 | Implement procedures to terminate sessions after inactivity - unused credential removal, limit root usage |
| **§164.312(a)(2)(iv)** - Encryption | F.3 | Implement mechanism to encrypt/decrypt ePHI - valid SSL/TLS certificates |
| **§164.312(b)** - Audit Controls | F.1, F.6 | Implement mechanisms to record and examine activity - Access Analyzer enabled and findings reviewed |
| **§164.312(c)(1)** - Integrity | C.3, C.4, D.4 | Protect ePHI from improper alteration - no PassRole *, no NotAction, no overly permissive roles |
| **§164.312(d)** - Authentication | A.2, A.3, A.4, A.10 | Verify identity of person/entity seeking access - MFA for root and all users |
| **§164.308(a)(1)** - Security Management | D.2, G.5 | Risk analysis and management - role trust policy review, cross-account audit |
| **§164.308(a)(4)** - Information Access Management | A.8, A.9, C.1 | Policies for authorizing access to ePHI - no direct policies, no admin access |
| **§164.308(a)(5)** - Security Awareness | B.1-B.8 | Security awareness and training - strong password policy enforcement |
| **§164.308(a)(3)** - Workforce Security | A.6, D.5, C.5 | Ensure workforce members have appropriate access - remove unused credentials, roles, policies |

---

## 6. SOC 2

### Trust Service Criteria (CC, A1, P6)

| SOC 2 Criteria | Check IDs | Description |
|----------------|-----------|-------------|
| **CC5.1** - COSO Principle 10: Control Activities | D.2, F.1 | Control activities to mitigate risk - wildcard principals, Access Analyzer enabled |
| **CC5.2** - COSO Principle 11: Control Activities (technology) | C.1, D.1, E.1 | General control activities over technology - admin policies, admin roles/groups |
| **CC6.1** - Logical Access Security | A.2, A.3, A.4, A.10, B.1-B.8 | Logical access to information assets - MFA, password policy |
| **CC6.2** - User Credential Management | A.5, A.6, A.7, A.1 | Prior to issuing credentials, register and authorize - key rotation, unused creds, root key review |
| **CC6.3** - Access Authorization | C.1, D.1, E.1, A.8, A.9 | Authorize based on business need - least privilege, group-based permissions |
| **CC6.5** - Credential Lifecycle | A.5, A.6, D.5, C.5 | Manage credential lifecycle - key rotation, unused credentials, unused roles and policies |
| **CC6.6** - Restrict External Access | D.2, G.5, F.4 | Restrict access from external sources - role trust policies, CloudShell access |
| **CC6.8** - Prevent Unauthorized Software | F.4, C.4 | Prevent/detect unauthorized software - CloudShell restrictions, no NotAction policies |
| **CC7.1** - Detect Anomalies | F.1, F.6 | Detect and monitor anomalies - Access Analyzer enabled, active findings reviewed |
| **CC7.2** - Monitor System Components | A.6, D.5, C.5 | Monitor components for anomalies - detect unused credentials, roles, policies |
| **CC8.1** - Change Management | C.2, C.4 | Manage changes to infrastructure - no wildcard service actions, no NotAction |
| **A1.2** - Environmental Protections | F.3, F.5 | Protect against environmental threats - certificate management |
| **P6.1** - Privacy Controls | A.8, A.9, E.3 | Restrict access to personal information - group-based permissions, no direct policies |
| **P6.7** - Quality of Personal Information | A.11, A.6 | Ensure data quality through proper access - limit root usage, remove unused credentials |

---

## 7. ISO 27001:2022

### Annex A Controls

| ISO 27001 Control | Check IDs | Description |
|-------------------|-----------|-------------|
| **A.5.15** - Access Control | C.1, D.1, E.1 | Access to information systems based on business requirements - least privilege |
| **A.5.16** - Identity Management | A.8, A.9, E.3, A.6 | Full lifecycle of identities managed - no direct policies, group membership, unused cred removal |
| **A.5.17** - Authentication Information | A.2, A.3, A.4, A.10, B.1-B.8 | Allocation and management of authentication information - MFA, password policy |
| **A.5.18** - Access Rights | C.1, C.3, D.1, D.4 | Restrict access rights following least privilege - no admin policies, no PassRole *, no overly permissive roles |
| **A.8.2** - Privileged Access Rights | D.1, E.1, C.1, A.1 | Restrict and manage privileged access - admin roles/groups/policies, root access keys |
| **A.8.3** - Information Access Restriction | D.2, G.5, F.4 | Restrict access per access control policy - role trust, cross-account, CloudShell |
| **A.8.5** - Secure Authentication | A.3, A.4, A.10, A.5 | Secure authentication technologies - hardware MFA, MFA for all, key rotation |
| **A.8.9** - Configuration Management | B.1-B.8, F.1 | Configurations managed and monitored - password policy, Access Analyzer |
| **A.8.15** - Logging | F.1, F.6 | Activity logs produced, stored, protected, analyzed - Access Analyzer enabled and findings reviewed |
| **A.8.16** - Monitoring Activities | F.1, F.6, A.6, D.5 | Monitor for anomalous behavior - Access Analyzer, unused creds, unused roles |
| **A.8.24** - Use of Cryptography | F.3 | Proper use of cryptography - valid SSL/TLS certificates |
| **A.8.18** - Use of Privileged Utility Programs | C.2, C.4 | Restrict and control use of privileged utilities - no wildcard service actions, no NotAction |
| **A.5.3** - Segregation of Duties | A.8, A.9, E.3, A.11 | Ensure segregation of duties - group-based permissions, limit root usage |

---

## 8. ISO 27017

### Cloud-Specific Controls (Based on ISO/IEC 27017:2015)

| ISO 27017 Control | Check IDs | Description |
|-------------------|-----------|-------------|
| **CLD.6.3.1** - Shared Roles and Responsibilities | A.8, A.9, E.3, C.1 | Customer manages IAM configuration - group-based permissions, least privilege |
| **CLD.8.1.5** - Removal of Cloud Service Customer Assets | D.5, C.5, A.6, E.2 | Remove unused cloud resources - unused roles, policies, credentials, empty groups |
| **A.9.4.2** - Secure log-on procedures | A.2, A.10, B.1-B.8 | Strong authentication - root/console MFA, password policy |
| **CLD.13.1.4** - Security Management for Virtual and Physical Networks | D.2, G.5, F.4 | Align security management for virtual/physical networks - role trust, cross-account, CloudShell |
| **CLD.12.1.5** - Administrator's Operational Security | A.1, D.1, E.1, A.11 | Manage administrator access - no root keys, no admin roles/groups, limit root usage |
| **CLD.12.4.5** - Monitoring of Cloud Services | F.1, F.6 | Monitor cloud services - Access Analyzer enabled and findings reviewed |
| **A.9.2.3** - Management of Privileged Access Rights | D.1, E.1, C.3, D.4 | Manage privileged access - no admin roles/groups, no PassRole *, no overly permissive inline |
| **A.10.1.1** - Policy on Use of Cryptographic Controls | F.3, F.5 | Cryptographic control policy - valid SSL/TLS certificates, prefer ACM over IAM |

---

## 9. ISO 27018

### PII Processor Controls (Based on ISO/IEC 27018:2019)

| ISO 27018 Control | Check IDs | Description |
|-------------------|-----------|-------------|
| **A.9.2** - PII Access Control | C.1, D.1, E.1, A.8, A.9 | Access to PII restricted by need - least privilege, group-based permissions |
| **A.9.4** - PII User Access Management | A.6, D.5, A.5 | Manage user access lifecycle - unused credentials, unused roles, key rotation |
| **A.10.1** - Cryptographic Controls for PII | F.3, F.5 | Encryption for PII protection - valid SSL/TLS certificates, prefer ACM |
| **A.11.1** - Data Minimization | C.5, D.5, E.2 | Minimize data processing - remove unused resources |
| **A.12.4** - Audit Logging of PII Processing | F.1, F.6 | Logging of PII processing - Access Analyzer for audit, findings reviewed |
| **A.11.2** - Secure Disposal | A.6, A.11 | Remove access when no longer needed - unused credentials, limit root usage |

---

## 10. GDPR

### General Data Protection Regulation

| GDPR Article | Check IDs | Description |
|--------------|-----------|-------------|
| **Art. 5(1)(f)** - Integrity & Confidentiality | C.1, D.1, A.4, A.10 | Process data securely - least privilege, MFA |
| **Art. 25** - Data Protection by Design | B.1-B.8, F.1, A.8, A.9 | Implement appropriate technical measures - password policy, Access Analyzer, group-based access |
| **Art. 32(1)(a)** - Pseudonymisation & Encryption | F.3 | Appropriate security measures - valid SSL/TLS certificates |
| **Art. 32(1)(b)** - Confidentiality | C.1, D.1, D.2, G.5, E.1 | Ensure ongoing confidentiality - least privilege, trust policy review |
| **Art. 32(1)(c)** - Availability & Resilience | F.2, F.5 | Ensure system availability - support role for incident management, certificate hygiene |
| **Art. 32(1)(d)** - Testing & Evaluation | F.1, F.6, A.6, D.5 | Regularly test and evaluate security - Access Analyzer, findings review, unused resource detection |
| **Art. 33** - Breach Notification | F.1, F.6 | Detect breaches without undue delay - Access Analyzer for external access detection, active findings |
| **Art. 5(1)(e)** - Storage Limitation | A.6, D.5, C.5, E.2 | Keep data only as long as necessary - remove unused credentials, roles, policies, groups |

---

## 11. NIST 800-53 Rev5

### Security and Privacy Controls

| NIST Control | Check IDs | Description |
|-------------|-----------|-------------|
| **AC-2** - Account Management | A.6, A.8, A.9, E.3, D.5, C.5 | Manage information system accounts - unused creds, group membership, unused roles/policies |
| **AC-2(1)** - Automated Account Management | A.6, D.5, A.11 | Automated account management mechanisms - detect unused credentials, roles, limit root usage |
| **AC-3** - Access Enforcement | C.1, D.1, E.1 | Enforce approved authorizations - least privilege policies, no admin roles/groups |
| **AC-5** - Separation of Duties | A.8, A.9, E.3, C.1 | Enforce separation of duties - group-based permissions, no single admin policies |
| **AC-6** - Least Privilege | C.1, C.2, C.3, D.1, D.4 | Employ least privilege principle - no admin policies, no wildcards, no PassRole * |
| **AC-6(1)** - Authorize Access to Security Functions | D.1, E.1, A.1 | Explicitly authorize access to security functions - admin roles/groups, root key review |
| **AC-6(5)** - Privileged Accounts | D.1, E.1, C.1, A.11 | Restrict privileged accounts - no unnecessary admin access, limit root usage |
| **AC-17** - Remote Access | D.2, G.5, F.4 | Establish and manage remote access - role trust policies, cross-account, CloudShell |
| **IA-2** - Identification and Authentication | A.2, A.3, A.4, A.10 | Uniquely identify and authenticate users - MFA for root and all users, hardware MFA |
| **IA-2(1)** - MFA to Privileged Accounts | A.2, A.10 | MFA to privileged accounts (Rev5) - root MFA, console MFA |
| **IA-2(2)** - MFA for Non-privileged Accounts | A.4 | MFA for non-privileged accounts - MFA for all users |
| **IA-4** - Identifier Management | A.6, E.3 | Manage information system identifiers - unused credentials, group membership |
| **IA-5** - Authenticator Management | B.1-B.8, A.5, A.7 | Manage authenticators - password policy, key rotation, single active key |
| **IA-5(1)** - Password-Based Authentication | B.1-B.8 | Password-based authentication controls - full password policy compliance |
| **AU-2** - Event Logging | F.1, F.6 | Determine events to be logged - Access Analyzer for access monitoring, findings reviewed |
| **AU-6** - Audit Review | F.1, F.6, D.5, C.5 | Review and analyze audit records - Access Analyzer, unused resource detection |
| **CM-6** - Configuration Settings | B.1-B.8, F.1 | Establish and enforce security configuration settings - password policy, Access Analyzer |
| **CM-7** - Least Functionality | C.5, D.5, E.2 | Restrict to essential capabilities only - remove unused policies, roles, groups |
| **SI-4** - System Monitoring | F.1, F.6 | Monitor information system - Access Analyzer, active findings |
| **SC-12** - Cryptographic Key Management | F.3, A.5 | Manage cryptographic keys - SSL/TLS certificates, access key rotation |
| **SC-28** - Protection of Information at Rest | F.3, F.5 | Protect information at rest - certificate management, prefer ACM |

---

## Compliance Lambda Implementation Pattern

All compliance controls are implemented as lambda functions that evaluate against the account-level checks dictionary. The pattern follows the Toc Consulting convention established in ec2-security-scanner.

### Key Principles

1. **Fail-closed defaults:** When data is missing, assume the worst:
   - `.get("bad_thing", True)` - assume bad thing exists
   - `.get("good_thing", False)` - assume good thing is missing
   - `.get("count", 1)` - assume at least one violation exists

2. **Cross-reference contract:** Every key name in the compliance lambdas MUST exactly match the key name set in `scanner.py` and referenced in `utils.py:calculate_security_score()`. This is validated by tests - any mismatch is a bug.

3. **Boolean return:** Every lambda returns `True` (pass) or `False` (fail).

4. **Compound checks pattern:** When a single compliance control maps to multiple scanner checks, use `and` to require all checks pass:
   ```python
   # CIS 1.15 - permissions only through groups (both A.8 AND A.9)
   "check": lambda r: (
       r.get("direct_attached_policies", {}).get("count", 1) == 0
       and r.get("inline_user_policies", {}).get("count", 1) == 0
   ),
   ```

5. **Conditional checks pattern:** When a check depends on another (e.g., F.6 only meaningful if F.1 passes):
   ```python
   # F.6 - Active findings (only relevant if analyzer is enabled)
   # If analyzer is not enabled, this control fails separately via F.1
   # Here we check: analyzer not enabled (auto-fail) OR no active findings
   "check": lambda r: (
       not r.get("access_analyzer", {}).get("enabled", False)
       or r.get("access_analyzer_findings", {}).get("count", 1) == 0
   ),
   ```
   > Note: This pattern means F.6 passes if Access Analyzer is disabled (since F.1 already catches that). The alternative (fail both) would double-penalize accounts without an analyzer.

### Example Implementation

```python
self.frameworks = {
    "AWS-FSBP": {
        "name": "AWS Foundational Security Best Practices",
        "controls": {
            "IAM.1": {
                "description": "IAM policies should not allow full admin privileges",
                "severity": "HIGH",
                "check": lambda r: r.get("admin_policies", {}).get("count", 1) == 0,
            },
            "IAM.4": {
                "description": "IAM root user access key should not exist",
                "severity": "CRITICAL",
                "check": lambda r: not r.get("root_access_keys", {}).get("exists", True),
            },
            "IAM.9": {
                "description": "MFA should be enabled for the root user",
                "severity": "CRITICAL",
                "check": lambda r: r.get("root_mfa", {}).get("enabled", False),
            },
        },
    },
}
```

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Compliance Controls** | 128 |
| **Compliance Frameworks** | 10 |
| **Scanner Checks** | 44 |
| **AWS-FSBP Controls** | 22 |
| **CIS v5.0.0 Controls** | 13 |
| **PCI DSS v4.0.1 Controls** | 12 |
| **HIPAA Controls** | 11 |
| **SOC 2 Controls** | 14 |
| **ISO 27001:2022 Controls** | 13 |
| **ISO 27017 Controls** | 8 |
| **ISO 27018 Controls** | 6 |
| **GDPR Controls** | 8 |
| **NIST 800-53 Rev5 Controls** | 21 |
