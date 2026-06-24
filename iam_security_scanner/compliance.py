"""Compliance framework mapping for IAM Security Scanner.

10 frameworks, 128 controls, all implemented as lambda functions
that evaluate against the account-level checks dictionary.

Control IDs are verified against the authoritative standards (see the
research/ folder). Mapping IAM-only checks to broad governance frameworks
(HIPAA/GDPR/SOC2/ISO) is partial technical evidence, NOT a compliance
attestation.
"""


class ComplianceChecker:
    """Evaluate IAM security checks against 10 compliance
    frameworks with 128 total controls."""

    def __init__(self):
        self.frameworks = {}
        self._define_frameworks()

    def _define_frameworks(self):
        """Define all compliance frameworks and their controls."""

        # ==============================================================
        # AWS Foundational Security Best Practices (22 controls)
        # ==============================================================
        self.frameworks["AWS-FSBP"] = {
            "name": (
                "AWS Foundational Security Best Practices"
            ),
            "controls": {
                "IAM.1": {
                    "description": (
                        "IAM policies should not allow full "
                        "admin privileges"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.2": {
                    "description": (
                        "IAM users should not have IAM "
                        "policies attached directly"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.3": {
                    "description": (
                        "IAM users access keys should be "
                        "rotated every 90 days or less"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.4": {
                    "description": (
                        "IAM root user access key should "
                        "not exist"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: not (
                        r.get("root_access_keys", {})
                        .get("exists", True)
                    ),
                },
                "IAM.5": {
                    "description": (
                        "MFA should be enabled for all IAM "
                        "users that have a console password"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.6": {
                    "description": (
                        "Hardware MFA should be enabled for "
                        "the root user"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("hardware", False)
                    ),
                },
                "IAM.8": {
                    "description": (
                        "Unused IAM user credentials should "
                        "be removed"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.9": {
                    "description": (
                        "MFA should be enabled for the "
                        "root user"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                    ),
                },
                "IAM.11": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "at least one uppercase letter"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("require_uppercase", False)
                    ),
                },
                "IAM.12": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "at least one lowercase letter"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("require_lowercase", False)
                    ),
                },
                "IAM.13": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "at least one symbol"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("require_symbols", False)
                    ),
                },
                "IAM.14": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "at least one number"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("require_numbers", False)
                    ),
                },
                "IAM.15": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "minimum length of 14"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                    ),
                },
                "IAM.16": {
                    "description": (
                        "Ensure IAM password policy prevents "
                        "password reuse"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("reuse_prevention", 0) >= 24
                    ),
                },
                "IAM.17": {
                    "description": (
                        "Ensure IAM password policy expires "
                        "passwords within 90 days"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        0 < r.get("password_policy", {})
                        .get("max_age", 0) <= 90
                    ),
                },
                "IAM.18": {
                    "description": (
                        "Ensure a support role has been "
                        "created for AWS Support"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("support_role", {})
                        .get("exists", False)
                    ),
                },
                "IAM.19": {
                    "description": (
                        "MFA should be enabled for all "
                        "IAM users"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("users_without_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.21": {
                    "description": (
                        "IAM customer managed policies "
                        "should not allow wildcard actions"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("wildcard_service_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.22": {
                    "description": (
                        "IAM user credentials unused for "
                        "45 days should be removed"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.26": {
                    "description": (
                        "Expired SSL/TLS certificates "
                        "managed in IAM should be removed"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.27": {
                    "description": (
                        "IAM identities should not have "
                        "AWSCloudShellFullAccess"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("cloudshell_full_access", {})
                        .get("count", 1) == 0
                    ),
                },
                "IAM.28": {
                    "description": (
                        "IAM Access Analyzer external access "
                        "analyzer should be enabled"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
            },
        }

        # ==============================================================
        # CIS AWS Foundations Benchmark v5.0.0 (16 controls)
        # NOTE: control numbers below are the v5.0.0 IAM (Section 1)
        # numbering as published in the AWS Security Hub version-comparison
        # table. CIS v7.0.0 (Apr 2026) re-sectioned IAM into Section 2;
        # adopt that numbering once the official v7 PDF is confirmed.
        # ==============================================================
        self.frameworks["CIS-v5.0"] = {
            "name": (
                "CIS AWS Foundations Benchmark v5.0.0"
            ),
            "controls": {
                "1.3": {
                    "description": (
                        "Ensure no root user access key "
                        "exists"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: not (
                        r.get("root_access_keys", {})
                        .get("exists", True)
                    ),
                },
                "1.4": {
                    "description": (
                        "Ensure MFA is enabled for the "
                        "root user account"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                    ),
                },
                "1.5": {
                    "description": (
                        "Ensure hardware MFA is enabled "
                        "for the root user account"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("hardware", False)
                    ),
                },
                "1.7": {
                    "description": (
                        "Ensure IAM password policy requires "
                        "minimum length of 14"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                    ),
                },
                "1.8": {
                    "description": (
                        "Ensure IAM password policy prevents "
                        "password reuse"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("reuse_prevention", 0) >= 24
                    ),
                },
                "1.9": {
                    "description": (
                        "Ensure MFA is enabled for all IAM "
                        "users that have a console password"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "1.11": {
                    "description": (
                        "Ensure credentials unused for 45 "
                        "days or greater are disabled"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "1.13": {
                    "description": (
                        "Ensure access keys are rotated "
                        "every 90 days or less"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "1.14": {
                    "description": (
                        "Ensure IAM users receive "
                        "permissions only through groups"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                    ),
                },
                "1.16": {
                    "description": (
                        "Ensure a support role has been "
                        "created to manage incidents"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("support_role", {})
                        .get("exists", False)
                    ),
                },
                "1.18": {
                    "description": (
                        "Ensure expired SSL/TLS certificates "
                        "stored in IAM are removed"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "1.19": {
                    "description": (
                        "Ensure IAM Access Analyzer is "
                        "enabled for all regions"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "1.21": {
                    "description": (
                        "Ensure access to "
                        "AWSCloudShellFullAccess is "
                        "restricted"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("cloudshell_full_access", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # PCI DSS v4.0.1 (12 controls) - v4.0 retired 31 Dec 2024
        # ==============================================================
        self.frameworks["PCI-DSS-v4.0.1"] = {
            "name": (
                "Payment Card Industry Data Security "
                "Standard v4.0.1"
            ),
            "controls": {
                "2.2.1": {
                    "description": (
                        "System configuration standards - "
                        "strong password policy"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                    ),
                },
                "7.2.1": {
                    "description": (
                        "Restrict access by business need - "
                        "least privilege"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "7.2.2": {
                    "description": (
                        "Access assigned based on job "
                        "classification - group-based"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "users_not_in_groups", {}
                        ).get("count", 1) == 0
                    ),
                },
                "7.2.4": {
                    "description": (
                        "Review access privileges "
                        "periodically - unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_policies", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                    ),
                },
                "7.2.6": {
                    "description": (
                        "All access authorized - role trust "
                        "policy review"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                    ),
                },
                "8.2.1": {
                    "description": (
                        "Root account security - no root "
                        "access keys, MFA enabled"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        not r.get("root_access_keys", {})
                        .get("exists", True)
                        and r.get("root_mfa", {})
                        .get("enabled", False)
                    ),
                },
                "8.2.4": {
                    "description": (
                        "User ID lifecycle - authorized "
                        "access, timely deprovisioning"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                    ),
                },
                "8.3.6": {
                    "description": (
                        "Password complexity requirements"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                        and r.get("password_policy", {})
                        .get("require_symbols", False)
                    ),
                },
                "8.3.7": {
                    "description": (
                        "Password history - prevent reuse"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("reuse_prevention", 0) >= 24
                    ),
                },
                "8.3.9": {
                    "description": (
                        "Change passwords every 90 days - "
                        "access key rotation"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "8.6.1": {
                    "description": (
                        "Management of system accounts - "
                        "no shared credentials"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("multiple_access_keys", {})
                        .get("count", 1) == 0
                        and r.get("notaction_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "10.2.1": {
                    "description": (
                        "Audit logs capture all access - "
                        "Access Analyzer enabled"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                        and r.get(
                            "access_analyzer_findings", {}
                        ).get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # HIPAA (11 controls)
        # ==============================================================
        self.frameworks["HIPAA"] = {
            "name": (
                "Health Insurance Portability and "
                "Accountability Act"
            ),
            "controls": {
                "164.312(a)(1)": {
                    "description": (
                        "Access Control - least privilege"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "164.312(a)(2)(i)": {
                    "description": (
                        "Unique User ID - group-based "
                        "management"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "users_not_in_groups", {}
                        ).get("count", 1) == 0
                    ),
                },
                "164.312(a)(2)(iii)": {
                    "description": (
                        "Automatic Logoff - unused "
                        "credential removal"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "164.312(a)(2)(iv)": {
                    "description": (
                        "Encryption - valid SSL/TLS "
                        "certificates"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "164.312(b)": {
                    "description": (
                        "Audit Controls - Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "164.312(c)(1)": {
                    "description": (
                        "Integrity - no PassRole *, no "
                        "NotAction, no overly permissive"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "passrole_star_policies", {}
                        ).get("count", 1) == 0
                        and r.get("notaction_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "overprivileged_roles", {}
                        ).get("count", 1) == 0
                    ),
                },
                "164.312(d)": {
                    "description": (
                        "Authentication - MFA for root "
                        "and all users"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "164.308(a)(1)": {
                    "description": (
                        "Security Management - role trust "
                        "policy review"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                    ),
                },
                "164.308(a)(4)": {
                    "description": (
                        "Information Access Management - "
                        "no direct policies, no admin"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get("admin_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "164.308(a)(5)": {
                    "description": (
                        "Security Awareness - strong "
                        "password policy"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                    ),
                },
                "164.308(a)(3)": {
                    "description": (
                        "Workforce Security - remove unused "
                        "credentials, roles, policies"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # SOC 2 (14 controls)
        # ==============================================================
        self.frameworks["SOC2"] = {
            "name": "SOC 2 Trust Service Criteria",
            "controls": {
                "CC5.1": {
                    "description": (
                        "Control Activities - wildcard "
                        "principals, Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "CC5.2": {
                    "description": (
                        "Control Activities - admin policies, "
                        "roles, groups"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "CC6.1": {
                    "description": (
                        "Logical Access Security - MFA, "
                        "password policy"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                        and r.get("password_policy", {})
                        .get("exists", False)
                    ),
                },
                "CC6.2": {
                    "description": (
                        "User Credential Management - key "
                        "rotation, unused creds"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("old_access_keys", {})
                        .get("count", 1) == 0
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and not r.get(
                            "root_access_keys", {}
                        ).get("exists", True)
                    ),
                },
                "CC6.3": {
                    "description": (
                        "Access Authorization - least "
                        "privilege, group-based, no privesc"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get(
                            "direct_attached_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "privesc_managed_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "privesc_inline_policies", {}
                        ).get("count", 1) == 0
                        and r.get("admin_users", {})
                        .get("count", 1) == 0
                    ),
                },
                "CC6.5": {
                    "description": (
                        "Credential Lifecycle - rotation, "
                        "unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("old_access_keys", {})
                        .get("count", 1) == 0
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "CC6.6": {
                    "description": (
                        "Restrict External Access - role "
                        "trust, CloudShell"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "cloudshell_full_access", {}
                        ).get("count", 1) == 0
                    ),
                },
                "CC6.8": {
                    "description": (
                        "Prevent Unauthorized Software - "
                        "CloudShell, NotAction"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get(
                            "cloudshell_full_access", {}
                        ).get("count", 1) == 0
                        and r.get("notaction_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "CC7.1": {
                    "description": (
                        "Detect Anomalies - Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "CC7.2": {
                    "description": (
                        "Monitor System Components - unused "
                        "credentials, roles"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "CC8.1": {
                    "description": (
                        "Change Management - no wildcard "
                        "service actions"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get(
                            "wildcard_service_policies", {}
                        ).get("count", 1) == 0
                        and r.get("notaction_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "A1.2": {
                    "description": (
                        "Availability - environmental "
                        "protections & recovery "
                        "(certificate hygiene)"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "P6.1": {
                    "description": (
                        "Privacy Controls - group-based "
                        "permissions"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "users_not_in_groups", {}
                        ).get("count", 1) == 0
                    ),
                },
                "P6.7": {
                    "description": (
                        "Privacy - restrict access to personal "
                        "data (limit root, remove unused creds)"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        not r.get("root_usage", {})
                        .get("used_recently", True)
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # ISO 27001:2022 (13 controls)
        # ==============================================================
        self.frameworks["ISO27001"] = {
            "name": "ISO 27001:2022 Annex A",
            "controls": {
                "A.5.15": {
                    "description": (
                        "Access Control - least privilege"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.5.16": {
                    "description": (
                        "Identity Management - lifecycle"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.5.17": {
                    "description": (
                        "Authentication Information - "
                        "MFA, password policy"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                        and r.get("password_policy", {})
                        .get("exists", False)
                    ),
                },
                "A.5.18": {
                    "description": (
                        "Access Rights - no admin, no "
                        "PassRole *, no overprivileged, no "
                        "privilege escalation"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "passrole_star_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "overprivileged_roles", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "privesc_managed_policies", {}
                        ).get("count", 1) == 0
                        and r.get("admin_users", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.8.2": {
                    "description": (
                        "Privileged Access Rights - admin "
                        "roles, groups, root"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                        and not r.get(
                            "root_access_keys", {}
                        ).get("exists", True)
                    ),
                },
                "A.8.3": {
                    "description": (
                        "Information Access Restriction - "
                        "trust policy, CloudShell"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "cloudshell_full_access", {}
                        ).get("count", 1) == 0
                    ),
                },
                "A.8.5": {
                    "description": (
                        "Secure Authentication - hardware "
                        "MFA, key rotation"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("hardware", False)
                        and r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.8.9": {
                    "description": (
                        "Configuration Management - "
                        "password policy, Access Analyzer"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "A.8.15": {
                    "description": (
                        "Logging - Access Analyzer enabled "
                        "and findings reviewed"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "A.8.16": {
                    "description": (
                        "Monitoring Activities - unused "
                        "creds, roles"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.8.24": {
                    "description": (
                        "Use of Cryptography - valid "
                        "certificates"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.8.18": {
                    "description": (
                        "Use of Privileged Utility Programs "
                        "- no wildcard service actions"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get(
                            "wildcard_service_policies", {}
                        ).get("count", 1) == 0
                        and r.get("notaction_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.5.3": {
                    "description": (
                        "Segregation of Duties - "
                        "group-based, limit root"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and not r.get("root_usage", {})
                        .get("used_recently", True)
                    ),
                },
            },
        }

        # ==============================================================
        # ISO 27017 (8 controls)
        # ==============================================================
        self.frameworks["ISO27017"] = {
            "name": "ISO/IEC 27017 Cloud Security",
            "controls": {
                "CLD.6.3.1": {
                    "description": (
                        "Shared Responsibilities - "
                        "group-based, least privilege"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "CLD.8.1.5": {
                    "description": (
                        "Removal of Cloud Assets - "
                        "unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("empty_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.9.4.2": {
                    "description": (
                        "Secure log-on procedures - root/"
                        "console MFA, password policy"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                        and r.get("password_policy", {})
                        .get("exists", False)
                    ),
                },
                "CLD.13.1.4": {
                    "description": (
                        "Security management for virtual "
                        "and physical networks - "
                        "trust policy, CloudShell"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "cloudshell_full_access", {}
                        ).get("count", 1) == 0
                    ),
                },
                "CLD.12.1.5": {
                    "description": (
                        "Administrator Security - no root "
                        "keys, no admin roles"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        not r.get("root_access_keys", {})
                        .get("exists", True)
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "CLD.12.4.5": {
                    "description": (
                        "Monitoring of Cloud Services - "
                        "Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "A.9.2.3": {
                    "description": (
                        "Privileged Access Rights - "
                        "admin roles, PassRole"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get(
                            "passrole_star_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "overprivileged_roles", {}
                        ).get("count", 1) == 0
                    ),
                },
                "A.10.1.1": {
                    "description": (
                        "Cryptographic Controls - "
                        "certificates, prefer ACM"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # ISO 27018 (6 controls)
        # ==============================================================
        self.frameworks["ISO27018"] = {
            "name": "ISO/IEC 27018 PII Processor",
            "controls": {
                "A.9.2": {
                    "description": (
                        "PII Access Control - least "
                        "privilege, group-based"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get(
                            "direct_attached_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                    ),
                },
                "A.9.4": {
                    "description": (
                        "PII User Access Management - "
                        "lifecycle"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.10.1": {
                    "description": (
                        "Cryptographic Controls for PII - "
                        "certificates"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.11.1": {
                    "description": (
                        "Data Minimization - remove "
                        "unused resources"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("unused_policies", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("empty_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "A.12.4": {
                    "description": (
                        "Audit Logging of PII Processing - "
                        "Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "A.11.2": {
                    "description": (
                        "Secure Disposal - unused "
                        "credentials, limit root"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and not r.get("root_usage", {})
                        .get("used_recently", True)
                    ),
                },
            },
        }

        # ==============================================================
        # GDPR (8 controls)
        # ==============================================================
        self.frameworks["GDPR"] = {
            "name": "General Data Protection Regulation",
            "controls": {
                "Art.5(1)(f)": {
                    "description": (
                        "Integrity & Confidentiality - "
                        "least privilege, MFA"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "Art.25": {
                    "description": (
                        "Data Protection by Design - "
                        "password policy, Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("access_analyzer", {})
                        .get("enabled", False)
                        and r.get(
                            "direct_attached_policies", {}
                        ).get("count", 1) == 0
                    ),
                },
                "Art.32(1)(a)": {
                    "description": (
                        "Encryption - valid certificates"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
                "Art.32(1)(b)": {
                    "description": (
                        "Confidentiality - least privilege, "
                        "trust policy"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "Art.32(1)(c)": {
                    "description": (
                        "Availability & Resilience - "
                        "support role, cert hygiene"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("support_role", {})
                        .get("exists", False)
                    ),
                },
                "Art.32(1)(d)": {
                    "description": (
                        "Testing & Evaluation - Access "
                        "Analyzer, unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                        and r.get("unused_credentials", {})
                        .get("count", 1) == 0
                    ),
                },
                "Art.33": {
                    "description": (
                        "Breach Notification - Access "
                        "Analyzer for detection"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "Art.5(1)(e)": {
                    "description": (
                        "Storage Limitation - remove "
                        "unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                        and r.get("empty_groups", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

        # ==============================================================
        # NIST 800-53 Rev5 (21 controls)
        # ==============================================================
        self.frameworks["NIST-800-53"] = {
            "name": "NIST 800-53 Rev5",
            "controls": {
                "AC-2": {
                    "description": (
                        "Account Management - unused creds, "
                        "group membership"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get(
                            "direct_attached_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "users_not_in_groups", {}
                        ).get("count", 1) == 0
                    ),
                },
                "AC-2(1)": {
                    "description": (
                        "Automated Account Management - "
                        "detect unused"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                    ),
                },
                "AC-3": {
                    "description": (
                        "Access Enforcement - least "
                        "privilege"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "AC-5": {
                    "description": (
                        "Separation of Duties - "
                        "group-based permissions"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("direct_attached_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "inline_user_policies", {}
                        ).get("count", 1) == 0
                    ),
                },
                "AC-6": {
                    "description": (
                        "Least Privilege - no admin, no "
                        "wildcards, no PassRole *, no "
                        "privilege-escalation paths"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_policies", {})
                        .get("count", 1) == 0
                        and r.get(
                            "wildcard_service_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "passrole_star_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "privesc_managed_policies", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "privesc_inline_policies", {}
                        ).get("count", 1) == 0
                        and r.get("admin_users", {})
                        .get("count", 1) == 0
                    ),
                },
                "AC-6(1)": {
                    "description": (
                        "Authorize Security Functions - "
                        "admin roles, root key"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                        and not r.get(
                            "root_access_keys", {}
                        ).get("exists", True)
                    ),
                },
                "AC-6(5)": {
                    "description": (
                        "Privileged Accounts - no admin, "
                        "limit root"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("admin_roles", {})
                        .get("count", 1) == 0
                        and r.get("admin_groups", {})
                        .get("count", 1) == 0
                        and not r.get("root_usage", {})
                        .get("used_recently", True)
                    ),
                },
                "AC-17": {
                    "description": (
                        "Remote Access - trust policies, "
                        "CloudShell"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get(
                            "wildcard_principal_roles", {}
                        ).get("count", 1) == 0
                        and r.get(
                            "cloudshell_full_access", {}
                        ).get("count", 1) == 0
                    ),
                },
                "IA-2": {
                    "description": (
                        "Identification and Authentication - "
                        "MFA"
                    ),
                    "severity": "CRITICAL",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "IA-2(1)": {
                    "description": (
                        "Multi-factor Authentication to "
                        "Privileged Accounts"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("root_mfa", {})
                        .get("enabled", False)
                        and r.get("console_no_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "IA-2(2)": {
                    "description": (
                        "MFA for Non-privileged Accounts"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("users_without_mfa", {})
                        .get("count", 1) == 0
                    ),
                },
                "IA-4": {
                    "description": (
                        "Identifier Management - unused "
                        "credentials, groups"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("unused_credentials", {})
                        .get("count", 1) == 0
                        and r.get(
                            "users_not_in_groups", {}
                        ).get("count", 1) == 0
                    ),
                },
                "IA-5": {
                    "description": (
                        "Authenticator Management - "
                        "password, key rotation"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("old_access_keys", {})
                        .get("count", 1) == 0
                        and r.get(
                            "multiple_access_keys", {}
                        ).get("count", 1) == 0
                    ),
                },
                "IA-5(1)": {
                    "description": (
                        "Password-Based Authentication"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("password_policy", {})
                        .get("min_length", 0) >= 14
                        and r.get("password_policy", {})
                        .get("require_uppercase", False)
                        and r.get("password_policy", {})
                        .get("require_lowercase", False)
                        and r.get("password_policy", {})
                        .get("require_numbers", False)
                        and r.get("password_policy", {})
                        .get("require_symbols", False)
                    ),
                },
                "AU-2": {
                    "description": (
                        "Event Logging - Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "AU-6": {
                    "description": (
                        "Audit Review - Access Analyzer, "
                        "unused resources"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("unused_policies", {})
                        .get("count", 1) == 0
                    ),
                },
                "CM-6": {
                    "description": (
                        "Configuration Settings - password "
                        "policy, Access Analyzer"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("password_policy", {})
                        .get("exists", False)
                        and r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "CM-7": {
                    "description": (
                        "Least Functionality - remove "
                        "unused resources"
                    ),
                    "severity": "LOW",
                    "check": lambda r: (
                        r.get("unused_policies", {})
                        .get("count", 1) == 0
                        and r.get("unused_roles", {})
                        .get("count", 1) == 0
                        and r.get("empty_groups", {})
                        .get("count", 1) == 0
                    ),
                },
                "SI-4": {
                    "description": (
                        "System Monitoring - Access Analyzer"
                    ),
                    "severity": "HIGH",
                    "check": lambda r: (
                        r.get("access_analyzer", {})
                        .get("enabled", False)
                    ),
                },
                "SC-12": {
                    "description": (
                        "Cryptographic Key Management - "
                        "certificates, key rotation"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                        and r.get("old_access_keys", {})
                        .get("count", 1) == 0
                    ),
                },
                "SC-28": {
                    "description": (
                        "Protection of Information at Rest - "
                        "certificate management"
                    ),
                    "severity": "MEDIUM",
                    "check": lambda r: (
                        r.get("expired_certificates", {})
                        .get("count", 1) == 0
                    ),
                },
            },
        }

    def check_compliance(self, checks):
        """Evaluate all compliance frameworks against checks.

        Args:
            checks: Account-level checks dictionary

        Returns:
            Dict with per-framework compliance results
        """
        results = {}
        for fw_id, framework in self.frameworks.items():
            passed = []
            failed = []
            for ctrl_id, control in (
                framework["controls"].items()
            ):
                try:
                    result = control["check"](checks)
                except Exception:
                    result = False  # Fail-closed

                entry = {
                    "control_id": ctrl_id,
                    "description": control["description"],
                    "severity": control["severity"],
                }
                if result:
                    passed.append(entry)
                else:
                    failed.append(entry)

            total = len(framework["controls"])
            results[fw_id] = {
                "framework_name": framework["name"],
                "total_controls": total,
                "passed_controls": len(passed),
                "failed_controls": len(failed),
                "compliance_percentage": round(
                    len(passed) / total * 100, 1
                ) if total > 0 else 0,
                "is_compliant": len(failed) == 0,
                "passed": passed,
                "failed": failed,
            }

        return results
