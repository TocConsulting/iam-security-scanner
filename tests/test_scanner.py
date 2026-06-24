"""Tests for Scanner orchestration."""

import base64
from unittest.mock import MagicMock, patch

from iam_security_scanner.scanner import IAMSecurityScanner


class TestScannerInit:
    @patch("iam_security_scanner.scanner.setup_logging")
    @patch("boto3.Session")
    def test_init_creates_session(
        self, mock_boto_session, mock_logging
    ):
        mock_session = MagicMock()
        mock_boto_session.return_value = mock_session
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
        }
        mock_session.client.return_value = mock_sts

        scanner = IAMSecurityScanner(
            region="us-east-1",
            output_dir="/tmp/test_output",
        )

        assert scanner.account_id == "123456789012"
        assert scanner.max_workers == 6


class TestCredentialReport:
    @patch("iam_security_scanner.scanner.setup_logging")
    @patch("boto3.Session")
    def test_parse_credential_report(
        self, mock_boto_session, mock_logging
    ):
        mock_session = MagicMock()
        mock_boto_session.return_value = mock_session
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
        }

        csv_content = (
            "user,mfa_active,access_key_1_active\n"
            "<root_account>,true,false\n"
            "alice,true,true\n"
        )
        mock_iam = MagicMock()
        mock_iam.get_credential_report.return_value = {
            "ReportFormat": "text/csv",
            "Content": csv_content.encode("utf-8"),
        }

        def client_factory(service, **kwargs):
            if service == "sts":
                return mock_sts
            return mock_iam

        mock_session.client.side_effect = client_factory

        scanner = IAMSecurityScanner(
            region="us-east-1",
            output_dir="/tmp/test_output",
        )
        report = scanner._generate_credential_report()

        assert len(report) == 2
        assert report[0]["user"] == "<root_account>"
        assert report[1]["user"] == "alice"


class TestBuildIssues:
    @patch("iam_security_scanner.scanner.setup_logging")
    @patch("boto3.Session")
    def test_issues_sorted_by_severity(
        self, mock_boto_session, mock_logging
    ):
        mock_session = MagicMock()
        mock_boto_session.return_value = mock_session
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
        }
        mock_session.client.return_value = mock_sts

        scanner = IAMSecurityScanner(
            region="us-east-1",
            output_dir="/tmp/test_output",
        )

        checks = {
            "root_access_keys": {"exists": True},
            "root_mfa": {
                "enabled": True, "hardware": True,
            },
            "root_usage": {
                "used_recently": False,
                "last_used": "never",
            },
            "admin_policies": {
                "count": 1, "policies": ["admin"],
            },
            "unused_policies": {
                "count": 2, "policies": ["p1", "p2"],
            },
            "users_without_mfa": {
                "count": 0, "users": [],
            },
            "console_no_mfa": {
                "count": 0, "users": [],
            },
            "old_access_keys": {
                "count": 0, "users": [],
            },
            "unused_credentials": {
                "count": 0, "users": [],
            },
            "multiple_access_keys": {
                "count": 0, "users": [],
            },
            "direct_attached_policies": {
                "count": 0, "users": [],
            },
            "inline_user_policies": {
                "count": 0, "users": [],
            },
            "wildcard_service_policies": {
                "count": 0, "policies": [],
            },
            "passrole_star_policies": {
                "count": 0, "policies": [],
            },
            "notaction_policies": {
                "count": 0, "policies": [],
            },
            "admin_roles": {"count": 0, "roles": []},
            "wildcard_principal_roles": {
                "count": 0, "roles": [],
            },
            "cross_account_roles": {
                "count": 0, "roles": [],
            },
            "overprivileged_roles": {
                "count": 0, "roles": [],
            },
            "unused_roles": {"count": 0, "roles": []},
            "admin_groups": {"count": 0, "groups": []},
            "empty_groups": {"count": 0, "groups": []},
            "users_not_in_groups": {
                "count": 0, "users": [],
            },
            "access_analyzer": {
                "enabled": True, "analyzers": ["d"],
            },
            "access_analyzer_findings": {
                "count": 0, "findings": [],
            },
            "support_role": {"exists": True},
            "expired_certificates": {
                "count": 0, "certificates": [],
            },
            "cloudshell_full_access": {
                "count": 0, "identities": [],
            },
            "iam_server_certificates": {
                "count": 0, "certificates": [],
            },
        }

        issues = scanner._build_issues(checks)

        # CRITICAL should be first
        assert issues[0]["severity"] == "CRITICAL"
        assert issues[0]["check_id"] == "A.1"

        # HIGH should be after CRITICAL
        severities = [i["severity"] for i in issues]
        crit_idx = severities.index("CRITICAL")
        high_idx = severities.index("HIGH")
        assert crit_idx < high_idx
