"""Tests for Account Settings checker (F.1-F.6)."""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from iam_security_scanner.checks.account_settings import (
    AccountSettingsChecker,
)


class TestAccessAnalyzer:
    def test_analyzer_enabled(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_client
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "analyzers": [
                    {
                        "name": "default",
                        "status": "ACTIVE",
                        "arn": (
                            "arn:aws:access-analyzer:"
                            "us-east-1:123:analyzer/default"
                        ),
                    }
                ]
            },
        ]
        mock_client.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_access_analyzer()

        assert result["enabled"] is True
        assert "default" in result["analyzers"]

    def test_no_analyzer(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_client
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"analyzers": []},
        ]
        mock_client.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_access_analyzer()

        assert result["enabled"] is False


class TestAccessAnalyzerFindings:
    def test_no_findings(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_client
        )

        # Mock list_analyzers for finding the ARN
        mock_pag_analyzers = MagicMock()
        mock_pag_analyzers.paginate.return_value = [
            {
                "analyzers": [
                    {
                        "name": "default",
                        "status": "ACTIVE",
                        "arn": "arn:aws:analyzer:us-east-1:123:analyzer/default",
                    }
                ]
            },
        ]

        # Mock list_findings
        mock_pag_findings = MagicMock()
        mock_pag_findings.paginate.return_value = [
            {"findings": []},
        ]

        def paginator_side_effect(api):
            if api == "list_analyzers":
                return mock_pag_analyzers
            elif api == "list_findings":
                return mock_pag_findings
            return MagicMock()

        mock_client.get_paginator.side_effect = (
            paginator_side_effect
        )

        checker = AccountSettingsChecker(mock_session)
        analyzer_result = {
            "enabled": True,
            "analyzers": ["default"],
        }
        result = checker._check_access_analyzer_findings(
            analyzer_result
        )

        assert result["count"] == 0

    def test_analyzer_not_enabled_returns_zero(self):
        checker = AccountSettingsChecker()
        result = checker._check_access_analyzer_findings(
            {"enabled": False, "analyzers": []}
        )
        assert result["count"] == 0


class TestSupportRole:
    def test_support_role_exists(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "AttachedPolicies": [
                    {
                        "PolicyArn": (
                            "arn:aws:iam::aws:policy/"
                            "AWSSupportAccess"
                        )
                    }
                ]
            },
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        roles = [{"RoleName": "SupportRole"}]
        result = checker._check_support_role(roles)

        assert result["exists"] is True

    def test_no_support_role(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        roles = [{"RoleName": "DevRole"}]
        result = checker._check_support_role(roles)

        assert result["exists"] is False


class TestExpiredCertificates:
    def test_expired_cert_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        past = datetime.now(timezone.utc) - timedelta(
            days=30
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "ServerCertificateMetadataList": [
                    {
                        "ServerCertificateName": "old-cert",
                        "Expiration": past,
                    }
                ]
            },
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_expired_certificates()

        assert result["count"] == 1
        assert "old-cert" in result["certificates"]

    def test_valid_cert_not_flagged(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        future = datetime.now(timezone.utc) + timedelta(
            days=365
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "ServerCertificateMetadataList": [
                    {
                        "ServerCertificateName": "good-cert",
                        "Expiration": future,
                    }
                ]
            },
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_expired_certificates()

        assert result["count"] == 0


class TestCloudShellAccess:
    def test_cloudshell_users_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "PolicyUsers": [
                    {"UserName": "bob"},
                ],
                "PolicyRoles": [],
                "PolicyGroups": [],
            },
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_cloudshell_access()

        assert result["count"] == 1
        assert "user:bob" in result["identities"]

    def test_cloudshell_policy_not_found(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchEntity",
                    "Message": "Policy not found",
                }
            },
            "ListEntitiesForPolicy",
        )
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_cloudshell_access()

        assert result["count"] == 0


class TestIAMCertificates:
    def test_iam_certs_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {
                "ServerCertificateMetadataList": [
                    {
                        "ServerCertificateName": "legacy",
                    }
                ]
            },
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_iam_certificates()

        assert result["count"] == 1

    def test_no_iam_certs(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"ServerCertificateMetadataList": []},
        ]
        mock_iam.get_paginator.return_value = mock_pag

        checker = AccountSettingsChecker(mock_session)
        result = checker._check_iam_certificates()

        assert result["count"] == 0
