"""Mocked tests for A.12 (admin users) and F.7 (unused-access analyzer)."""

from unittest.mock import MagicMock

from iam_security_scanner.checks.user_security import (
    UserSecurityChecker,
)
from iam_security_scanner.checks.account_settings import (
    AccountSettingsChecker,
)

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _session_with(mock_client):
    s = MagicMock()
    s.return_value.client.return_value = mock_client
    return s


class TestAdminUsers:
    def test_user_with_admin_flagged(self):
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"AttachedPolicies": [{"PolicyArn": ADMIN_ARN}]}
        ]
        client.get_paginator.return_value = pag
        checker = UserSecurityChecker(_session_with(client))
        result = checker._check_admin_users([{"UserName": "alice"}])
        assert result["count"] == 1
        assert "alice" in result["users"]

    def test_user_without_admin_not_flagged(self):
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
            ]}
        ]
        client.get_paginator.return_value = pag
        checker = UserSecurityChecker(_session_with(client))
        result = checker._check_admin_users([{"UserName": "bob"}])
        assert result["count"] == 0


class TestUnusedAccessAnalyzer:
    def test_unused_access_analyzer_enabled(self):
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"analyzers": [
                {"name": "u", "type": "ACCOUNT_UNUSED_ACCESS",
                 "status": "ACTIVE"}
            ]}
        ]
        client.get_paginator.return_value = pag
        checker = AccountSettingsChecker(_session_with(client))
        result = checker._check_unused_access_analyzer()
        assert result["enabled"] is True
        assert "u" in result["analyzers"]

    def test_only_external_analyzer_not_counted(self):
        client = MagicMock()
        pag = MagicMock()
        pag.paginate.return_value = [
            {"analyzers": [
                {"name": "ext", "type": "ACCOUNT", "status": "ACTIVE"}
            ]}
        ]
        client.get_paginator.return_value = pag
        checker = AccountSettingsChecker(_session_with(client))
        result = checker._check_unused_access_analyzer()
        assert result["enabled"] is False
