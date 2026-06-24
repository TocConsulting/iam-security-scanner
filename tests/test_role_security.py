"""Tests for Role Security checker (D.1-D.5)."""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from iam_security_scanner.checks.role_security import (
    RoleSecurityChecker,
)


def _make_role(
    name="TestRole",
    path="/",
    trust_doc=None,
    last_used=None,
    create_date=None,
):
    role = {
        "RoleName": name,
        "Path": path,
        "AssumeRolePolicyDocument": trust_doc or {
            "Statement": [],
        },
    }
    if last_used:
        role["RoleLastUsed"] = {
            "LastUsedDate": last_used,
        }
    else:
        role["RoleLastUsed"] = {}
    if create_date:
        role["CreateDate"] = create_date
    return role


class TestWildcardPrincipal:
    def test_wildcard_principal_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        # No attached or inline policies
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="OpenRole",
                trust_doc={
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert (
            result["wildcard_principal_roles"]["count"] == 1
        )
        assert "OpenRole" in (
            result["wildcard_principal_roles"]["roles"]
        )

    def test_wildcard_with_condition_not_flagged(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="CondRole",
                trust_doc={
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {
                                    "aws:PrincipalOrgID": (
                                        "o-123456"
                                    )
                                }
                            },
                        }
                    ]
                },
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert (
            result["wildcard_principal_roles"]["count"] == 0
        )


class TestCrossAccountRoles:
    def test_cross_account_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="CrossRole",
                trust_doc={
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": (
                                    "arn:aws:iam::"
                                    "999999999999:root"
                                )
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert (
            result["cross_account_roles"]["count"] == 1
        )

    def test_same_account_not_flagged(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="SameAcctRole",
                trust_doc={
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": (
                                    "arn:aws:iam::"
                                    "123456789012:root"
                                )
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert (
            result["cross_account_roles"]["count"] == 0
        )


class TestServiceLinkedRoleExclusion:
    def test_service_linked_skipped(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="AWSServiceRoleForConfig",
                path="/aws-service-role/config/",
                trust_doc={
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        # Should not be flagged because service-linked
        assert (
            result["wildcard_principal_roles"]["count"] == 0
        )


class TestUnusedRoles:
    def test_recently_used(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        now = datetime.now(timezone.utc)
        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="ActiveRole",
                last_used=now - timedelta(days=10),
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert result["unused_roles"]["count"] == 0

    def test_unused_role(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_iam.get_paginator.side_effect = (
            lambda x: mock_pag
            if "attached" in x
            else mock_pag2
        )

        now = datetime.now(timezone.utc)
        checker = RoleSecurityChecker(mock_session)
        roles = [
            _make_role(
                name="OldRole",
                last_used=now - timedelta(days=120),
            ),
        ]
        result = checker.check_all(roles, "123456789012")

        assert result["unused_roles"]["count"] == 1
