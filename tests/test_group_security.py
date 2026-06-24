"""Tests for Group Security checker (E.1-E.3)."""

from unittest.mock import MagicMock

from iam_security_scanner.checks.group_security import (
    GroupSecurityChecker,
)


class TestAdminGroups:
    def test_admin_group_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        # Admin managed policy attached
        mock_pag_attached = MagicMock()
        mock_pag_attached.paginate.return_value = [
            {
                "AttachedPolicies": [
                    {
                        "PolicyArn": (
                            "arn:aws:iam::aws:policy/"
                            "AdministratorAccess"
                        )
                    }
                ]
            },
        ]

        mock_pag_groups_user = MagicMock()
        mock_pag_groups_user.paginate.return_value = [
            {"Groups": [{"GroupName": "admins"}]},
        ]

        def paginator_side_effect(api):
            if api == "list_attached_group_policies":
                return mock_pag_attached
            elif api == "list_groups_for_user":
                return mock_pag_groups_user
            return MagicMock()

        mock_iam.get_paginator.side_effect = (
            paginator_side_effect
        )
        mock_iam.get_group.return_value = {
            "Users": [{"UserName": "alice"}],
        }

        checker = GroupSecurityChecker(mock_session)
        groups = [{"GroupName": "admins"}]
        users = [{"UserName": "alice"}]
        result = checker.check_all(groups, users)

        assert result["admin_groups"]["count"] == 1


class TestEmptyGroups:
    def test_empty_group_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        # No admin policies
        mock_pag = MagicMock()
        mock_pag.paginate.return_value = [
            {"AttachedPolicies": []},
        ]
        mock_pag2 = MagicMock()
        mock_pag2.paginate.return_value = [
            {"PolicyNames": []},
        ]
        mock_pag_gfu = MagicMock()
        mock_pag_gfu.paginate.return_value = [
            {"Groups": [{"GroupName": "empty_grp"}]},
        ]

        def paginator_side_effect(api):
            if api == "list_attached_group_policies":
                return mock_pag
            elif api == "list_group_policies":
                return mock_pag2
            elif api == "list_groups_for_user":
                return mock_pag_gfu
            return MagicMock()

        mock_iam.get_paginator.side_effect = (
            paginator_side_effect
        )
        mock_iam.get_group.return_value = {"Users": []}

        checker = GroupSecurityChecker(mock_session)
        groups = [{"GroupName": "empty_grp"}]
        users = [{"UserName": "alice"}]
        result = checker.check_all(groups, users)

        assert result["empty_groups"]["count"] == 1


class TestUsersNotInGroups:
    def test_user_not_in_group(self):
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
        mock_pag_gfu = MagicMock()
        mock_pag_gfu.paginate.return_value = [
            {"Groups": []},  # No groups
        ]

        def paginator_side_effect(api):
            if api == "list_attached_group_policies":
                return mock_pag
            elif api == "list_group_policies":
                return mock_pag2
            elif api == "list_groups_for_user":
                return mock_pag_gfu
            return MagicMock()

        mock_iam.get_paginator.side_effect = (
            paginator_side_effect
        )
        mock_iam.get_group.return_value = {
            "Users": [{"UserName": "bob"}],
        }

        checker = GroupSecurityChecker(mock_session)
        groups = [{"GroupName": "devs"}]
        users = [{"UserName": "alice"}]
        result = checker.check_all(groups, users)

        assert result["users_not_in_groups"]["count"] == 1
        assert "alice" in (
            result["users_not_in_groups"]["users"]
        )
