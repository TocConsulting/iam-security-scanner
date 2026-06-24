"""Tests for Policy Security checker (C.1-C.5)."""

from unittest.mock import MagicMock

from iam_security_scanner.checks.policy_security import (
    PolicySecurityChecker,
)


def _make_policy(
    name="TestPolicy",
    arn="arn:aws:iam::123456789012:policy/TestPolicy",
    version="v1",
    attachment_count=1,
):
    return {
        "PolicyName": name,
        "Arn": arn,
        "DefaultVersionId": version,
        "AttachmentCount": attachment_count,
    }


class TestAdminPolicies:
    def test_admin_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="AdminPolicy")]
        result = checker.check_all(policies)

        assert result["admin_policies"]["count"] == 1
        assert "AdminPolicy" in (
            result["admin_policies"]["policies"]
        )

    def test_non_admin_not_flagged(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": (
                                "arn:aws:s3:::mybucket/*"
                            ),
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="ReadPolicy")]
        result = checker.check_all(policies)

        assert result["admin_policies"]["count"] == 0


class TestWildcardServicePolicies:
    def test_service_wildcard_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="S3Full")]
        result = checker.check_all(policies)

        assert (
            result["wildcard_service_policies"]["count"]
            == 1
        )

    def test_prefix_wildcard_not_flagged(self):
        """ec2:Describe* is acceptable, not exact service:*."""
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "ec2:Describe*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="EC2Read")]
        result = checker.check_all(policies)

        assert (
            result["wildcard_service_policies"]["count"]
            == 0
        )


class TestPassRoleStar:
    def test_passrole_star_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="PassRolePolicy")]
        result = checker.check_all(policies)

        assert (
            result["passrole_star_policies"]["count"] == 1
        )


class TestNotActionPolicies:
    def test_notaction_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotAction": "iam:*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [_make_policy(name="NotActionPolicy")]
        result = checker.check_all(policies)

        assert result["notaction_policies"]["count"] == 1


class TestUnusedPolicies:
    def test_unused_detected(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [
            _make_policy(
                name="UnusedPolicy", attachment_count=0
            ),
        ]
        result = checker.check_all(policies)

        assert result["unused_policies"]["count"] == 1

    def test_attached_policy_not_flagged(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }

        checker = PolicySecurityChecker(mock_session)
        policies = [
            _make_policy(
                name="UsedPolicy", attachment_count=3
            ),
        ]
        result = checker.check_all(policies)

        assert result["unused_policies"]["count"] == 0
