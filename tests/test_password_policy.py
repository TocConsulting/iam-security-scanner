"""Tests for Password Policy checker (B.1-B.7)."""

from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from iam_security_scanner.checks.password_policy import (
    PasswordPolicyChecker,
)


def _make_client_error(code="NoSuchEntity"):
    return ClientError(
        {"Error": {"Code": code, "Message": "test"}},
        "GetAccountPasswordPolicy",
    )


class TestPasswordPolicyExists:
    def test_strong_policy(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "PasswordReusePrevention": 24,
                "MaxPasswordAge": 90,
            }
        }

        checker = PasswordPolicyChecker(mock_session)
        result = checker.check_all()
        pp = result["password_policy"]

        assert pp["exists"] is True
        assert pp["min_length"] == 14
        assert pp["require_uppercase"] is True
        assert pp["require_lowercase"] is True
        assert pp["require_numbers"] is True
        assert pp["require_symbols"] is True
        assert pp["reuse_prevention"] == 24
        assert pp["max_age"] == 90

    def test_weak_policy(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        }

        checker = PasswordPolicyChecker(mock_session)
        result = checker.check_all()
        pp = result["password_policy"]

        assert pp["exists"] is True
        assert pp["min_length"] == 8
        assert pp["require_uppercase"] is False
        assert pp["reuse_prevention"] == 0
        assert pp["max_age"] == 0


class TestNoPasswordPolicy:
    def test_no_policy_nosuchentity(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )
        mock_iam.get_account_password_policy.side_effect = (
            _make_client_error("NoSuchEntity")
        )

        checker = PasswordPolicyChecker(mock_session)
        result = checker.check_all()
        pp = result["password_policy"]

        assert pp["exists"] is False
        assert pp["min_length"] == 0
        assert pp["require_uppercase"] is False
        assert pp["require_lowercase"] is False
        assert pp["require_numbers"] is False
        assert pp["require_symbols"] is False
        assert pp["reuse_prevention"] == 0
        assert pp["max_age"] == 0
