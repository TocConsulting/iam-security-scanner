"""Tests for User Security checker (A.1-A.11)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from iam_security_scanner.checks.user_security import (
    UserSecurityChecker,
)


def _days_ago(days):
    """Return an ISO-8601 UTC timestamp `days` in the past.

    Used so time-relative assertions (key rotation, root usage) stay
    valid as real time passes instead of relying on fixed dates.
    """
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()


def _make_credential_row(
    user="testuser",
    mfa_active="true",
    password_enabled="true",
    password_last_used="2026-01-01T00:00:00+00:00",
    key1_active="false",
    key1_rotated="N/A",
    key1_last_used="N/A",
    key2_active="false",
    key2_rotated="N/A",
    key2_last_used="N/A",
):
    return {
        "user": user,
        "mfa_active": mfa_active,
        "password_enabled": password_enabled,
        "password_last_used": password_last_used,
        "access_key_1_active": key1_active,
        "access_key_1_last_rotated": key1_rotated,
        "access_key_1_last_used_date": key1_last_used,
        "access_key_2_active": key2_active,
        "access_key_2_last_rotated": key2_rotated,
        "access_key_2_last_used_date": key2_last_used,
        "user_creation_time": "2025-01-01T00:00:00+00:00",
    }


def _make_root_row(**kwargs):
    defaults = {
        "user": "<root_account>",
        "mfa_active": "true",
        "password_enabled": "not_supported",
        "password_last_used": "no_information",
        "key1_active": "false",
        "key2_active": "false",
    }
    defaults.update(kwargs)
    return _make_credential_row(**defaults)


class TestRootAccessKeys:
    def test_no_root_keys(self):
        checker = UserSecurityChecker()
        root = _make_root_row()
        result = checker._check_root_access_keys(root)
        assert result["exists"] is False

    def test_root_has_key1(self):
        checker = UserSecurityChecker()
        root = _make_root_row(key1_active="true")
        result = checker._check_root_access_keys(root)
        assert result["exists"] is True

    def test_root_has_key2(self):
        checker = UserSecurityChecker()
        root = _make_root_row(key2_active="true")
        result = checker._check_root_access_keys(root)
        assert result["exists"] is True

    def test_null_root_fails_closed(self):
        checker = UserSecurityChecker()
        result = checker._check_root_access_keys(None)
        assert result["exists"] is True


class TestRootMFA:
    def test_root_mfa_enabled(self):
        checker = UserSecurityChecker()
        root = _make_root_row(mfa_active="true")
        result = checker._check_root_mfa(root)
        assert result["enabled"] is True

    def test_root_mfa_disabled(self):
        checker = UserSecurityChecker()
        root = _make_root_row(mfa_active="false")
        result = checker._check_root_mfa(root)
        assert result["enabled"] is False

    def test_null_root_fails_closed(self):
        checker = UserSecurityChecker()
        result = checker._check_root_mfa(None)
        assert result["enabled"] is False


class TestRootHardwareMFA:
    def test_hardware_mfa(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"VirtualMFADevices": []},
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        checker = UserSecurityChecker(mock_session)
        result = checker._check_root_hardware_mfa(
            {"enabled": True, "hardware": False}
        )
        assert result["hardware"] is True

    def test_virtual_mfa(self):
        mock_session = MagicMock()
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = (
            mock_iam
        )

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "VirtualMFADevices": [
                    {
                        "SerialNumber": (
                            "arn:aws:iam::123456789012:"
                            "mfa/root-account-mfa-device"
                        )
                    }
                ]
            },
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        checker = UserSecurityChecker(mock_session)
        result = checker._check_root_hardware_mfa(
            {"enabled": True, "hardware": False}
        )
        assert result["hardware"] is False

    def test_mfa_not_enabled_skip(self):
        checker = UserSecurityChecker()
        result = checker._check_root_hardware_mfa(
            {"enabled": False, "hardware": False}
        )
        assert result["hardware"] is False


class TestUsersMFA:
    def test_all_have_mfa(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice", mfa_active="true"
            ),
            _make_credential_row(
                user="bob", mfa_active="true"
            ),
        ]
        result = checker._check_users_mfa(rows)
        assert result["count"] == 0

    def test_one_without_mfa(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice", mfa_active="true"
            ),
            _make_credential_row(
                user="bob", mfa_active="false"
            ),
        ]
        result = checker._check_users_mfa(rows)
        assert result["count"] == 1
        assert "bob" in result["users"]


class TestKeyRotation:
    def test_fresh_keys(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                key1_active="true",
                key1_rotated=_days_ago(10),
            ),
        ]
        result = checker._check_key_rotation(rows)
        assert result["count"] == 0

    def test_old_keys(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                key1_active="true",
                key1_rotated="2025-01-01T00:00:00+00:00",
            ),
        ]
        result = checker._check_key_rotation(rows)
        assert result["count"] == 1
        assert "alice" in result["users"]


class TestConsoleNoMFA:
    def test_console_with_mfa(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                password_enabled="true",
                mfa_active="true",
            ),
        ]
        result = checker._check_console_no_mfa(rows)
        assert result["count"] == 0

    def test_console_without_mfa(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                password_enabled="true",
                mfa_active="false",
            ),
        ]
        result = checker._check_console_no_mfa(rows)
        assert result["count"] == 1

    def test_no_console_no_mfa(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                password_enabled="false",
                mfa_active="false",
            ),
        ]
        result = checker._check_console_no_mfa(rows)
        assert result["count"] == 0


class TestMultipleKeys:
    def test_single_key(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                key1_active="true",
                key2_active="false",
            ),
        ]
        result = checker._check_multiple_keys(rows)
        assert result["count"] == 0

    def test_both_keys_active(self):
        checker = UserSecurityChecker()
        rows = [
            _make_credential_row(
                user="alice",
                key1_active="true",
                key2_active="true",
            ),
        ]
        result = checker._check_multiple_keys(rows)
        assert result["count"] == 1


class TestRootUsage:
    def test_root_not_used_recently(self):
        checker = UserSecurityChecker()
        root = _make_root_row(
            password_last_used="2025-01-01T00:00:00+00:00"
        )
        result = checker._check_root_usage(root)
        assert result["used_recently"] is False

    def test_root_used_recently(self):
        checker = UserSecurityChecker()
        root = _make_root_row(
            password_last_used=_days_ago(10)
        )
        result = checker._check_root_usage(root)
        assert result["used_recently"] is True

    def test_root_never_used(self):
        checker = UserSecurityChecker()
        root = _make_root_row(
            password_last_used="no_information"
        )
        result = checker._check_root_usage(root)
        assert result["used_recently"] is False
        assert result["last_used"] == "never"

    def test_null_root_fails_closed(self):
        checker = UserSecurityChecker()
        result = checker._check_root_usage(None)
        assert result["used_recently"] is True
