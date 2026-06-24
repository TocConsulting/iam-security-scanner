"""Tests for security scoring function."""

import pytest

from iam_security_scanner.utils import calculate_security_score


def _all_pass_checks():
    """Return checks dict where every check passes."""
    return {
        "root_access_keys": {"exists": False},
        "root_mfa": {"enabled": True, "hardware": True},
        "root_usage": {
            "used_recently": False, "last_used": "never",
        },
        "users_without_mfa": {"count": 0, "users": []},
        "console_no_mfa": {"count": 0, "users": []},
        "old_access_keys": {"count": 0, "users": []},
        "unused_credentials": {"count": 0, "users": []},
        "multiple_access_keys": {"count": 0, "users": []},
        "direct_attached_policies": {
            "count": 0, "users": [],
        },
        "inline_user_policies": {"count": 0, "users": []},
        "password_policy": {
            "exists": True,
            "min_length": 14,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "reuse_prevention": 24,
            "max_age": 90,
        },
        "admin_policies": {"count": 0, "policies": []},
        "wildcard_service_policies": {
            "count": 0, "policies": [],
        },
        "passrole_star_policies": {
            "count": 0, "policies": [],
        },
        "notaction_policies": {
            "count": 0, "policies": [],
        },
        "unused_policies": {"count": 0, "policies": []},
        "admin_roles": {"count": 0, "roles": []},
        "wildcard_principal_roles": {
            "count": 0, "roles": [],
        },
        "cross_account_roles": {"count": 0, "roles": []},
        "overprivileged_roles": {"count": 0, "roles": []},
        "unused_roles": {"count": 0, "roles": []},
        "admin_groups": {"count": 0, "groups": []},
        "empty_groups": {"count": 0, "groups": []},
        "users_not_in_groups": {"count": 0, "users": []},
        "access_analyzer": {
            "enabled": True, "analyzers": ["default"],
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
        "unused_access_analyzer": {
            "enabled": True, "analyzers": ["unused"],
        },
        "admin_users": {"count": 0, "users": []},
        "privesc_managed_policies": {"count": 0, "findings": []},
        "privesc_inline_policies": {"count": 0, "findings": []},
        "permissive_assume_role": {"count": 0, "findings": []},
        "unguarded_trust": {"count": 0, "roles": []},
        "cross_account_trust": {"count": 0, "roles": []},
    }


def _all_fail_checks():
    """Return checks dict where every check fails."""
    return {
        "root_access_keys": {"exists": True},
        "root_mfa": {"enabled": False, "hardware": False},
        "root_usage": {
            "used_recently": True,
            "last_used": "2026-03-01",
        },
        "users_without_mfa": {
            "count": 5, "users": ["a", "b", "c", "d", "e"],
        },
        "console_no_mfa": {
            "count": 3, "users": ["a", "b", "c"],
        },
        "old_access_keys": {
            "count": 2, "users": ["a", "b"],
        },
        "unused_credentials": {
            "count": 2, "users": ["a", "b"],
        },
        "multiple_access_keys": {
            "count": 1, "users": ["a"],
        },
        "direct_attached_policies": {
            "count": 3, "users": ["a", "b", "c"],
        },
        "inline_user_policies": {
            "count": 2, "users": ["a", "b"],
        },
        "password_policy": {
            "exists": False,
            "min_length": 0,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_numbers": False,
            "require_symbols": False,
            "reuse_prevention": 0,
            "max_age": 0,
        },
        "admin_policies": {
            "count": 1, "policies": ["admin"],
        },
        "wildcard_service_policies": {
            "count": 1, "policies": ["s3_full"],
        },
        "passrole_star_policies": {
            "count": 1, "policies": ["passrole"],
        },
        "notaction_policies": {
            "count": 1, "policies": ["notaction"],
        },
        "unused_policies": {
            "count": 2, "policies": ["p1", "p2"],
        },
        "admin_roles": {
            "count": 1, "roles": ["admin_role"],
        },
        "wildcard_principal_roles": {
            "count": 1, "roles": ["open_role"],
        },
        "cross_account_roles": {
            "count": 1, "roles": ["cross"],
        },
        "overprivileged_roles": {
            "count": 1, "roles": ["overpriv"],
        },
        "unused_roles": {
            "count": 3, "roles": ["r1", "r2", "r3"],
        },
        "admin_groups": {
            "count": 1, "groups": ["admins"],
        },
        "empty_groups": {
            "count": 2, "groups": ["g1", "g2"],
        },
        "users_not_in_groups": {
            "count": 2, "users": ["a", "b"],
        },
        "access_analyzer": {
            "enabled": False, "analyzers": [],
        },
        "access_analyzer_findings": {
            "count": 3, "findings": ["f1", "f2", "f3"],
        },
        "support_role": {"exists": False},
        "expired_certificates": {
            "count": 1, "certificates": ["cert1"],
        },
        "cloudshell_full_access": {
            "count": 1, "identities": ["user:bob"],
        },
        "iam_server_certificates": {
            "count": 2, "certificates": ["c1", "c2"],
        },
    }


class TestAllPass:
    def test_all_pass_100(self):
        score = calculate_security_score(_all_pass_checks())
        assert score == 100

    def test_empty_checks_not_100(self):
        """Empty dict should fail-closed (not 100)."""
        score = calculate_security_score({})
        assert score < 100


class TestAllFail:
    def test_all_fail_zero(self):
        score = calculate_security_score(_all_fail_checks())
        assert score == 0


class TestCriticalDeductions:
    def test_root_access_keys(self):
        checks = _all_pass_checks()
        checks["root_access_keys"]["exists"] = True
        assert calculate_security_score(checks) == 75

    def test_root_no_mfa(self):
        checks = _all_pass_checks()
        checks["root_mfa"]["enabled"] = False
        checks["root_mfa"]["hardware"] = False
        assert calculate_security_score(checks) == 75

    def test_root_virtual_mfa(self):
        checks = _all_pass_checks()
        checks["root_mfa"]["hardware"] = False
        assert calculate_security_score(checks) == 95

    def test_wildcard_principal(self):
        checks = _all_pass_checks()
        checks["wildcard_principal_roles"]["count"] = 1
        assert calculate_security_score(checks) == 80


class TestMFANonStacking:
    def test_only_a4_penalty(self):
        """Only users_without_mfa fails -> -10."""
        checks = _all_pass_checks()
        checks["users_without_mfa"]["count"] = 2
        assert calculate_security_score(checks) == 90

    def test_only_a10_penalty(self):
        """Only console_no_mfa fails -> -15."""
        checks = _all_pass_checks()
        checks["console_no_mfa"]["count"] = 2
        assert calculate_security_score(checks) == 85

    def test_both_a4_a10_non_stacking(self):
        """Both fail -> max(-10, -15) = -15, NOT -25."""
        checks = _all_pass_checks()
        checks["users_without_mfa"]["count"] = 3
        checks["console_no_mfa"]["count"] = 2
        assert calculate_security_score(checks) == 85


class TestPasswordPolicyNoPolicy:
    def test_no_policy_deduction(self):
        """No password policy -> -21 total."""
        checks = _all_pass_checks()
        checks["password_policy"] = {
            "exists": False,
            "min_length": 0,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_numbers": False,
            "require_symbols": False,
            "reuse_prevention": 0,
            "max_age": 0,
        }
        assert calculate_security_score(checks) == 79


class TestPasswordPolicyPartial:
    def test_weak_length(self):
        checks = _all_pass_checks()
        checks["password_policy"]["min_length"] = 8
        assert calculate_security_score(checks) == 95

    def test_no_reuse_prevention(self):
        checks = _all_pass_checks()
        checks["password_policy"]["reuse_prevention"] = 0
        assert calculate_security_score(checks) == 98

    def test_no_max_age(self):
        checks = _all_pass_checks()
        checks["password_policy"]["max_age"] = 0
        assert calculate_security_score(checks) == 98


class TestHighDeductions:
    def test_admin_policies(self):
        checks = _all_pass_checks()
        checks["admin_policies"]["count"] = 1
        assert calculate_security_score(checks) == 85

    def test_admin_roles(self):
        checks = _all_pass_checks()
        checks["admin_roles"]["count"] = 1
        assert calculate_security_score(checks) == 85

    def test_passrole_star(self):
        checks = _all_pass_checks()
        checks["passrole_star_policies"]["count"] = 1
        assert calculate_security_score(checks) == 90

    def test_access_analyzer_disabled(self):
        checks = _all_pass_checks()
        checks["access_analyzer"]["enabled"] = False
        assert calculate_security_score(checks) == 90

    def test_admin_groups(self):
        checks = _all_pass_checks()
        checks["admin_groups"]["count"] = 1
        assert calculate_security_score(checks) == 90

    def test_overprivileged_roles(self):
        checks = _all_pass_checks()
        checks["overprivileged_roles"]["count"] = 1
        assert calculate_security_score(checks) == 90

    def test_access_analyzer_findings(self):
        checks = _all_pass_checks()
        checks["access_analyzer_findings"]["count"] = 2
        assert calculate_security_score(checks) == 90


class TestLowDeductions:
    def test_direct_attached(self):
        checks = _all_pass_checks()
        checks["direct_attached_policies"]["count"] = 1
        assert calculate_security_score(checks) == 95

    def test_inline_policies(self):
        checks = _all_pass_checks()
        checks["inline_user_policies"]["count"] = 1
        assert calculate_security_score(checks) == 98

    def test_multiple_keys(self):
        checks = _all_pass_checks()
        checks["multiple_access_keys"]["count"] = 1
        assert calculate_security_score(checks) == 98

    def test_no_support_role(self):
        checks = _all_pass_checks()
        checks["support_role"]["exists"] = False
        assert calculate_security_score(checks) == 98

    def test_empty_groups(self):
        checks = _all_pass_checks()
        checks["empty_groups"]["count"] = 1
        assert calculate_security_score(checks) == 98

    def test_unused_policies(self):
        checks = _all_pass_checks()
        checks["unused_policies"]["count"] = 1
        assert calculate_security_score(checks) == 98

    def test_unused_roles(self):
        checks = _all_pass_checks()
        checks["unused_roles"]["count"] = 1
        assert calculate_security_score(checks) == 98

    def test_iam_certs(self):
        checks = _all_pass_checks()
        checks["iam_server_certificates"]["count"] = 1
        assert calculate_security_score(checks) == 99

    def test_root_used_recently(self):
        checks = _all_pass_checks()
        checks["root_usage"]["used_recently"] = True
        assert calculate_security_score(checks) == 98


class TestErrorHandling:
    def test_error_in_check_uses_default(self):
        """Checks with error key should use fail-closed defaults."""
        checks = _all_pass_checks()
        checks["admin_policies"] = {
            "error": "AccessDenied",
        }
        score = calculate_security_score(checks)
        # Error means fail-closed: count defaults to 1 (worst case)
        assert score < 100

    def test_score_never_negative(self):
        score = calculate_security_score(_all_fail_checks())
        assert score >= 0


class TestNewCheckScoring:
    """Scoring for checks added in v1.0.0 (privesc, admin-user, etc.)."""

    def test_privesc_managed_deducts_20(self):
        checks = _all_pass_checks()
        checks["privesc_managed_policies"] = {
            "count": 2, "findings": []
        }
        assert calculate_security_score(checks) == 80

    def test_privesc_non_stacking(self):
        # managed + inline together still -20 (non-stacking)
        checks = _all_pass_checks()
        checks["privesc_managed_policies"] = {"count": 1, "findings": []}
        checks["privesc_inline_policies"] = {"count": 1, "findings": []}
        assert calculate_security_score(checks) == 80

    def test_admin_users_deducts_15(self):
        checks = _all_pass_checks()
        checks["admin_users"] = {"count": 1, "users": ["a"]}
        assert calculate_security_score(checks) == 85

    def test_permissive_assume_role_deducts_10(self):
        checks = _all_pass_checks()
        checks["permissive_assume_role"] = {"count": 1, "findings": []}
        assert calculate_security_score(checks) == 90

    def test_unguarded_trust_deducts_10(self):
        checks = _all_pass_checks()
        checks["unguarded_trust"] = {"count": 1, "roles": []}
        assert calculate_security_score(checks) == 90

    def test_unused_access_analyzer_deducts_3(self):
        checks = _all_pass_checks()
        checks["unused_access_analyzer"] = {
            "enabled": False, "analyzers": []
        }
        assert calculate_security_score(checks) == 97
