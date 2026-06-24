"""Tests for category B password-policy findings (B.1-B.8)."""

from iam_security_scanner.scanner import IAMSecurityScanner

# _build_password_policy_issues does not use `self`, so we can call it
# unbound with a dummy first argument to test the pure logic.
_build = IAMSecurityScanner._build_password_policy_issues


def _ids(checks):
    return {i["check_id"] for i in _build(None, checks)}


def _strong():
    return {
        "password_policy": {
            "exists": True,
            "min_length": 14,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_symbols": True,
            "reuse_prevention": 24,
            "max_age": 90,
        }
    }


def test_no_policy_emits_only_b1():
    checks = {"password_policy": {"exists": False}}
    assert _ids(checks) == {"B.1"}


def test_strong_policy_emits_nothing():
    assert _ids(_strong()) == set()


def test_weak_length_emits_b2():
    c = _strong()
    c["password_policy"]["min_length"] = 8
    assert "B.2" in _ids(c)


def test_missing_complexity_emits_b3_b6():
    c = _strong()
    c["password_policy"]["require_uppercase"] = False
    c["password_policy"]["require_symbols"] = False
    ids = _ids(c)
    assert "B.3" in ids and "B.6" in ids


def test_weak_reuse_and_age():
    c = _strong()
    c["password_policy"]["reuse_prevention"] = 5
    c["password_policy"]["max_age"] = 0  # never expires
    ids = _ids(c)
    assert "B.7" in ids and "B.8" in ids


def test_error_result_is_skipped():
    assert _ids({"password_policy": {"error": "AccessDenied"}}) == set()
