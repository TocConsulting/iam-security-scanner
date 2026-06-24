"""Tests for privilege-escalation detection (G.1-G.3)."""

from iam_security_scanner.checks.privilege_escalation import (
    find_privesc_methods,
    policy_allows_assume_role_star,
)


def _doc(*actions, resource="*", effect="Allow", notaction=False):
    stmt = {"Effect": effect, "Resource": resource}
    if notaction:
        stmt["NotAction"] = list(actions)
    else:
        stmt["Action"] = list(actions)
    return {"Version": "2012-10-17", "Statement": [stmt]}


class TestPrivescMethods:
    def test_create_policy_version(self):
        assert "CreatePolicyVersion" in find_privesc_methods(
            _doc("iam:CreatePolicyVersion")
        )

    def test_passrole_ec2_requires_both(self):
        assert "PassRoleToEC2" in find_privesc_methods(
            _doc("iam:PassRole", "ec2:RunInstances")
        )

    def test_passrole_alone_not_enough(self):
        assert find_privesc_methods(_doc("iam:PassRole")) == []

    def test_attach_user_policy(self):
        assert "AttachUserPolicy" in find_privesc_methods(
            _doc("iam:AttachUserPolicy")
        )

    def test_update_assume_role_policy_needs_sts(self):
        assert "UpdateAssumeRolePolicy" in find_privesc_methods(
            _doc("iam:UpdateAssumeRolePolicy", "sts:AssumeRole")
        )
        assert "UpdateAssumeRolePolicy" not in find_privesc_methods(
            _doc("iam:UpdateAssumeRolePolicy")
        )

    def test_wildcard_service_expands(self):
        assert "PassRoleToEC2" in find_privesc_methods(
            _doc("iam:*", "ec2:*")
        )

    def test_full_admin_triggers_many(self):
        assert len(find_privesc_methods(_doc("*"))) >= 10

    def test_notaction_allow_is_effectively_all(self):
        assert len(
            find_privesc_methods(_doc("iam:DeleteUser", notaction=True))
        ) >= 10

    def test_readonly_is_clean(self):
        assert find_privesc_methods(
            _doc("s3:GetObject", "ec2:DescribeInstances")
        ) == []

    def test_deny_statement_ignored(self):
        assert find_privesc_methods(
            _doc("iam:CreatePolicyVersion", effect="Deny")
        ) == []


class TestAssumeRoleStar:
    def test_assume_role_on_star(self):
        assert policy_allows_assume_role_star(
            _doc("sts:AssumeRole", resource="*")
        ) is True

    def test_assume_role_scoped_is_clean(self):
        assert policy_allows_assume_role_star(
            _doc("sts:AssumeRole", resource="arn:aws:iam::1:role/x")
        ) is False

    def test_assume_role_on_role_glob(self):
        assert policy_allows_assume_role_star(
            _doc("sts:AssumeRole", resource="arn:aws:iam::1:role/*")
        ) is True

    def test_star_action_counts(self):
        assert policy_allows_assume_role_star(
            _doc("*", resource="*")
        ) is True
