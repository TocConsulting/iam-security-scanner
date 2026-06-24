"""Tests for compliance framework validation."""

import pytest

from iam_security_scanner.compliance import ComplianceChecker


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


class TestFrameworkDefinition:
    def test_all_frameworks_defined(self):
        checker = ComplianceChecker()
        expected = [
            "AWS-FSBP", "CIS-v5.0", "PCI-DSS-v4.0.1",
            "HIPAA", "SOC2", "ISO27001", "ISO27017",
            "ISO27018", "GDPR", "NIST-800-53",
        ]
        for fw in expected:
            assert fw in checker.frameworks, (
                f"Missing framework: {fw}"
            )
        assert len(checker.frameworks) == 10

    def test_total_control_count(self):
        checker = ComplianceChecker()
        total = sum(
            len(fw["controls"])
            for fw in checker.frameworks.values()
        )
        assert total == 128, (
            f"Expected 128 controls, got {total}"
        )

    def test_individual_framework_counts(self):
        checker = ComplianceChecker()
        expected_counts = {
            "AWS-FSBP": 22,
            "CIS-v5.0": 13,
            "PCI-DSS-v4.0.1": 12,
            "HIPAA": 11,
            "SOC2": 14,
            "ISO27001": 13,
            "ISO27017": 8,
            "ISO27018": 6,
            "GDPR": 8,
            "NIST-800-53": 21,
        }
        for fw_id, expected in expected_counts.items():
            actual = len(
                checker.frameworks[fw_id]["controls"]
            )
            assert actual == expected, (
                f"{fw_id}: expected {expected} controls, "
                f"got {actual}"
            )


class TestControlStructure:
    def test_all_controls_have_required_keys(self):
        checker = ComplianceChecker()
        for fw_id, framework in checker.frameworks.items():
            for ctrl_id, control in (
                framework["controls"].items()
            ):
                assert "description" in control, (
                    f"{fw_id}/{ctrl_id} missing description"
                )
                assert "severity" in control, (
                    f"{fw_id}/{ctrl_id} missing severity"
                )
                assert "check" in control, (
                    f"{fw_id}/{ctrl_id} missing check"
                )
                assert callable(control["check"]), (
                    f"{fw_id}/{ctrl_id} check not callable"
                )

    def test_all_severities_valid(self):
        checker = ComplianceChecker()
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for fw_id, framework in checker.frameworks.items():
            for ctrl_id, control in (
                framework["controls"].items()
            ):
                assert control["severity"] in valid, (
                    f"{fw_id}/{ctrl_id} invalid severity: "
                    f"{control['severity']}"
                )


class TestAllPass:
    def test_all_pass_100_percent(self):
        checker = ComplianceChecker()
        results = checker.check_compliance(
            _all_pass_checks()
        )
        for fw_id, fw_result in results.items():
            assert fw_result[
                "compliance_percentage"
            ] == 100.0, (
                f"{fw_id}: expected 100%, got "
                f"{fw_result['compliance_percentage']}% "
                f"(failed: {[c['control_id'] for c in fw_result['failed']]})"
            )

    def test_all_pass_is_compliant(self):
        checker = ComplianceChecker()
        results = checker.check_compliance(
            _all_pass_checks()
        )
        for fw_id, fw_result in results.items():
            assert fw_result["is_compliant"], (
                f"{fw_id} should be compliant"
            )


class TestLambdaExecution:
    def test_all_lambdas_execute_without_error(self):
        """Every lambda must execute without raising."""
        checker = ComplianceChecker()
        checks = _all_pass_checks()
        for fw_id, framework in checker.frameworks.items():
            for ctrl_id, control in (
                framework["controls"].items()
            ):
                result = control["check"](checks)
                assert isinstance(result, bool), (
                    f"{fw_id}/{ctrl_id} returned "
                    f"{type(result)}, expected bool"
                )

    def test_all_lambdas_handle_empty_dict(self):
        """Lambdas should not crash on empty checks."""
        checker = ComplianceChecker()
        for fw_id, framework in checker.frameworks.items():
            for ctrl_id, control in (
                framework["controls"].items()
            ):
                # Should not raise
                try:
                    result = control["check"]({})
                    assert isinstance(result, bool)
                except Exception as e:
                    pytest.fail(
                        f"{fw_id}/{ctrl_id} crashed on "
                        f"empty dict: {e}"
                    )


class TestCheckCompliance:
    def test_result_structure(self):
        checker = ComplianceChecker()
        results = checker.check_compliance(
            _all_pass_checks()
        )
        for fw_id, fw_result in results.items():
            assert "framework_name" in fw_result
            assert "total_controls" in fw_result
            assert "passed_controls" in fw_result
            assert "failed_controls" in fw_result
            assert "compliance_percentage" in fw_result
            assert "is_compliant" in fw_result
            assert "passed" in fw_result
            assert "failed" in fw_result
            assert (
                fw_result["passed_controls"]
                + fw_result["failed_controls"]
                == fw_result["total_controls"]
            )

    def test_root_access_keys_fails_correct_frameworks(self):
        """Root access keys should fail FSBP IAM.4, CIS 1.4,
        PCI 8.2.1, etc."""
        checker = ComplianceChecker()
        checks = _all_pass_checks()
        checks["root_access_keys"]["exists"] = True

        results = checker.check_compliance(checks)

        # FSBP IAM.4 should fail
        fsbp_failed = [
            c["control_id"]
            for c in results["AWS-FSBP"]["failed"]
        ]
        assert "IAM.4" in fsbp_failed

        # CIS 1.4 should fail
        cis_failed = [
            c["control_id"]
            for c in results["CIS-v5.0"]["failed"]
        ]
        assert "1.3" in cis_failed

    def test_password_policy_missing_fails_all_pw_controls(self):
        """Missing password policy should fail all pw-related
        controls."""
        checker = ComplianceChecker()
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

        results = checker.check_compliance(checks)

        # FSBP password controls should all fail
        fsbp_failed = [
            c["control_id"]
            for c in results["AWS-FSBP"]["failed"]
        ]
        for ctrl in (
            "IAM.11", "IAM.12", "IAM.13",
            "IAM.14", "IAM.15", "IAM.16", "IAM.17",
        ):
            assert ctrl in fsbp_failed, (
                f"{ctrl} should fail when no password policy"
            )

    def test_fail_closed_defaults(self):
        """Empty checks should fail most controls
        (fail-closed)."""
        checker = ComplianceChecker()
        results = checker.check_compliance({})

        for fw_id, fw_result in results.items():
            # Most controls should fail on empty dict
            assert fw_result["failed_controls"] > 0, (
                f"{fw_id} should have failures on "
                f"empty checks"
            )


class TestCIS115Compound:
    def test_cis_115_both_pass(self):
        """CIS 1.14 passes only if both A.8 and A.9 pass."""
        checker = ComplianceChecker()
        checks = _all_pass_checks()
        results = checker.check_compliance(checks)
        cis_passed = [
            c["control_id"]
            for c in results["CIS-v5.0"]["passed"]
        ]
        assert "1.14" in cis_passed

    def test_cis_115_a8_fails(self):
        """CIS 1.14 fails if A.8 (direct policies) fails."""
        checker = ComplianceChecker()
        checks = _all_pass_checks()
        checks["direct_attached_policies"]["count"] = 1
        results = checker.check_compliance(checks)
        cis_failed = [
            c["control_id"]
            for c in results["CIS-v5.0"]["failed"]
        ]
        assert "1.14" in cis_failed

    def test_cis_115_a9_fails(self):
        """CIS 1.14 fails if A.9 (inline policies) fails."""
        checker = ComplianceChecker()
        checks = _all_pass_checks()
        checks["inline_user_policies"]["count"] = 1
        results = checker.check_compliance(checks)
        cis_failed = [
            c["control_id"]
            for c in results["CIS-v5.0"]["failed"]
        ]
        assert "1.14" in cis_failed
