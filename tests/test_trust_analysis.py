"""Tests for Org-agnostic trust analysis (G.4-G.5)."""

from iam_security_scanner.checks.trust_analysis import (
    analyze_trust_document,
)

SELF = "111111111111"


def _trust(principal, condition=None):
    stmt = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "sts:AssumeRole",
    }
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


class TestCrossAccount:
    def test_external_account_is_cross_account_and_unguarded(self):
        r = analyze_trust_document(
            _trust({"AWS": "arn:aws:iam::999999999999:root"}), SELF
        )
        assert r["cross_account"] == ["999999999999"]
        assert r["unguarded_external"] == ["999999999999"]

    def test_principal_org_id_clears_unguarded(self):
        r = analyze_trust_document(
            _trust(
                {"AWS": "arn:aws:iam::999999999999:root"},
                {"StringEquals": {"aws:PrincipalOrgID": "o-x"}},
            ),
            SELF,
        )
        assert r["cross_account"] == ["999999999999"]
        assert r["unguarded_external"] == []

    def test_external_id_clears_unguarded(self):
        r = analyze_trust_document(
            _trust(
                {"AWS": "arn:aws:iam::999999999999:root"},
                {"StringEquals": {"sts:ExternalId": "x"}},
            ),
            SELF,
        )
        assert r["unguarded_external"] == []

    def test_same_account_ignored(self):
        r = analyze_trust_document(
            _trust({"AWS": "arn:aws:iam::111111111111:root"}), SELF
        )
        assert r["cross_account"] == []
        assert r["unguarded_external"] == []

    def test_bare_account_id_principal(self):
        r = analyze_trust_document(
            _trust({"AWS": "999999999999"}), SELF
        )
        assert r["cross_account"] == ["999999999999"]


class TestWildcardAndService:
    def test_wildcard_principal(self):
        r = analyze_trust_document(_trust({"AWS": "*"}), SELF)
        assert r["wildcard_principal"] is True

    def test_service_principal_detected(self):
        # service confused-deputy is computed but not emitted as a finding;
        # it is still surfaced in the analysis dict.
        r = analyze_trust_document(
            _trust({"Service": "cloudtrail.amazonaws.com"}), SELF
        )
        assert "cloudtrail.amazonaws.com" in r["confused_deputy_services"]

    def test_service_with_source_arn_clean(self):
        r = analyze_trust_document(
            _trust(
                {"Service": "cloudtrail.amazonaws.com"},
                {"ArnLike": {"aws:SourceArn": "arn:aws:..."}},
            ),
            SELF,
        )
        assert r["confused_deputy_services"] == []
