"""Trust-policy analysis (G.4-G.5).

Design assumption: the scanner runs as a NORMAL member account, not the AWS
Organizations management/delegated-admin account. From a member account there
is no API that resolves another account's Organization (membership is
private), so we deliberately do NOT classify "in-Org vs out-of-Org" - that
would be over-claiming.

Instead:

* Any role that trusts ANOTHER AWS account -> a WARNING to review (we cannot
  verify whether that account is in your Organization).
* The reliably-detectable, actionable defect is a MISSING GUARD: cross-account
  or service trust without ``aws:PrincipalOrgID`` / ``sts:ExternalId`` /
  ``aws:SourceArn`` / ``aws:SourceAccount`` (the confused-deputy problem). This
  needs no Org knowledge - the condition is right there in the policy.

Note: the robust mitigation is for the trust policy itself to carry
``aws:PrincipalOrgID``; AWS then enforces "same Org" at runtime, which is the
only sound way to constrain to an Organization.
"""

import json
import logging
import re
from typing import Any, Dict, List, Set

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")

_ACCOUNT_RE = re.compile(r"arn:aws[a-z-]*:iam::(\d{12}):")


def _accounts_from_principal(principal: Any) -> Set[str]:
    """Extract 12-digit account IDs from an AWS principal block.

    Adds the literal token '*' if a wildcard principal is present.
    """
    out: Set[str] = set()
    if isinstance(principal, str):
        vals = [principal]
    elif isinstance(principal, dict):
        aws = principal.get("AWS", [])
        vals = [aws] if isinstance(aws, str) else list(aws)
    else:
        vals = []
    for v in vals:
        if not isinstance(v, str):
            continue
        if v == "*":
            out.add("*")
        elif v.isdigit() and len(v) == 12:
            out.add(v)
        else:
            m = _ACCOUNT_RE.search(v)
            if m:
                out.add(m.group(1))
    return out


def _condition_keys(condition: Any) -> Set[str]:
    """Lowercased set of all condition keys present in a Condition block."""
    keys: Set[str] = set()
    if isinstance(condition, dict):
        for ops in condition.values():
            if isinstance(ops, dict):
                keys.update(k.lower() for k in ops.keys())
    return keys


def analyze_trust_document(
    trust_doc: Dict, current_account: str
) -> Dict[str, Any]:
    """Classify a role trust policy without any Org knowledge.

    Returns:
        wildcard_principal: bool (Principal "*"/"AWS":"*")
        cross_account: sorted list of external account IDs trusted (WARNING)
        unguarded_external: list of external accounts trusted with NO
            aws:PrincipalOrgID and NO sts:ExternalId guard (HIGH)
        confused_deputy_services: list of service principals trusted with NO
            aws:SourceArn / aws:SourceAccount guard (HIGH)
    """
    res = {
        "wildcard_principal": False,
        "cross_account": set(),
        "unguarded_external": set(),
        "confused_deputy_services": [],
    }
    statements = trust_doc.get("Statement", []) if trust_doc else []
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        ckeys = _condition_keys(stmt.get("Condition", {}))
        has_external_id = "sts:externalid" in ckeys
        has_org_id = "aws:principalorgid" in ckeys
        has_source = (
            "aws:sourcearn" in ckeys or "aws:sourceaccount" in ckeys
        )
        principal = stmt.get("Principal", {})

        # Service principals -> confused deputy if no SourceArn/SourceAccount.
        services = []
        if isinstance(principal, dict):
            svc = principal.get("Service", [])
            services = [svc] if isinstance(svc, str) else list(svc)
        for s in services:
            if not (has_source or has_org_id):
                res["confused_deputy_services"].append(s)

        # AWS account principals.
        for acct in _accounts_from_principal(principal):
            if acct == "*":
                res["wildcard_principal"] = True
            elif acct != current_account:
                res["cross_account"].add(acct)
                if not (has_external_id or has_org_id):
                    res["unguarded_external"].add(acct)

    res["cross_account"] = sorted(res["cross_account"])
    res["unguarded_external"] = sorted(res["unguarded_external"])
    return res


class TrustAnalysisChecker(BaseChecker):
    """Trust analysis: cross-account warning + confused-deputy (G.4-G.5)."""

    def check_all(
        self, roles: List[Dict[str, Any]], account_id: str
    ) -> Dict[str, Any]:
        """Analyze every role trust policy.

        Org membership is NOT resolved (assumes member-account scan); any
        cross-account trust is surfaced as a warning to review.
        """
        results = {
            # G.5 - warning: trusts another account, Org unverifiable.
            "cross_account_trust": {"count": 0, "roles": []},
            # G.4 - high: external/service trust missing confused-deputy guard.
            "unguarded_trust": {"count": 0, "roles": []},
        }

        for role in roles:
            name = role.get("RoleName", "unknown")
            if role.get("Path", "/").startswith("/aws-service-role/"):
                continue
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                try:
                    trust = json.loads(trust)
                except (json.JSONDecodeError, TypeError):
                    continue
            a = analyze_trust_document(trust, account_id)

            if a["cross_account"]:
                results["cross_account_trust"]["roles"].append(
                    {"role": name, "accounts": a["cross_account"],
                     "note": ("cannot verify AWS Org membership from a "
                              "member account - review and constrain with "
                              "aws:PrincipalOrgID")}
                )
            # G.4 is intentionally scoped to CROSS-ACCOUNT unguarded trust
            # only (high confidence). Generic service-principal trust without
            # aws:SourceArn is NOT flagged here: the vast majority of service
            # roles (lambda/ec2/ecs-tasks execution roles, etc.) legitimately
            # do not use SourceArn, so flagging them produces false positives.
            if a["unguarded_external"]:
                results["unguarded_trust"]["roles"].append(
                    {"role": name,
                     "accounts": a["unguarded_external"],
                     "missing": "sts:ExternalId/aws:PrincipalOrgID"}
                )

        for key in ("cross_account_trust", "unguarded_trust"):
            results[key]["count"] = len(results[key]["roles"])
        return results
