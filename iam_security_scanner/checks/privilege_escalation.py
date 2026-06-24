"""Privilege-escalation checks (G.1-G.4).

Detects IAM principals (via customer-managed, inline user, and inline role
policies) whose ALLOWED actions are sufficient to escalate privileges. Based
on the well-documented AWS IAM privilege-escalation paths (Rhino Security
Labs "AWS IAM Privilege Escalation - Methods and Mitigation", and Prowler's
iam_policy_allows_privilege_escalation checks).

A policy is flagged when its effective Allow set is a superset of the actions
required by any escalation method. Wildcards (``*``, ``service:*``) honored.
"""

import json
import logging
from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")

# Each method maps to the set of actions an attacker needs (logical AND).
# If a principal is allowed ALL actions in a method's set, it can escalate.
# Source: Rhino Security Labs (21 methods) + Prowler privesc check.
PRIVESC_METHODS: Dict[str, Set[str]] = {
    # Rewrite any managed policy attached to self.
    "CreatePolicyVersion": {"iam:createpolicyversion"},
    "SetDefaultPolicyVersion": {"iam:setdefaultpolicyversion"},
    # Mint credentials for any user.
    "CreateAccessKey": {"iam:createaccesskey"},
    "CreateLoginProfile": {"iam:createloginprofile"},
    "UpdateLoginProfile": {"iam:updateloginprofile"},
    # Attach an admin managed policy to self / a controlled principal.
    "AttachUserPolicy": {"iam:attachuserpolicy"},
    "AttachGroupPolicy": {"iam:attachgrouppolicy"},
    "AttachRolePolicy": {"iam:attachrolepolicy"},
    # Inject an inline admin policy.
    "PutUserPolicy": {"iam:putuserpolicy"},
    "PutGroupPolicy": {"iam:putgrouppolicy"},
    "PutRolePolicy": {"iam:putrolepolicy"},
    # Join a privileged group.
    "AddUserToGroup": {"iam:addusertogroup"},
    # Rewrite a role's trust policy then assume it.
    "UpdateAssumeRolePolicy": {
        "iam:updateassumerolepolicy",
        "sts:assumerole",
    },
    # PassRole + compute service => run code as the passed role.
    "PassRoleToEC2": {"iam:passrole", "ec2:runinstances"},
    "PassRoleToLambdaCreate": {
        "iam:passrole",
        "lambda:createfunction",
        "lambda:invokefunction",
    },
    "PassRoleToLambdaEventMapping": {
        "iam:passrole",
        "lambda:createfunction",
        "lambda:createeventsourcemapping",
    },
    "PassRoleToCloudFormation": {
        "iam:passrole",
        "cloudformation:createstack",
    },
    "PassRoleToDataPipeline": {
        "iam:passrole",
        "datapipeline:createpipeline",
        "datapipeline:putpipelinedefinition",
    },
    "PassRoleToGlue": {
        "iam:passrole",
        "glue:createdevendpoint",
    },
    "UpdateGlueDevEndpoint": {"glue:updatedevendpoint"},
    "PassRoleToCodeBuild": {
        "iam:passrole",
        "codebuild:createproject",
    },
    "PassRoleToSageMaker": {
        "iam:passrole",
        "sagemaker:createnotebookinstance",
    },
}


def _action_allowed(allowed: Set[str], action: str) -> bool:
    """Whether `action` (lowercase) is granted by an allowed set.

    Honors ``*`` (all), ``service:*`` (whole service), and exact matches.
    """
    if "*" in allowed:
        return True
    if action in allowed:
        return True
    service = action.split(":", 1)[0]
    if f"{service}:*" in allowed:
        return True
    return False


def _allowed_actions_from_document(document: Dict) -> Set[str]:
    """Collect lowercased Action strings from Allow statements.

    NotAction-with-Allow is treated as effectively-all actions ("*") because
    it grants everything except the listed actions (an escalation enabler).
    """
    allowed: Set[str] = set()
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        if "NotAction" in stmt:
            allowed.add("*")
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str):
                allowed.add(a.lower())
    return allowed


def find_privesc_methods(document: Dict) -> List[str]:
    """Return the names of escalation methods a policy document enables."""
    allowed = _allowed_actions_from_document(document)
    if not allowed:
        return []
    hits = []
    for method, required in PRIVESC_METHODS.items():
        if all(_action_allowed(allowed, act) for act in required):
            hits.append(method)
    return hits


def policy_allows_assume_role_star(document: Dict) -> bool:
    """True if the policy allows sts:AssumeRole on Resource '*'.

    Identity-side permissive role assumption: the principal can assume ANY
    role in the account (pivot to higher privilege).
    """
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_l = {a.lower() for a in actions if isinstance(a, str)}
        grants_assume = (
            "sts:assumerole" in actions_l
            or "sts:*" in actions_l
            or "*" in actions_l
        )
        if not grants_assume:
            continue
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in resources or any(
            isinstance(r, str) and r.endswith(":role/*") for r in resources
        ):
            return True
    return False


class PrivilegeEscalationChecker(BaseChecker):
    """Checks for IAM privilege-escalation paths (G.1-G.4)."""

    def check_all(
        self,
        policies: List[Dict[str, Any]],
        users: List[Dict[str, Any]],
        roles: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Scan customer-managed + inline policies for escalation paths.

        Args:
            policies: customer managed policies (list_policies Scope=Local)
            users: IAM users (list_users)
            roles: IAM roles (list_roles)

        Returns:
            Dict with privilege-escalation findings keyed for the scanner.
        """
        results = {
            "privesc_managed_policies": {"count": 0, "findings": []},
            "privesc_inline_policies": {"count": 0, "findings": []},
            "permissive_assume_role": {"count": 0, "findings": []},
        }
        try:
            iam = self.get_client("iam")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not create IAM client: {e}")
            for k in results:
                results[k]["error"] = str(e)
            return results

        self._scan_managed(iam, policies, results)
        self._scan_inline_users(iam, users, results)
        self._scan_inline_roles(iam, roles, results)

        for key in results:
            if "findings" in results[key]:
                results[key]["count"] = len(results[key]["findings"])
        return results

    def _record(self, results, bucket, name, methods, assume_star, document):
        if methods:
            results[bucket]["findings"].append(
                {"name": name, "methods": sorted(methods)}
            )
        if assume_star and policy_allows_assume_role_star(document):
            results["permissive_assume_role"]["findings"].append(
                {"name": name}
            )

    def _scan_managed(self, iam, policies, results):
        for policy in policies:
            name = policy.get("PolicyName", "unknown")
            arn = policy.get("Arn", "")
            version = policy.get("DefaultVersionId", "v1")
            try:
                resp = iam.get_policy_version(
                    PolicyArn=arn, VersionId=version
                )
                doc = resp.get("PolicyVersion", {}).get("Document", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
            except (ClientError, json.JSONDecodeError) as e:
                logger.debug(f"privesc managed {name}: {e}")
                continue
            methods = find_privesc_methods(doc)
            if methods:
                results["privesc_managed_policies"]["findings"].append(
                    {"name": name, "methods": sorted(methods)}
                )
            if policy_allows_assume_role_star(doc):
                results["permissive_assume_role"]["findings"].append(
                    {"name": f"policy:{name}"}
                )

    def _scan_inline_users(self, iam, users, results):
        for user in users:
            uname = user.get("UserName", "unknown")
            try:
                names = iam.list_user_policies(UserName=uname).get(
                    "PolicyNames", []
                )
                for pn in names:
                    doc = iam.get_user_policy(
                        UserName=uname, PolicyName=pn
                    ).get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    self._record_inline(
                        results, f"user:{uname}/{pn}", doc
                    )
            except (ClientError, json.JSONDecodeError) as e:
                logger.debug(f"privesc inline user {uname}: {e}")

    def _scan_inline_roles(self, iam, roles, results):
        for role in roles:
            rname = role.get("RoleName", "unknown")
            if role.get("Path", "/").startswith("/aws-service-role/"):
                continue
            try:
                names = iam.list_role_policies(RoleName=rname).get(
                    "PolicyNames", []
                )
                for pn in names:
                    doc = iam.get_role_policy(
                        RoleName=rname, PolicyName=pn
                    ).get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    self._record_inline(
                        results, f"role:{rname}/{pn}", doc
                    )
            except (ClientError, json.JSONDecodeError) as e:
                logger.debug(f"privesc inline role {rname}: {e}")

    def _record_inline(self, results, name, doc):
        methods = find_privesc_methods(doc)
        if methods:
            results["privesc_inline_policies"]["findings"].append(
                {"name": name, "methods": sorted(methods)}
            )
        if policy_allows_assume_role_star(doc):
            results["permissive_assume_role"]["findings"].append(
                {"name": name}
            )
