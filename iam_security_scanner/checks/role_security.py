"""Role Security checks (D.1-D.5)."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")


class RoleSecurityChecker(BaseChecker):
    """Checks for IAM role security: admin access, trust
    policies, cross-account, and unused roles."""

    def check_all(
        self,
        roles: List[Dict[str, Any]],
        account_id: str,
    ) -> Dict[str, Any]:
        """Run all role security checks.

        Args:
            roles: List of IAM role dicts from list_roles()
            account_id: Current AWS account ID

        Returns:
            Dict with all role security check results
        """
        results = {
            "admin_roles": {"count": 0, "roles": []},
            "wildcard_principal_roles": {
                "count": 0, "roles": [],
            },
            "cross_account_roles": {
                "count": 0, "roles": [],
            },
            "overprivileged_roles": {
                "count": 0, "roles": [],
            },
            "unused_roles": {"count": 0, "roles": []},
        }

        try:
            iam = self.get_client("iam")
        except Exception as e:
            logger.warning(
                f"Could not create IAM client: {e}"
            )
            for key in results:
                results[key]["error"] = str(e)
            return results

        for role in roles:
            role_name = role.get("RoleName", "unknown")
            role_path = role.get("Path", "/")

            # Skip service-linked roles
            if role_path.startswith("/aws-service-role/"):
                continue

            # D.2 - Wildcard principal
            trust_doc = role.get(
                "AssumeRolePolicyDocument", {}
            )
            if isinstance(trust_doc, str):
                try:
                    trust_doc = json.loads(trust_doc)
                except (json.JSONDecodeError, TypeError):
                    trust_doc = {}

            self._check_trust_policy(
                trust_doc, role_name, account_id, results
            )

            # D.1 - Admin access
            self._check_role_admin(
                iam, role_name, results
            )

            # D.4 - Overly permissive inline policies
            self._check_role_inline_permissions(
                iam, role_name, results
            )

            # D.5 - Unused roles
            self._check_role_usage(role, results)

        # Update counts
        for key in results:
            if "roles" in results[key]:
                results[key]["count"] = len(
                    results[key]["roles"]
                )

        return results

    def _check_trust_policy(
        self,
        trust_doc: Dict,
        role_name: str,
        account_id: str,
        results: Dict[str, Any],
    ) -> None:
        """D.2 & D.3: Check trust policy for wildcard
        principals and cross-account access."""
        statements = trust_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            condition = stmt.get("Condition", {})

            # Normalize principal
            if isinstance(principal, str):
                principals = [principal]
            elif isinstance(principal, dict):
                principals = []
                for val in principal.values():
                    if isinstance(val, str):
                        principals.append(val)
                    elif isinstance(val, list):
                        principals.extend(val)
            else:
                principals = []

            for p in principals:
                # D.2 - Wildcard principal
                if p == "*":
                    # Check if conditions restrict it
                    if not condition:
                        if role_name not in (
                            results[
                                "wildcard_principal_roles"
                            ]["roles"]
                        ):
                            results[
                                "wildcard_principal_roles"
                            ]["roles"].append(role_name)

                # D.3 - Cross-account
                elif p.startswith("arn:aws:iam::"):
                    parts = p.split(":")
                    if len(parts) >= 5:
                        ext_account = parts[4]
                        if (
                            ext_account
                            and ext_account != account_id
                        ):
                            if role_name not in (
                                results[
                                    "cross_account_roles"
                                ]["roles"]
                            ):
                                results[
                                    "cross_account_roles"
                                ]["roles"].append(role_name)

    def _check_role_admin(
        self,
        iam,
        role_name: str,
        results: Dict[str, Any],
    ) -> None:
        """D.1: Check if role has admin access."""
        try:
            # Check attached managed policies
            paginator = iam.get_paginator(
                "list_attached_role_policies"
            )
            for page in paginator.paginate(
                RoleName=role_name
            ):
                for policy in page.get(
                    "AttachedPolicies", []
                ):
                    arn = policy.get("PolicyArn", "")
                    if arn.endswith(
                        "/AdministratorAccess"
                    ) or arn.endswith("/PowerUserAccess"):
                        if role_name not in (
                            results["admin_roles"]["roles"]
                        ):
                            results["admin_roles"][
                                "roles"
                            ].append(role_name)
                            return

            # Check inline policies for *:*
            paginator = iam.get_paginator(
                "list_role_policies"
            )
            for page in paginator.paginate(
                RoleName=role_name
            ):
                for policy_name in page.get(
                    "PolicyNames", []
                ):
                    try:
                        doc_resp = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                        )
                        document = doc_resp.get(
                            "PolicyDocument", {}
                        )
                        if isinstance(document, str):
                            document = json.loads(document)

                        if self._has_admin_access(document):
                            if role_name not in (
                                results["admin_roles"][
                                    "roles"
                                ]
                            ):
                                results["admin_roles"][
                                    "roles"
                                ].append(role_name)
                                return
                    except ClientError:
                        pass

        except ClientError as e:
            logger.debug(
                f"Error checking admin for {role_name}: {e}"
            )
        except Exception as e:
            logger.debug(
                f"Error checking admin for {role_name}: {e}"
            )

    def _check_role_inline_permissions(
        self,
        iam,
        role_name: str,
        results: Dict[str, Any],
    ) -> None:
        """D.4: Check for overly permissive inline policies."""
        try:
            paginator = iam.get_paginator(
                "list_role_policies"
            )
            for page in paginator.paginate(
                RoleName=role_name
            ):
                for policy_name in page.get(
                    "PolicyNames", []
                ):
                    try:
                        doc_resp = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                        )
                        document = doc_resp.get(
                            "PolicyDocument", {}
                        )
                        if isinstance(document, str):
                            document = json.loads(document)

                        if self._has_wildcard_permissions(
                            document
                        ):
                            if role_name not in (
                                results[
                                    "overprivileged_roles"
                                ]["roles"]
                            ):
                                results[
                                    "overprivileged_roles"
                                ]["roles"].append(role_name)
                                return
                    except ClientError:
                        pass

        except ClientError as e:
            logger.debug(
                f"Error checking inline for "
                f"{role_name}: {e}"
            )
        except Exception as e:
            logger.debug(
                f"Error checking inline for "
                f"{role_name}: {e}"
            )

    def _check_role_usage(
        self,
        role: Dict[str, Any],
        results: Dict[str, Any],
    ) -> None:
        """D.5: Check if role is unused (90+ days)."""
        role_name = role.get("RoleName", "unknown")
        now = datetime.now(timezone.utc)

        last_used_info = role.get("RoleLastUsed", {})
        last_used_date = last_used_info.get("LastUsedDate")

        if last_used_date:
            if hasattr(last_used_date, "tzinfo"):
                days_ago = (now - last_used_date).days
            else:
                try:
                    dt = datetime.fromisoformat(
                        str(last_used_date).replace(
                            "Z", "+00:00"
                        )
                    )
                    days_ago = (now - dt).days
                except (ValueError, TypeError):
                    days_ago = 999
        else:
            # Never used - check create date
            create_date = role.get("CreateDate")
            if create_date and hasattr(
                create_date, "tzinfo"
            ):
                days_ago = (now - create_date).days
            else:
                days_ago = 999

        if days_ago > 90:
            if role_name not in (
                results["unused_roles"]["roles"]
            ):
                results["unused_roles"]["roles"].append(
                    role_name
                )

    def _has_admin_access(
        self, document: Dict
    ) -> bool:
        """Check if policy document grants *:* admin."""
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                return True
        return False

    def _has_wildcard_permissions(
        self, document: Dict
    ) -> bool:
        """Check if policy has wildcard actions or resources."""
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in resources:
                for action in actions:
                    if action == "*":
                        return True
                    if (
                        ":" in action
                        and action.endswith(":*")
                    ):
                        service_part = action.split(":")[1]
                        if service_part == "*":
                            return True
        return False
