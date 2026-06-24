"""Group Security checks (E.1-E.3)."""

import json
import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")


class GroupSecurityChecker(BaseChecker):
    """Checks for IAM group security: admin groups, empty
    groups, and users without group membership."""

    def check_all(
        self,
        groups: List[Dict[str, Any]],
        users: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run all group security checks.

        Args:
            groups: List of IAM group dicts from list_groups()
            users: List of IAM user dicts from list_users()

        Returns:
            Dict with all group security check results
        """
        results = {
            "admin_groups": {"count": 0, "groups": []},
            "empty_groups": {"count": 0, "groups": []},
            "users_not_in_groups": {
                "count": 0, "users": [],
            },
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

        # E.1 - Admin groups & E.2 - Empty groups
        for group in groups:
            group_name = group.get(
                "GroupName", "unknown"
            )

            # E.1 - Check for admin access
            self._check_group_admin(
                iam, group_name, results
            )

            # E.2 - Check if empty
            self._check_group_empty(
                iam, group_name, results
            )

        # E.3 - Users not in any group
        self._check_users_group_membership(
            iam, users, results
        )

        # Update counts
        for key in results:
            list_key = None
            if "groups" in results[key]:
                list_key = "groups"
            elif "users" in results[key]:
                list_key = "users"
            if list_key:
                results[key]["count"] = len(
                    results[key][list_key]
                )

        return results

    def _check_group_admin(
        self,
        iam,
        group_name: str,
        results: Dict[str, Any],
    ) -> None:
        """E.1: Check if group has admin access."""
        try:
            # Check attached managed policies
            paginator = iam.get_paginator(
                "list_attached_group_policies"
            )
            for page in paginator.paginate(
                GroupName=group_name
            ):
                for policy in page.get(
                    "AttachedPolicies", []
                ):
                    arn = policy.get("PolicyArn", "")
                    if arn.endswith(
                        "/AdministratorAccess"
                    ) or arn.endswith("/PowerUserAccess"):
                        results["admin_groups"][
                            "groups"
                        ].append(group_name)
                        return

            # Check inline policies for *:*
            paginator = iam.get_paginator(
                "list_group_policies"
            )
            for page in paginator.paginate(
                GroupName=group_name
            ):
                for policy_name in page.get(
                    "PolicyNames", []
                ):
                    try:
                        doc_resp = iam.get_group_policy(
                            GroupName=group_name,
                            PolicyName=policy_name,
                        )
                        document = doc_resp.get(
                            "PolicyDocument", {}
                        )
                        if isinstance(document, str):
                            document = json.loads(document)

                        if self._has_admin_access(document):
                            results["admin_groups"][
                                "groups"
                            ].append(group_name)
                            return
                    except ClientError:
                        pass

        except ClientError as e:
            logger.debug(
                f"Error checking admin for group "
                f"{group_name}: {e}"
            )
        except Exception as e:
            logger.debug(
                f"Error checking admin for group "
                f"{group_name}: {e}"
            )

    def _check_group_empty(
        self,
        iam,
        group_name: str,
        results: Dict[str, Any],
    ) -> None:
        """E.2: Check if group has no members."""
        try:
            response = iam.get_group(
                GroupName=group_name, MaxItems=1
            )
            users = response.get("Users", [])
            if not users:
                results["empty_groups"]["groups"].append(
                    group_name
                )
        except ClientError as e:
            logger.debug(
                f"Error checking group {group_name}: {e}"
            )
        except Exception as e:
            logger.debug(
                f"Error checking group {group_name}: {e}"
            )

    def _check_users_group_membership(
        self,
        iam,
        users: List[Dict[str, Any]],
        results: Dict[str, Any],
    ) -> None:
        """E.3: Check for users not in any group."""
        for user in users:
            username = user.get("UserName", "unknown")
            try:
                paginator = iam.get_paginator(
                    "list_groups_for_user"
                )
                groups = []
                for page in paginator.paginate(
                    UserName=username
                ):
                    groups.extend(
                        page.get("Groups", [])
                    )
                if not groups:
                    results["users_not_in_groups"][
                        "users"
                    ].append(username)
            except ClientError as e:
                logger.debug(
                    f"Error checking groups for "
                    f"{username}: {e}"
                )
            except Exception as e:
                logger.debug(
                    f"Error checking groups for "
                    f"{username}: {e}"
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
