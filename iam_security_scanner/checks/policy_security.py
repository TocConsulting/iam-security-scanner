"""Policy Security checks (C.1-C.5)."""

import json
import logging
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")


class PolicySecurityChecker(BaseChecker):
    """Checks for customer managed IAM policy security."""

    def check_all(
        self, policies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run all policy security checks.

        Args:
            policies: List of customer managed policy dicts
                from list_policies(Scope='Local')

        Returns:
            Dict with all policy security check results
        """
        results = {
            "admin_policies": {
                "count": 0, "policies": [],
            },
            "wildcard_service_policies": {
                "count": 0, "policies": [],
            },
            "passrole_star_policies": {
                "count": 0, "policies": [],
            },
            "notaction_policies": {
                "count": 0, "policies": [],
            },
            "unused_policies": {
                "count": 0, "policies": [],
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

        for policy in policies:
            policy_name = policy.get("PolicyName", "unknown")
            policy_arn = policy.get("Arn", "")
            default_version = policy.get(
                "DefaultVersionId", "v1"
            )
            attachment_count = policy.get(
                "AttachmentCount", 0
            )

            # C.5 - Unused policies
            if attachment_count == 0:
                results["unused_policies"]["policies"].append(
                    policy_name
                )

            # Get policy document for C.1-C.4
            try:
                doc_response = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version,
                )
                document = doc_response.get(
                    "PolicyVersion", {}
                ).get("Document", {})

                # Document may be URL-encoded JSON string
                if isinstance(document, str):
                    document = json.loads(document)

                statements = document.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                self._analyze_statements(
                    statements, policy_name, results
                )

            except ClientError as e:
                logger.debug(
                    f"Could not get policy version for "
                    f"{policy_name}: {e}"
                )
            except Exception as e:
                logger.debug(
                    f"Error analyzing policy "
                    f"{policy_name}: {e}"
                )

        # Update counts
        for key in results:
            list_key = (
                "policies"
                if "policies" in results[key]
                else None
            )
            if list_key:
                results[key]["count"] = len(
                    results[key][list_key]
                )

        return results

    def _analyze_statements(
        self,
        statements: List[Dict],
        policy_name: str,
        results: Dict[str, Any],
    ) -> None:
        """Analyze policy statements for C.1-C.4 issues."""
        for stmt in statements:
            effect = stmt.get("Effect", "")
            if effect != "Allow":
                continue

            # C.4 - NotAction check
            if "NotAction" in stmt:
                if policy_name not in (
                    results["notaction_policies"]["policies"]
                ):
                    results["notaction_policies"][
                        "policies"
                    ].append(policy_name)
                continue  # NotAction stmts are a separate concern

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_star_resource = "*" in resources

            for action in actions:
                # C.1 - Full admin (*:*)
                if action == "*" and has_star_resource:
                    if policy_name not in (
                        results["admin_policies"]["policies"]
                    ):
                        results["admin_policies"][
                            "policies"
                        ].append(policy_name)

                # C.2 - Wildcard service actions (e.g., "s3:*")
                # Only exact "service:*", not "ec2:Describe*"
                elif (
                    ":" in action
                    and action.endswith(":*")
                    and action != "*"
                ):
                    service_action = action.split(":")[1]
                    if service_action == "*":
                        if policy_name not in (
                            results[
                                "wildcard_service_policies"
                            ]["policies"]
                        ):
                            results[
                                "wildcard_service_policies"
                            ]["policies"].append(policy_name)

                # C.3 - PassRole with star resource
                if has_star_resource and (
                    action.lower() == "iam:passrole"
                    or action == "iam:*"
                    or action == "*"
                ):
                    # Only flag PassRole * specifically
                    # (admin * is already C.1)
                    if action.lower() == "iam:passrole" or (
                        action == "iam:*"
                    ):
                        if policy_name not in (
                            results["passrole_star_policies"][
                                "policies"
                            ]
                        ):
                            results[
                                "passrole_star_policies"
                            ]["policies"].append(policy_name)
