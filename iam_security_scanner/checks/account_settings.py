"""Account Settings checks (F.1-F.6)."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")

CLOUDSHELL_POLICY_ARN = (
    "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
)


class AccountSettingsChecker(BaseChecker):
    """Checks for account-level IAM settings: Access Analyzer,
    support role, certificates, CloudShell access."""

    def check_all(
        self, roles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run all account settings checks.

        Args:
            roles: List of IAM role dicts (reused from D checks)

        Returns:
            Dict with all account settings check results
        """
        results = {}

        # F.1 - Access Analyzer
        results["access_analyzer"] = (
            self._check_access_analyzer()
        )

        # F.6 - Access Analyzer findings
        results["access_analyzer_findings"] = (
            self._check_access_analyzer_findings(
                results["access_analyzer"]
            )
        )

        # F.2 - Support role
        results["support_role"] = (
            self._check_support_role(roles)
        )

        # F.3 - Expired certificates
        results["expired_certificates"] = (
            self._check_expired_certificates()
        )

        # F.4 - CloudShell full access
        results["cloudshell_full_access"] = (
            self._check_cloudshell_access()
        )

        # F.5 - IAM server certificates (legacy)
        results["iam_server_certificates"] = (
            self._check_iam_certificates()
        )

        # F.7 - Access Analyzer unused-access analyzer (2024 feature)
        results["unused_access_analyzer"] = (
            self._check_unused_access_analyzer()
        )

        return results

    def _check_unused_access_analyzer(self) -> Dict[str, Any]:
        """F.7: Check for an IAM Access Analyzer unused-access analyzer.

        Distinct from F.1 (external-access). Unused-access analyzers
        (GA 2024) surface unused roles, permissions, and access keys for
        least-privilege right-sizing.
        """
        try:
            client = self.get_client("accessanalyzer")
            paginator = client.get_paginator("list_analyzers")
            unused = []
            for page in paginator.paginate():
                for analyzer in page.get("analyzers", []):
                    a_type = analyzer.get("type", "")
                    if (
                        "UNUSED_ACCESS" in a_type
                        and analyzer.get("status") == "ACTIVE"
                    ):
                        unused.append(analyzer.get("name", ""))
            return {
                "enabled": len(unused) > 0,
                "analyzers": unused,
            }
        except ClientError as e:
            return self.handle_client_error(
                e, {"enabled": False, "analyzers": []},
            )
        except Exception as e:
            logger.warning(
                f"Unused-access analyzer check failed: {e}"
            )
            return {
                "enabled": False,
                "analyzers": [],
                "error": str(e),
            }

    def _check_access_analyzer(self) -> Dict[str, Any]:
        """F.1: Check if IAM Access Analyzer is enabled."""
        try:
            client = self.get_client("accessanalyzer")
            paginator = client.get_paginator(
                "list_analyzers"
            )
            analyzers = []
            for page in paginator.paginate():
                for analyzer in page.get("analyzers", []):
                    if analyzer.get("status") == "ACTIVE":
                        analyzers.append(
                            analyzer.get("name", "")
                        )

            return {
                "enabled": len(analyzers) > 0,
                "analyzers": analyzers,
            }
        except ClientError as e:
            return self.handle_client_error(
                e,
                {"enabled": False, "analyzers": []},
            )
        except Exception as e:
            logger.warning(
                f"Access Analyzer check failed: {e}"
            )
            return {
                "enabled": False,
                "analyzers": [],
                "error": str(e),
            }

    def _check_access_analyzer_findings(
        self, analyzer_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """F.6: Check for active Access Analyzer findings."""
        if not analyzer_result.get("enabled", False):
            # No analyzer - F.1 handles this separately
            return {"count": 0, "findings": []}

        analyzers = analyzer_result.get("analyzers", [])
        if not analyzers:
            return {"count": 0, "findings": []}

        try:
            client = self.get_client("accessanalyzer")

            # Get the ARN of the first active analyzer
            paginator = client.get_paginator(
                "list_analyzers"
            )
            analyzer_arn = None
            for page in paginator.paginate():
                for analyzer in page.get("analyzers", []):
                    if analyzer.get("status") == "ACTIVE":
                        analyzer_arn = analyzer.get("arn")
                        break
                if analyzer_arn:
                    break

            if not analyzer_arn:
                return {"count": 0, "findings": []}

            # List active findings - list_findings_v2 supports
            # all analyzer types (external, unused-access,
            # internal-access). list_findings only works for
            # external analyzers.
            findings_paginator = client.get_paginator(
                "list_findings_v2"
            )
            active_findings = []
            for page in findings_paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={
                    "status": {"eq": ["ACTIVE"]},
                },
            ):
                for finding in page.get(
                    "findings", []
                ):
                    finding_id = finding.get("id", "")
                    resource = finding.get(
                        "resource", ""
                    )
                    active_findings.append(
                        f"{finding_id}:{resource}"
                    )

            return {
                "count": len(active_findings),
                "findings": active_findings,
            }

        except ClientError as e:
            return self.handle_client_error(
                e, {"count": 0, "findings": []},
            )
        except Exception as e:
            logger.warning(
                f"Access Analyzer findings check "
                f"failed: {e}"
            )
            return {
                "count": 0,
                "findings": [],
                "error": str(e),
            }

    def _check_support_role(
        self, roles: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """F.2: Check if a support role exists."""
        try:
            iam = self.get_client("iam")
            for role in roles:
                role_name = role.get("RoleName", "")
                try:
                    paginator = iam.get_paginator(
                        "list_attached_role_policies"
                    )
                    for page in paginator.paginate(
                        RoleName=role_name
                    ):
                        for policy in page.get(
                            "AttachedPolicies", []
                        ):
                            arn = policy.get(
                                "PolicyArn", ""
                            )
                            if arn.endswith(
                                "/AWSSupportAccess"
                            ):
                                return {"exists": True}
                except ClientError:
                    continue

            return {"exists": False}

        except Exception as e:
            logger.warning(
                f"Support role check failed: {e}"
            )
            return {"exists": False, "error": str(e)}

    def _check_expired_certificates(
        self,
    ) -> Dict[str, Any]:
        """F.3: Check for expired SSL/TLS certificates."""
        try:
            iam = self.get_client("iam")
            paginator = iam.get_paginator(
                "list_server_certificates"
            )
            expired = []
            now = datetime.now(timezone.utc)

            for page in paginator.paginate():
                for cert in page.get(
                    "ServerCertificateMetadataList", []
                ):
                    cert_name = cert.get(
                        "ServerCertificateName", ""
                    )
                    expiration = cert.get("Expiration")
                    if expiration:
                        if hasattr(expiration, "tzinfo"):
                            if expiration < now:
                                expired.append(cert_name)
                        else:
                            try:
                                exp_dt = (
                                    datetime.fromisoformat(
                                        str(
                                            expiration
                                        ).replace(
                                            "Z", "+00:00"
                                        )
                                    )
                                )
                                if exp_dt < now:
                                    expired.append(
                                        cert_name
                                    )
                            except (
                                ValueError,
                                TypeError,
                            ):
                                pass

            return {
                "count": len(expired),
                "certificates": expired,
            }

        except ClientError as e:
            return self.handle_client_error(
                e,
                {"count": 0, "certificates": []},
            )
        except Exception as e:
            logger.warning(
                f"Certificate check failed: {e}"
            )
            return {
                "count": 0,
                "certificates": [],
                "error": str(e),
            }

    def _check_cloudshell_access(self) -> Dict[str, Any]:
        """F.4: Check for entities with CloudShell full access."""
        try:
            iam = self.get_client("iam")
            identities = []

            try:
                paginator = iam.get_paginator(
                    "list_entities_for_policy"
                )
                for page in paginator.paginate(
                    PolicyArn=CLOUDSHELL_POLICY_ARN
                ):
                    for user in page.get(
                        "PolicyUsers", []
                    ):
                        identities.append(
                            f"user:{user.get('UserName', '')}"
                        )
                    for role in page.get(
                        "PolicyRoles", []
                    ):
                        identities.append(
                            f"role:{role.get('RoleName', '')}"
                        )
                    for group in page.get(
                        "PolicyGroups", []
                    ):
                        identities.append(
                            f"group:{group.get('GroupName', '')}"
                        )
            except ClientError as e:
                code = e.response.get("Error", {}).get(
                    "Code", ""
                )
                if code == "NoSuchEntity":
                    # Policy doesn't exist in this account
                    return {
                        "count": 0,
                        "identities": [],
                    }
                raise

            return {
                "count": len(identities),
                "identities": identities,
            }

        except ClientError as e:
            return self.handle_client_error(
                e,
                {"count": 0, "identities": []},
            )
        except Exception as e:
            logger.warning(
                f"CloudShell check failed: {e}"
            )
            return {
                "count": 0,
                "identities": [],
                "error": str(e),
            }

    def _check_iam_certificates(self) -> Dict[str, Any]:
        """F.5: Check for any IAM-managed certificates."""
        try:
            iam = self.get_client("iam")
            paginator = iam.get_paginator(
                "list_server_certificates"
            )
            certs = []

            for page in paginator.paginate():
                for cert in page.get(
                    "ServerCertificateMetadataList", []
                ):
                    certs.append(
                        cert.get(
                            "ServerCertificateName", ""
                        )
                    )

            return {
                "count": len(certs),
                "certificates": certs,
            }

        except ClientError as e:
            return self.handle_client_error(
                e,
                {"count": 0, "certificates": []},
            )
        except Exception as e:
            logger.warning(
                f"IAM certificate check failed: {e}"
            )
            return {
                "count": 0,
                "certificates": [],
                "error": str(e),
            }
