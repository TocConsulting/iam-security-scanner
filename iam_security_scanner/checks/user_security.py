"""User Security checks (A.1-A.11)."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")


class UserSecurityChecker(BaseChecker):
    """Checks for IAM user security: root account, MFA, access
    keys, credential hygiene, and direct policy attachments."""

    def check_all(
        self,
        credential_report: List[Dict[str, str]],
        users: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run all user security checks.

        Args:
            credential_report: Parsed credential report rows
            users: List of IAM user dicts from list_users()

        Returns:
            Dict with all user security check results
        """
        results = {}

        # Separate root from regular users
        root_row = None
        user_rows = []
        for row in credential_report:
            if row.get("user") == "<root_account>":
                root_row = row
            else:
                user_rows.append(row)

        # A.1 - Root access keys
        results["root_access_keys"] = (
            self._check_root_access_keys(root_row)
        )

        # A.2 + A.3 - Root MFA (hardware enrichment folded in)
        root_mfa_base = self._check_root_mfa(root_row)
        results["root_mfa"] = self._check_root_hardware_mfa(
            root_mfa_base
        )

        # A.4 - All users MFA
        results["users_without_mfa"] = (
            self._check_users_mfa(user_rows)
        )

        # A.5 - Access key rotation
        results["old_access_keys"] = (
            self._check_key_rotation(user_rows)
        )

        # A.6 - Unused credentials
        results["unused_credentials"] = (
            self._check_unused_credentials(user_rows)
        )

        # A.7 - Multiple active keys
        results["multiple_access_keys"] = (
            self._check_multiple_keys(user_rows)
        )

        # A.8 - Direct attached policies
        results["direct_attached_policies"] = (
            self._check_direct_policies(users)
        )

        # A.9 - Inline user policies
        results["inline_user_policies"] = (
            self._check_inline_policies(users)
        )

        # A.10 - Console access without MFA
        results["console_no_mfa"] = (
            self._check_console_no_mfa(user_rows)
        )

        # A.11 - Root account usage
        results["root_usage"] = (
            self._check_root_usage(root_row)
        )

        # A.12 - Users with AWS-managed AdministratorAccess attached
        results["admin_users"] = (
            self._check_admin_users(users)
        )

        return results

    def _check_admin_users(
        self, users: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """A.12: Users with AdministratorAccess attached directly.

        Flags the AWS-managed AdministratorAccess policy attached straight
        to a user (vs A.8 which flags any directly-attached policy). Admin
        on a user is a far higher risk than a scoped policy.
        """
        flagged = []
        admin_arn = (
            "arn:aws:iam::aws:policy/AdministratorAccess"
        )
        try:
            iam = self.get_client("iam")
            for user in users:
                username = user.get("UserName", "unknown")
                try:
                    paginator = iam.get_paginator(
                        "list_attached_user_policies"
                    )
                    for page in paginator.paginate(
                        UserName=username
                    ):
                        for p in page.get(
                            "AttachedPolicies", []
                        ):
                            if p.get("PolicyArn") == admin_arn:
                                flagged.append(username)
                                break
                except ClientError as e:
                    logger.debug(
                        f"admin-user check {username}: {e}"
                    )
        except Exception as e:
            logger.warning(
                f"Admin-user check failed: {e}"
            )
            return {"count": 0, "users": [], "error": str(e)}

        return {"count": len(flagged), "users": flagged}

    def _check_root_access_keys(
        self, root_row: Dict[str, str]
    ) -> Dict[str, Any]:
        """A.1: Check if root has active access keys."""
        if root_row is None:
            return {"exists": True}  # Fail-closed

        key1 = root_row.get(
            "access_key_1_active", "true"
        ).lower() == "true"
        key2 = root_row.get(
            "access_key_2_active", "true"
        ).lower() == "true"

        return {"exists": key1 or key2}

    def _check_root_mfa(
        self, root_row: Dict[str, str]
    ) -> Dict[str, Any]:
        """A.2: Check if root has MFA enabled."""
        if root_row is None:
            return {
                "enabled": False,
                "hardware": False,
            }  # Fail-closed

        enabled = root_row.get(
            "mfa_active", "false"
        ).lower() == "true"

        return {"enabled": enabled, "hardware": False}

    def _check_root_hardware_mfa(
        self, root_mfa_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """A.3: Check if root MFA is hardware (not virtual).

        Updates the root_mfa result dict with hardware status.
        """
        if not root_mfa_result.get("enabled", False):
            # No MFA at all - hardware check not applicable
            return root_mfa_result

        try:
            iam = self.get_client("iam")
            paginator = iam.get_paginator(
                "list_virtual_mfa_devices"
            )
            virtual_serials = []
            for page in paginator.paginate():
                for device in page.get(
                    "VirtualMFADevices", []
                ):
                    serial = device.get(
                        "SerialNumber", ""
                    )
                    virtual_serials.append(serial)

            # Root virtual MFA serial contains
            # "mfa/root-account-mfa-device"
            is_virtual = any(
                "root-account-mfa-device" in s
                for s in virtual_serials
            )

            root_mfa_result["hardware"] = not is_virtual
            return root_mfa_result

        except Exception as e:
            logger.warning(
                f"Could not check root hardware MFA: {e}"
            )
            root_mfa_result["hardware"] = False
            return root_mfa_result

    def _check_users_mfa(
        self, user_rows: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """A.4: Check all users have MFA enabled."""
        users_without = []
        for row in user_rows:
            if row.get("mfa_active", "false").lower() != "true":
                users_without.append(row.get("user", "unknown"))

        return {
            "count": len(users_without),
            "users": users_without,
        }

    def _check_key_rotation(
        self, user_rows: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """A.5: Check access keys are rotated within 90 days."""
        old_keys = []
        now = datetime.now(timezone.utc)

        for row in user_rows:
            username = row.get("user", "unknown")
            for key_num in ("1", "2"):
                active = row.get(
                    f"access_key_{key_num}_active", "false"
                ).lower()
                if active != "true":
                    continue

                rotated = row.get(
                    f"access_key_{key_num}_last_rotated", "N/A"
                )
                if rotated in ("N/A", "not_supported"):
                    continue

                try:
                    rotated_dt = datetime.fromisoformat(
                        rotated.replace("Z", "+00:00")
                    )
                    age_days = (now - rotated_dt).days
                    if age_days > 90:
                        if username not in old_keys:
                            old_keys.append(username)
                except (ValueError, TypeError):
                    # Can't parse date - flag it
                    if username not in old_keys:
                        old_keys.append(username)

        return {"count": len(old_keys), "users": old_keys}

    def _check_unused_credentials(
        self, user_rows: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """A.6: Check for credentials unused for 45+ days."""
        unused = []
        now = datetime.now(timezone.utc)
        threshold_days = 45

        for row in user_rows:
            username = row.get("user", "unknown")
            is_unused = False

            # Check password
            pwd_enabled = row.get(
                "password_enabled", "false"
            ).lower() == "true"
            if pwd_enabled:
                pwd_last = row.get(
                    "password_last_used", "no_information"
                )
                if pwd_last in ("no_information", "N/A"):
                    # Never used - check create date
                    created = row.get("user_creation_time", "")
                    if created:
                        try:
                            created_dt = datetime.fromisoformat(
                                created.replace("Z", "+00:00")
                            )
                            if (now - created_dt).days >= threshold_days:
                                is_unused = True
                        except (ValueError, TypeError):
                            pass
                elif pwd_last != "not_supported":
                    try:
                        pwd_dt = datetime.fromisoformat(
                            pwd_last.replace("Z", "+00:00")
                        )
                        if (now - pwd_dt).days >= threshold_days:
                            is_unused = True
                    except (ValueError, TypeError):
                        pass

            # Check access keys
            for key_num in ("1", "2"):
                active = row.get(
                    f"access_key_{key_num}_active", "false"
                ).lower()
                if active != "true":
                    continue

                last_used = row.get(
                    f"access_key_{key_num}_last_used_date",
                    "N/A",
                )
                if last_used in ("N/A", "no_information"):
                    rotated = row.get(
                        f"access_key_{key_num}_last_rotated",
                        "N/A",
                    )
                    if rotated not in ("N/A", "not_supported"):
                        try:
                            rot_dt = datetime.fromisoformat(
                                rotated.replace("Z", "+00:00")
                            )
                            if (now - rot_dt).days >= threshold_days:
                                is_unused = True
                        except (ValueError, TypeError):
                            pass
                elif last_used != "not_supported":
                    try:
                        used_dt = datetime.fromisoformat(
                            last_used.replace("Z", "+00:00")
                        )
                        if (now - used_dt).days >= threshold_days:
                            is_unused = True
                    except (ValueError, TypeError):
                        pass

            if is_unused and username not in unused:
                unused.append(username)

        return {"count": len(unused), "users": unused}

    def _check_multiple_keys(
        self, user_rows: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """A.7: Check for users with multiple active access keys."""
        multi = []
        for row in user_rows:
            key1 = row.get(
                "access_key_1_active", "false"
            ).lower() == "true"
            key2 = row.get(
                "access_key_2_active", "false"
            ).lower() == "true"
            if key1 and key2:
                multi.append(row.get("user", "unknown"))

        return {"count": len(multi), "users": multi}

    def _check_direct_policies(
        self, users: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """A.8: Check for users with directly attached policies."""
        flagged = []
        try:
            iam = self.get_client("iam")
            for user in users:
                username = user["UserName"]
                try:
                    paginator = iam.get_paginator(
                        "list_attached_user_policies"
                    )
                    policies = []
                    for page in paginator.paginate(
                        UserName=username
                    ):
                        policies.extend(
                            page.get(
                                "AttachedPolicies", []
                            )
                        )
                    if policies:
                        flagged.append(username)
                except ClientError as e:
                    logger.debug(
                        f"Error checking policies for "
                        f"{username}: {e}"
                    )
        except Exception as e:
            logger.warning(
                f"Direct policy check failed: {e}"
            )
            return {"count": 0, "users": [], "error": str(e)}

        return {"count": len(flagged), "users": flagged}

    def _check_inline_policies(
        self, users: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """A.9: Check for users with inline policies."""
        flagged = []
        try:
            iam = self.get_client("iam")
            for user in users:
                username = user["UserName"]
                try:
                    paginator = iam.get_paginator(
                        "list_user_policies"
                    )
                    policy_names = []
                    for page in paginator.paginate(
                        UserName=username
                    ):
                        policy_names.extend(
                            page.get("PolicyNames", [])
                        )
                    if policy_names:
                        flagged.append(username)
                except ClientError as e:
                    logger.debug(
                        f"Error checking inline policies "
                        f"for {username}: {e}"
                    )
        except Exception as e:
            logger.warning(
                f"Inline policy check failed: {e}"
            )
            return {"count": 0, "users": [], "error": str(e)}

        return {"count": len(flagged), "users": flagged}

    def _check_console_no_mfa(
        self, user_rows: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """A.10: Check for console users without MFA."""
        flagged = []
        for row in user_rows:
            pwd_enabled = row.get(
                "password_enabled", "false"
            ).lower() == "true"
            mfa_active = row.get(
                "mfa_active", "false"
            ).lower() == "true"
            if pwd_enabled and not mfa_active:
                flagged.append(row.get("user", "unknown"))

        return {"count": len(flagged), "users": flagged}

    def _check_root_usage(
        self, root_row: Dict[str, str]
    ) -> Dict[str, Any]:
        """A.11: Check if root was used in the last 90 days."""
        if root_row is None:
            return {
                "used_recently": True,
                "last_used": "unknown",
            }  # Fail-closed

        now = datetime.now(timezone.utc)
        last_used_dates = []

        # Check password last used
        pwd_last = root_row.get(
            "password_last_used", "no_information"
        )
        if pwd_last not in (
            "no_information", "N/A", "not_supported"
        ):
            try:
                dt = datetime.fromisoformat(
                    pwd_last.replace("Z", "+00:00")
                )
                last_used_dates.append(dt)
            except (ValueError, TypeError):
                pass

        # Check access key last used
        for key_num in ("1", "2"):
            key_last = root_row.get(
                f"access_key_{key_num}_last_used_date", "N/A"
            )
            if key_last not in (
                "N/A", "no_information", "not_supported"
            ):
                try:
                    dt = datetime.fromisoformat(
                        key_last.replace("Z", "+00:00")
                    )
                    last_used_dates.append(dt)
                except (ValueError, TypeError):
                    pass

        if not last_used_dates:
            return {
                "used_recently": False,
                "last_used": "never",
            }

        most_recent = max(last_used_dates)
        days_ago = (now - most_recent).days
        return {
            "used_recently": days_ago <= 90,
            "last_used": most_recent.isoformat(),
        }
