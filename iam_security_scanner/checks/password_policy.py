"""Password Policy checks (B.1-B.7)."""

import logging
from typing import Any, Dict

from botocore.exceptions import ClientError

from .base import BaseChecker

logger = logging.getLogger("iam_security_scanner")


class PasswordPolicyChecker(BaseChecker):
    """Checks for IAM account password policy configuration."""

    def check_all(self) -> Dict[str, Any]:
        """Run all password policy checks.

        Returns:
            Dict with password_policy key containing all
            password policy settings.
        """
        try:
            iam = self.get_client("iam")
            response = iam.get_account_password_policy()
            policy = response.get("PasswordPolicy", {})

            return {
                "password_policy": {
                    "exists": True,
                    "min_length": policy.get(
                        "MinimumPasswordLength", 0
                    ),
                    "require_uppercase": policy.get(
                        "RequireUppercaseCharacters", False
                    ),
                    "require_lowercase": policy.get(
                        "RequireLowercaseCharacters", False
                    ),
                    "require_numbers": policy.get(
                        "RequireNumbers", False
                    ),
                    "require_symbols": policy.get(
                        "RequireSymbols", False
                    ),
                    "reuse_prevention": policy.get(
                        "PasswordReusePrevention", 0
                    ),
                    "max_age": policy.get(
                        "MaxPasswordAge", 0
                    ),
                },
            }

        except ClientError as e:
            code = e.response.get("Error", {}).get(
                "Code", ""
            )
            if code == "NoSuchEntity":
                # No password policy configured
                return {
                    "password_policy": {
                        "exists": False,
                        "min_length": 0,
                        "require_uppercase": False,
                        "require_lowercase": False,
                        "require_numbers": False,
                        "require_symbols": False,
                        "reuse_prevention": 0,
                        "max_age": 0,
                    },
                }
            return {
                "password_policy": self.handle_client_error(
                    e,
                    {
                        "exists": False,
                        "min_length": 0,
                        "require_uppercase": False,
                        "require_lowercase": False,
                        "require_numbers": False,
                        "require_symbols": False,
                        "reuse_prevention": 0,
                        "max_age": 0,
                    },
                ),
            }
        except Exception as e:
            logger.warning(
                f"Password policy check failed: {e}"
            )
            return {
                "password_policy": {
                    "exists": False,
                    "min_length": 0,
                    "require_uppercase": False,
                    "require_lowercase": False,
                    "require_numbers": False,
                    "require_symbols": False,
                    "reuse_prevention": 0,
                    "max_age": 0,
                    "error": str(e),
                },
            }
