"""Utility functions for IAM Security Scanner."""

import logging
import os
from datetime import datetime
from typing import Dict, Any


def setup_logging(output_dir: str) -> logging.Logger:
    """Setup logging configuration with console and file handlers."""
    logger = logging.getLogger("iam_security_scanner")
    logger.setLevel(logging.INFO)

    # Prevent propagation to root logger
    logger.propagate = False

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_file = os.path.join(
        output_dir,
        f'iam_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def calculate_security_score(checks: Dict[str, Any]) -> int:
    """Calculate a security score for the account (0-100).

    Implements non-stacking rule for overlapping MFA checks:
    A.4 (all users) and A.10 (console users) share overlap,
    so only the highest single penalty is applied.

    Score is clamped to minimum 0 (never negative).
    """
    score = 100

    # Helper function to safely get check results
    # Fail-closed: errors return fail-safe defaults
    def get(key: str, field: str, default=False):
        check = checks.get(key, {})
        if isinstance(check, dict) and "error" not in check:
            return check.get(field, default)
        # On error or missing, return fail-closed defaults
        if isinstance(default, (int, float)):
            return 1  # assume worst case for counts
        return default

    # === CRITICAL deductions ===
    if get("root_access_keys", "exists", True):
        score -= 25
    if not get("root_mfa", "enabled"):
        score -= 25
    if get("root_mfa", "enabled") and not get(
        "root_mfa", "hardware"
    ):
        score -= 5
    if get("wildcard_principal_roles", "count", 0) > 0:
        score -= 20

    # G.1/G.2 - privilege escalation (managed or inline; non-stacking
    # so a principal flagged by both isn't penalized twice)
    privesc_penalty = 0
    if get("privesc_managed_policies", "count", 0) > 0:
        privesc_penalty = 20
    if get("privesc_inline_policies", "count", 0) > 0:
        privesc_penalty = 20
    score -= privesc_penalty

    # === HIGH deductions ===
    if get("admin_users", "count", 0) > 0:
        score -= 15
    if get("permissive_assume_role", "count", 0) > 0:
        score -= 10
    if get("unguarded_trust", "count", 0) > 0:
        score -= 10
    if get("admin_policies", "count", 0) > 0:
        score -= 15
    if get("admin_roles", "count", 0) > 0:
        score -= 15
    if get("passrole_star_policies", "count", 0) > 0:
        score -= 10
    if not get("access_analyzer", "enabled"):
        score -= 10
    if get("admin_groups", "count", 0) > 0:
        score -= 10
    if get("overprivileged_roles", "count", 0) > 0:
        score -= 10
    if get("access_analyzer_findings", "count", 0) > 0:
        score -= 10

    # === MFA non-stacking penalty (A.4 + A.10 overlap) ===
    mfa_penalty = 0
    if get("users_without_mfa", "count", 0) > 0:
        mfa_penalty = max(mfa_penalty, 10)   # A.4 MEDIUM
    if get("console_no_mfa", "count", 0) > 0:
        mfa_penalty = max(mfa_penalty, 15)   # A.10 HIGH
    score -= mfa_penalty

    # === MEDIUM deductions ===
    if get("old_access_keys", "count", 0) > 0:
        score -= 10
    if get("unused_credentials", "count", 0) > 0:
        score -= 8

    pp = checks.get("password_policy", {})
    if not pp.get("exists", False):
        # No policy = all password checks fail
        # (sum of B.1-B.7 = -21)
        score -= 21
    else:
        if pp.get("min_length", 0) < 14:
            score -= 5
        if not pp.get("require_uppercase", False):
            score -= 3
        if not pp.get("require_lowercase", False):
            score -= 3
        if not pp.get("require_numbers", False):
            score -= 3
        if not pp.get("require_symbols", False):
            score -= 3
        # LOW password policy deductions (part of B)
        pp_reuse = pp.get("reuse_prevention", 0)
        if pp_reuse < 24:
            score -= 2
        pp_age = pp.get("max_age", 0)
        if pp_age == 0 or pp_age > 90:
            score -= 2

    if get("wildcard_service_policies", "count", 0) > 0:
        score -= 3
    if get("notaction_policies", "count", 0) > 0:
        score -= 3
    if get("expired_certificates", "count", 0) > 0:
        score -= 5
    if get("cloudshell_full_access", "count", 0) > 0:
        score -= 5
    if not get("unused_access_analyzer", "enabled"):
        score -= 3
    if get("cross_account_roles", "count", 0) > 0:
        score -= 5
    if get("users_not_in_groups", "count", 0) > 0:
        score -= 5

    # === LOW deductions ===
    if get("direct_attached_policies", "count", 0) > 0:
        score -= 5
    if get("inline_user_policies", "count", 0) > 0:
        score -= 2
    if get("multiple_access_keys", "count", 0) > 0:
        score -= 2
    if not get("support_role", "exists"):
        score -= 2
    if get("empty_groups", "count", 0) > 0:
        score -= 2
    if get("unused_policies", "count", 0) > 0:
        score -= 2
    if get("unused_roles", "count", 0) > 0:
        score -= 2
    if get("iam_server_certificates", "count", 0) > 0:
        score -= 1
    if get("root_usage", "used_recently"):
        score -= 2

    # Clamp to minimum 0
    return max(0, score)


def get_severity_color(severity: str) -> str:
    """Map severity level to Rich color string."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "ERROR": "magenta",
    }
    return colors.get(severity, "white")


def format_datetime(dt) -> str:
    """Format datetime for display."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(
                dt.replace("Z", "+00:00")
            )
        except ValueError:
            return dt

    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    return str(dt)
