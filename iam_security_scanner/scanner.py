"""IAM Security Scanner - Main orchestrator with multi-threading,
compliance mapping, and account-level scanning."""

import csv
import io
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .compliance import ComplianceChecker
from .html_reporter import HTMLReporter
from .utils import (
    setup_logging,
    calculate_security_score,
    get_severity_color,
)
from .checks import (
    UserSecurityChecker,
    PasswordPolicyChecker,
    PolicySecurityChecker,
    RoleSecurityChecker,
    GroupSecurityChecker,
    AccountSettingsChecker,
    PrivilegeEscalationChecker,
    TrustAnalysisChecker,
)


class IAMSecurityScanner:
    """IAM Security Scanner driving all security checks.

    Facade pattern: orchestrates scanning across 6 checker
    modules, manages thread pool, progress display, and
    report generation. Produces one result per account.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        output_dir: str = "./output",
        max_workers: int = 6,
    ):
        """Initialize the IAM Security Scanner.

        Args:
            region: AWS region for API calls
            profile: AWS profile name
            output_dir: Directory for reports and logs
            max_workers: Maximum parallel threads (default 6)
        """
        self.region = region
        self.profile = profile
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.console = Console()

        os.makedirs(output_dir, exist_ok=True)
        self.logger = setup_logging(output_dir)

        # Setup AWS session for main thread
        try:
            self._session = self._create_session()
            self.account_id = self._get_account_id()
        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. "
                "Please configure your credentials."
            )
            raise

        # Initialize 6 checker modules with session factory
        factory = self._create_session
        self.user_checker = UserSecurityChecker(factory)
        self.password_checker = PasswordPolicyChecker(
            factory
        )
        self.policy_checker = PolicySecurityChecker(factory)
        self.role_checker = RoleSecurityChecker(factory)
        self.group_checker = GroupSecurityChecker(factory)
        self.account_checker = AccountSettingsChecker(
            factory
        )
        self.privesc_checker = PrivilegeEscalationChecker(
            factory
        )
        self.trust_checker = TrustAnalysisChecker(factory)

        # Compliance & reporting
        self.compliance_checker = ComplianceChecker()
        self.html_reporter = HTMLReporter()

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with profile if specified."""
        if self.profile:
            return boto3.Session(
                profile_name=self.profile,
                region_name=self.region,
            )
        return boto3.Session(region_name=self.region)

    def _get_account_id(self) -> str:
        """Get the AWS account ID."""
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception as e:
            self.logger.debug(
                f"Could not determine AWS account ID: {e}"
            )
            return "unknown"

    # ================================================================
    # Data Collection (run on main thread before parallelism)
    # ================================================================

    def _generate_credential_report(self) -> List[Dict]:
        """Generate and download a fresh IAM credential report.

        Always requests a new generation to avoid returning stale
        data (AWS caches reports for up to 4 hours). Falls back to
        the existing report if generation is throttled.

        Returns:
            List of dicts, one per user row in the CSV report
        """
        iam = self._session.client("iam")

        # Always request a fresh report first
        try:
            iam.generate_credential_report()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "LimitExceededException":
                raise
            # Throttled - AWS already has a recent report; use it
            self.logger.debug(
                "Credential report generation throttled; "
                "using existing report"
            )

        max_retries = 10
        for _ in range(max_retries):
            try:
                response = iam.get_credential_report()
                if response.get("ReportFormat") == "text/csv":
                    content = response["Content"].decode(
                        "utf-8"
                    )
                    reader = csv.DictReader(
                        io.StringIO(content)
                    )
                    return list(reader)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in (
                    "ReportNotPresent",
                    "ReportInProgress",
                ):
                    time.sleep(2)
                else:
                    raise

        self.logger.error(
            "Failed to generate credential report "
            f"after {max_retries} attempts"
        )
        return []

    def _list_all_users(self) -> List[Dict]:
        """List all IAM users using pagination."""
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
        return users

    def _list_all_roles(self) -> List[Dict]:
        """List all IAM roles using pagination."""
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
        return roles

    def _list_all_policies(self) -> List[Dict]:
        """List all customer managed policies using pagination."""
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_policies")
        policies = []
        for page in paginator.paginate(Scope="Local"):
            policies.extend(page.get("Policies", []))
        return policies

    def _list_all_groups(self) -> List[Dict]:
        """List all IAM groups using pagination."""
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get("Groups", []))
        return groups

    # ================================================================
    # Main Scan
    # ================================================================

    def scan(self) -> Dict[str, Any]:
        """Run the full IAM security scan.

        Returns:
            Complete scan result dict with checks, issues,
            score, and compliance status
        """
        scan_start = datetime.now(timezone.utc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            # Phase 1: Collect shared data
            task = progress.add_task(
                "Generating credential report...", total=None
            )
            credential_report = (
                self._generate_credential_report()
            )
            progress.update(
                task,
                description="Listing IAM entities...",
            )
            users = self._list_all_users()
            roles = self._list_all_roles()
            policies = self._list_all_policies()
            groups = self._list_all_groups()
            progress.update(
                task,
                description=(
                    f"Found {len(users)} users, "
                    f"{len(roles)} roles, "
                    f"{len(policies)} policies, "
                    f"{len(groups)} groups"
                ),
            )

            # Phase 2: Run check categories in parallel
            progress.update(
                task,
                description=(
                    "Running 44 security checks across "
                    "7 categories..."
                ),
            )
            checks = self._run_checks_parallel(
                credential_report, users, roles,
                policies, groups,
            )

            # Phase 3: Analyze results
            progress.update(
                task,
                description="Analyzing results...",
            )
            issues = self._build_issues(checks)
            security_score = calculate_security_score(checks)
            compliance_status = (
                self.compliance_checker.check_compliance(
                    checks
                )
            )

            progress.update(
                task,
                description="Scan complete!",
            )

        scan_end = datetime.now(timezone.utc)
        duration = (scan_end - scan_start).total_seconds()

        return {
            "summary": {
                "scan_time": scan_start.isoformat() + "Z",
                "scan_duration_seconds": round(duration, 1),
                "account_id": self.account_id,
                "region": self.region,
                "security_score": security_score,
                "total_users": len(users),
                "total_roles": len(roles),
                "total_policies": len(policies),
                "total_groups": len(groups),
                "total_findings": len(issues),
                "critical_findings": sum(
                    1 for i in issues
                    if i["severity"] == "CRITICAL"
                ),
                "high_findings": sum(
                    1 for i in issues
                    if i["severity"] == "HIGH"
                ),
                "medium_findings": sum(
                    1 for i in issues
                    if i["severity"] == "MEDIUM"
                ),
                "low_findings": sum(
                    1 for i in issues
                    if i["severity"] == "LOW"
                ),
            },
            "checks": checks,
            "issues": issues,
            "compliance_status": compliance_status,
        }

    def _run_checks_parallel(
        self,
        credential_report,
        users,
        roles,
        policies,
        groups,
    ) -> Dict[str, Any]:
        """Run all 6 check categories in parallel."""
        checks = {}

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            futures = {
                executor.submit(
                    self.user_checker.check_all,
                    credential_report,
                    users,
                ): "user_security",
                executor.submit(
                    self.password_checker.check_all,
                ): "password_policy",
                executor.submit(
                    self.policy_checker.check_all,
                    policies,
                ): "policy_security",
                executor.submit(
                    self.role_checker.check_all,
                    roles,
                    self.account_id,
                ): "role_security",
                executor.submit(
                    self.group_checker.check_all,
                    groups,
                    users,
                ): "group_security",
                executor.submit(
                    self.account_checker.check_all,
                    roles,
                ): "account_settings",
                executor.submit(
                    self.privesc_checker.check_all,
                    policies,
                    users,
                    roles,
                ): "privilege_escalation",
                executor.submit(
                    self.trust_checker.check_all,
                    roles,
                    self.account_id,
                ): "trust_analysis",
            }

            for future in as_completed(futures):
                category = futures[future]
                try:
                    result = future.result()
                    checks.update(result)
                except Exception as e:
                    self.logger.error(
                        f"{category} checks failed: {e}"
                    )
                    checks[f"{category}_error"] = {
                        "error": str(e),
                    }

        return checks

    # ================================================================
    # Issue Building
    # ================================================================

    def _build_issues(
        self, checks: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Build issues list from checks dictionary."""
        issues = []

        # Map check keys to issue metadata
        issue_map = [
            (
                "root_access_keys", "exists", True,
                "A.1", "CRITICAL",
                "Root account has active access keys",
            ),
            (
                "root_mfa", "enabled", False,
                "A.2", "CRITICAL",
                "Root account does not have MFA enabled",
            ),
            (
                "root_mfa", "hardware", False,
                "A.3", "CRITICAL",
                "Root MFA is not a hardware device",
                lambda c: c.get("root_mfa", {}).get(
                    "enabled", False
                ),
            ),
            (
                "users_without_mfa", "count", None,
                "A.4", "MEDIUM",
                "IAM users without MFA enabled",
            ),
            (
                "old_access_keys", "count", None,
                "A.5", "MEDIUM",
                "Access keys older than 90 days",
            ),
            (
                "unused_credentials", "count", None,
                "A.6", "MEDIUM",
                "Credentials unused for 45+ days",
            ),
            (
                "multiple_access_keys", "count", None,
                "A.7", "LOW",
                "Users with multiple active access keys",
            ),
            (
                "direct_attached_policies", "count", None,
                "A.8", "LOW",
                "Users with directly attached policies",
            ),
            (
                "inline_user_policies", "count", None,
                "A.9", "LOW",
                "Users with inline policies",
            ),
            (
                "console_no_mfa", "count", None,
                "A.10", "HIGH",
                "Console users without MFA",
            ),
            (
                "root_usage", "used_recently", True,
                "A.11", "LOW",
                "Root account used in the last 90 days",
            ),
            (
                "admin_policies", "count", None,
                "C.1", "HIGH",
                "Customer managed policies with full admin",
            ),
            (
                "wildcard_service_policies", "count", None,
                "C.2", "LOW",
                "Policies with wildcard service actions",
            ),
            (
                "passrole_star_policies", "count", None,
                "C.3", "HIGH",
                "Policies with PassRole on wildcard resource",
            ),
            (
                "notaction_policies", "count", None,
                "C.4", "MEDIUM",
                "Policies using NotAction with Allow",
            ),
            (
                "unused_policies", "count", None,
                "C.5", "LOW",
                "Unused customer managed policies",
            ),
            (
                "admin_roles", "count", None,
                "D.1", "HIGH",
                "Roles with full admin access",
            ),
            (
                "wildcard_principal_roles", "count", None,
                "D.2", "CRITICAL",
                "Roles with wildcard principal in trust",
            ),
            (
                "overprivileged_roles", "count", None,
                "D.4", "HIGH",
                "Roles with overly permissive inline policies",
            ),
            (
                "unused_roles", "count", None,
                "D.5", "LOW",
                "Roles unused for 90+ days",
            ),
            (
                "admin_groups", "count", None,
                "E.1", "HIGH",
                "Groups with full admin access",
            ),
            (
                "empty_groups", "count", None,
                "E.2", "LOW",
                "Empty IAM groups",
            ),
            (
                "users_not_in_groups", "count", None,
                "E.3", "MEDIUM",
                "Users not in any group",
            ),
            (
                "access_analyzer", "enabled", False,
                "F.1", "HIGH",
                "IAM Access Analyzer is not enabled",
            ),
            (
                "support_role", "exists", False,
                "F.2", "LOW",
                "No support role with AWSSupportAccess",
            ),
            (
                "expired_certificates", "count", None,
                "F.3", "MEDIUM",
                "Expired SSL/TLS certificates in IAM",
            ),
            (
                "cloudshell_full_access", "count", None,
                "F.4", "MEDIUM",
                "Identities with CloudShell full access",
            ),
            (
                "iam_server_certificates", "count", None,
                "F.5", "LOW",
                "Certificates managed in IAM (legacy)",
            ),
            (
                "access_analyzer_findings", "count", None,
                "F.6", "HIGH",
                "Access Analyzer has active findings",
            ),
            (
                "unused_access_analyzer", "enabled", False,
                "F.7", "MEDIUM",
                "No Access Analyzer unused-access analyzer enabled",
            ),
            (
                "admin_users", "count", None,
                "A.12", "HIGH",
                "Users with AdministratorAccess attached directly",
            ),
            (
                "privesc_managed_policies", "count", None,
                "G.1", "CRITICAL",
                "Customer managed policies enabling privilege escalation",
            ),
            (
                "privesc_inline_policies", "count", None,
                "G.2", "CRITICAL",
                "Inline policies enabling privilege escalation",
            ),
            (
                "permissive_assume_role", "count", None,
                "G.3", "HIGH",
                "Policies allowing sts:AssumeRole on all resources",
            ),
            (
                "unguarded_trust", "count", None,
                "G.4", "HIGH",
                "Cross-account trust missing ExternalId/PrincipalOrgID "
                "guard (confused-deputy risk)",
            ),
            (
                "cross_account_trust", "count", None,
                "G.5", "MEDIUM",
                "Roles trusting another AWS account "
                "(Org membership unverifiable - review)",
            ),
        ]

        for entry in issue_map:
            if len(entry) == 7:
                (
                    key, field, trigger, check_id,
                    severity, desc, condition,
                ) = entry
                if not condition(checks):
                    continue
            else:
                (
                    key, field, trigger, check_id,
                    severity, desc,
                ) = entry

            check = checks.get(key, {})
            if not isinstance(check, dict):
                continue
            if "error" in check:
                continue

            value = check.get(field)

            # Determine if this is an issue
            is_issue = False
            if trigger is None:
                # count-based: issue if count > 0
                if isinstance(value, (int, float)):
                    is_issue = value > 0
            elif trigger is True:
                # boolean: issue if value is True
                is_issue = bool(value)
            elif trigger is False:
                # boolean: issue if value is False
                is_issue = not bool(value)

            if is_issue:
                issue = {
                    "check_id": check_id,
                    "severity": severity,
                    "description": desc,
                }
                # Note: bool is a subclass of int, so exclude it here -
                # boolean (presence/absence) checks have no meaningful
                # count and would otherwise render as "False"/"True".
                if isinstance(value, (int, float)) and not isinstance(
                    value, bool
                ):
                    issue["count"] = value
                issues.append(issue)

        # Category B: password policy findings (emitted from the
        # password_policy settings the scanner already collects).
        issues.extend(self._build_password_policy_issues(checks))

        # Sort by severity
        severity_order = {
            "CRITICAL": 0, "HIGH": 1,
            "MEDIUM": 2, "LOW": 3,
        }
        issues.sort(
            key=lambda x: severity_order.get(
                x["severity"], 99
            )
        )

        return issues

    def _build_password_policy_issues(
        self, checks: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Category B: emit findings from the account password policy.

        B.1 (no policy) is the umbrella finding; the granular B.2-B.8 are
        only emitted when a policy exists but is weak.
        """
        pp = checks.get("password_policy", {})
        if not isinstance(pp, dict) or "error" in pp:
            return []
        out = []

        def add(cid, sev, desc):
            out.append(
                {"check_id": cid, "severity": sev, "description": desc}
            )

        if not pp.get("exists", False):
            add("B.1", "HIGH",
                "No IAM account password policy is configured")
            return out

        if pp.get("min_length", 0) < 14:
            add("B.2", "MEDIUM",
                "Password policy minimum length is less than 14")
        if not pp.get("require_uppercase", False):
            add("B.3", "LOW",
                "Password policy does not require an uppercase letter")
        if not pp.get("require_lowercase", False):
            add("B.4", "LOW",
                "Password policy does not require a lowercase letter")
        if not pp.get("require_numbers", False):
            add("B.5", "LOW",
                "Password policy does not require a number")
        if not pp.get("require_symbols", False):
            add("B.6", "LOW",
                "Password policy does not require a symbol")
        if pp.get("reuse_prevention", 0) < 24:
            add("B.7", "LOW",
                "Password policy reuse prevention is less than 24")
        max_age = pp.get("max_age", 0)
        if not (0 < max_age <= 90):
            add("B.8", "LOW",
                "Password policy does not expire passwords within 90 days")
        return out

    # ================================================================
    # Report Generation
    # ================================================================

    def generate_reports(
        self,
        result: Dict[str, Any],
        output_format: str = "all",
    ) -> Dict[str, str]:
        """Generate reports in requested formats.

        Args:
            result: Scan result dict from scan()
            output_format: 'json', 'csv', 'html', or 'all'

        Returns:
            Dict mapping format name to file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_files = {}

        if output_format in ("json", "all"):
            json_file = os.path.join(
                self.output_dir,
                f"iam_scan_{timestamp}.json",
            )
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str)
            report_files["json"] = json_file

        if output_format in ("csv", "all"):
            csv_file = os.path.join(
                self.output_dir,
                f"iam_scan_{timestamp}.csv",
            )
            self._write_csv_report(result, csv_file)
            report_files["csv"] = csv_file

        if output_format in ("html", "all"):
            html_file = os.path.join(
                self.output_dir,
                f"iam_scan_{timestamp}.html",
            )
            self.html_reporter.generate_report(
                result, html_file,
            )
            report_files["html"] = html_file

        return report_files

    def _write_csv_report(
        self, result: Dict[str, Any], file_path: str
    ) -> None:
        """Write CSV report of findings."""
        with open(file_path, "w", newline="",
                  encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Check ID", "Severity", "Description",
                "Count",
            ])
            for issue in result.get("issues", []):
                writer.writerow([
                    issue.get("check_id", ""),
                    issue.get("severity", ""),
                    issue.get("description", ""),
                    issue.get("count", ""),
                ])

    # ================================================================
    # Console Summary
    # ================================================================

    def print_summary(
        self, result: Dict[str, Any]
    ) -> None:
        """Print scan summary to console using Rich."""
        summary = result.get("summary", {})
        issues = result.get("issues", [])
        compliance = result.get("compliance_status", {})

        # Account info
        self.console.print(
            f"\n[bold]Account:[/bold] {summary.get('account_id', 'N/A')}"
            f"  [bold]Region:[/bold] {summary.get('region', 'N/A')}"
            f"  [bold]Duration:[/bold] "
            f"{summary.get('scan_duration_seconds', 0)}s"
        )

        # Entity counts
        self.console.print(
            f"[dim]Users: {summary.get('total_users', 0)} | "
            f"Roles: {summary.get('total_roles', 0)} | "
            f"Policies: {summary.get('total_policies', 0)} | "
            f"Groups: {summary.get('total_groups', 0)}[/dim]"
        )

        # Security score
        score = summary.get("security_score", 0)
        if score >= 90:
            color = "green"
        elif score >= 70:
            color = "yellow"
        elif score >= 50:
            color = "orange1"
        else:
            color = "red"
        self.console.print(
            f"\n[bold {color}]Security Score: "
            f"{score}/100[/bold {color}]"
        )

        # Findings summary
        self.console.print(
            f"\n[bold]Findings:[/bold] "
            f"[bold red]{summary.get('critical_findings', 0)} "
            f"CRITICAL[/bold red] | "
            f"[red]{summary.get('high_findings', 0)} "
            f"HIGH[/red] | "
            f"[yellow]{summary.get('medium_findings', 0)} "
            f"MEDIUM[/yellow] | "
            f"[blue]{summary.get('low_findings', 0)} "
            f"LOW[/blue]"
        )

        # Issues table
        if issues:
            table = Table(title="Security Findings")
            table.add_column(
                "Check", style="cyan", width=8
            )
            table.add_column(
                "Severity", width=10
            )
            table.add_column(
                "Description", width=50
            )
            table.add_column(
                "Count", justify="right", width=8
            )

            for issue in issues:
                sev = issue["severity"]
                sev_color = get_severity_color(sev)
                table.add_row(
                    issue["check_id"],
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    issue["description"],
                    str(issue.get("count", "")),
                )

            self.console.print(table)

        # Compliance summary
        if compliance:
            comp_table = Table(
                title="Compliance Status"
            )
            comp_table.add_column(
                "Framework", style="cyan", width=20
            )
            comp_table.add_column(
                "Passed", justify="right", width=8
            )
            comp_table.add_column(
                "Failed", justify="right", width=8
            )
            comp_table.add_column(
                "Score", justify="right", width=8
            )
            comp_table.add_column(
                "Status", width=12
            )

            for fw_id, fw_result in compliance.items():
                pct = fw_result.get(
                    "compliance_percentage", 0
                )
                if pct == 100:
                    status = "[green]COMPLIANT[/green]"
                elif pct >= 80:
                    status = "[yellow]PARTIAL[/yellow]"
                else:
                    status = "[red]NON-COMPLIANT[/red]"

                comp_table.add_row(
                    fw_id,
                    str(fw_result.get(
                        "passed_controls", 0
                    )),
                    str(fw_result.get(
                        "failed_controls", 0
                    )),
                    f"{pct}%",
                    status,
                )

            self.console.print(comp_table)
