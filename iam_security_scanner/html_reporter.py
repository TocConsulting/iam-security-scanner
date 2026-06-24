"""HTML report generator for IAM Security Scanner."""

import os
from typing import Dict, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .utils import get_severity_color, format_datetime


class HTMLReporter:
    """Generate HTML dashboard reports for IAM security
    scan results."""

    def __init__(self, template_dir: str = None):
        """Initialize HTML reporter with template directory."""
        if template_dir is None:
            template_dir = os.path.join(
                os.path.dirname(__file__), "templates"
            )

        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

        # Custom filters
        self.env.filters["format_datetime"] = format_datetime
        self.env.filters[
            "get_severity_color"
        ] = get_severity_color

    def generate_report(
        self,
        result: Dict[str, Any],
        output_file: str,
    ) -> str:
        """Generate HTML report from scan results.

        Args:
            result: Complete scan result dict
            output_file: Path to write HTML file

        Returns:
            Path to generated HTML file
        """
        template = self.env.get_template("report.html")

        summary = result.get("summary", {})
        issues = result.get("issues", [])
        compliance = result.get("compliance_status", {})

        # Calculate chart data
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM": 0, "LOW": 0,
        }
        for issue in issues:
            sev = issue.get("severity", "LOW")
            if sev in severity_counts:
                severity_counts[sev] += 1

        compliance_labels = []
        compliance_percentages = []
        for fw_id, fw_result in compliance.items():
            compliance_labels.append(fw_id)
            compliance_percentages.append(
                fw_result.get("compliance_percentage", 0)
            )

        html_content = template.render(
            summary=summary,
            issues=issues,
            compliance=compliance,
            severity_counts=severity_counts,
            compliance_labels=compliance_labels,
            compliance_percentages=compliance_percentages,
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_file
