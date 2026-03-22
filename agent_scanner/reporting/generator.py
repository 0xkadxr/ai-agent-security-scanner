"""Report generation module.

Generates markdown, JSON, and summary reports from scan results.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from agent_scanner.reporting.severity import severity_label

if TYPE_CHECKING:
    from agent_scanner.scanner import Finding, ScanReport


class ReportGenerator:
    """Generates security scan reports in multiple formats.

    Supports markdown, JSON, and plain-text summary output from
    ScanReport objects.
    """

    def generate_markdown(self, scan_results: "ScanReport") -> str:
        """Generate a detailed markdown report.

        Args:
            scan_results: The scan results to report on.

        Returns:
            Markdown-formatted report string.
        """
        lines: list[str] = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines.append("# AI Agent Security Scan Report")
        lines.append("")
        lines.append(f"**Generated:** {now}")
        lines.append(f"**Files Scanned:** {scan_results.files_scanned}")
        lines.append(f"**Scan Duration:** {scan_results.scan_duration_seconds:.2f}s")
        lines.append(f"**Overall Risk Score:** {scan_results.risk_score:.1f}/10")
        lines.append("")

        # Severity distribution
        lines.append("## Severity Distribution")
        lines.append("")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        lines.append(f"| Critical | {scan_results.critical_count} |")
        lines.append(f"| High     | {scan_results.high_count} |")
        lines.append(f"| Medium   | {scan_results.medium_count} |")
        lines.append(f"| Low      | {scan_results.low_count} |")
        lines.append(f"| **Total** | **{len(scan_results.findings)}** |")
        lines.append("")

        # Findings
        if scan_results.findings:
            lines.append("## Findings")
            lines.append("")

            sorted_findings = sorted(
                scan_results.findings,
                key=lambda f: f.severity_score,
                reverse=True,
            )

            for i, finding in enumerate(sorted_findings, 1):
                sev = severity_label(finding.severity_score)
                lines.append(f"### {i}. [{sev}] {finding.title}")
                lines.append("")
                lines.append(f"**Vulnerability ID:** {finding.vuln_id}")
                lines.append(f"**Severity Score:** {finding.severity_score}/10")

                if finding.file_path:
                    loc = finding.file_path
                    if finding.line_number:
                        loc += f":{finding.line_number}"
                    lines.append(f"**Location:** `{loc}`")

                lines.append("")
                lines.append(f"**Description:** {finding.description}")
                lines.append("")

                if finding.code_snippet:
                    lines.append("**Code:**")
                    lines.append("```python")
                    lines.append(finding.code_snippet)
                    lines.append("```")
                    lines.append("")

                if finding.recommendation:
                    lines.append(f"**Recommendation:** {finding.recommendation}")
                    lines.append("")

                lines.append("---")
                lines.append("")
        else:
            lines.append("## No Findings")
            lines.append("")
            lines.append("No security vulnerabilities were detected.")
            lines.append("")

        # Recommendations summary
        if scan_results.findings:
            lines.append("## Recommendations Summary")
            lines.append("")
            unique_recs: dict[str, str] = {}
            for f in scan_results.findings:
                if f.recommendation and f.vuln_id not in unique_recs:
                    unique_recs[f.vuln_id] = f.recommendation
            for vuln_id, rec in sorted(unique_recs.items()):
                lines.append(f"- **{vuln_id}:** {rec}")
            lines.append("")

        return "\n".join(lines)

    def generate_json(self, scan_results: "ScanReport") -> str:
        """Generate a machine-readable JSON report.

        Args:
            scan_results: The scan results to report on.

        Returns:
            JSON-formatted report string.
        """
        data: dict[str, Any] = {
            "report": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "files_scanned": scan_results.files_scanned,
                "scan_duration_seconds": round(scan_results.scan_duration_seconds, 2),
                "risk_score": round(scan_results.risk_score, 1),
                "severity_distribution": {
                    "critical": scan_results.critical_count,
                    "high": scan_results.high_count,
                    "medium": scan_results.medium_count,
                    "low": scan_results.low_count,
                },
                "total_findings": len(scan_results.findings),
            },
            "findings": [
                {
                    "vuln_id": f.vuln_id,
                    "title": f.title,
                    "description": f.description,
                    "severity_score": f.severity_score,
                    "severity_label": severity_label(f.severity_score),
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                    "category": f.category,
                }
                for f in sorted(
                    scan_results.findings,
                    key=lambda x: x.severity_score,
                    reverse=True,
                )
            ],
            "metadata": scan_results.metadata,
        }

        return json.dumps(data, indent=2)

    def generate_summary(self, scan_results: "ScanReport") -> str:
        """Generate an executive summary of the scan.

        Args:
            scan_results: The scan results to summarize.

        Returns:
            Plain-text executive summary string.
        """
        total = len(scan_results.findings)
        risk = scan_results.risk_score

        if risk >= 9.0:
            risk_assessment = "CRITICAL - Immediate remediation required"
        elif risk >= 7.0:
            risk_assessment = "HIGH - Significant security issues found"
        elif risk >= 4.0:
            risk_assessment = "MEDIUM - Some security improvements needed"
        elif risk >= 0.1:
            risk_assessment = "LOW - Minor issues to address"
        else:
            risk_assessment = "CLEAN - No significant issues found"

        lines = [
            "EXECUTIVE SUMMARY",
            "=" * 50,
            "",
            f"Risk Assessment: {risk_assessment}",
            f"Risk Score: {risk:.1f}/10",
            f"Total Findings: {total}",
            "",
            "Breakdown:",
            f"  Critical: {scan_results.critical_count}",
            f"  High:     {scan_results.high_count}",
            f"  Medium:   {scan_results.medium_count}",
            f"  Low:      {scan_results.low_count}",
            "",
            f"Files Scanned: {scan_results.files_scanned}",
            f"Scan Duration: {scan_results.scan_duration_seconds:.2f}s",
        ]

        if scan_results.findings:
            lines.append("")
            lines.append("Top Issues:")
            top = sorted(
                scan_results.findings,
                key=lambda f: f.severity_score,
                reverse=True,
            )[:5]
            for f in top:
                sev = severity_label(f.severity_score)
                lines.append(f"  [{sev}] {f.vuln_id}: {f.title}")

        return "\n".join(lines)
