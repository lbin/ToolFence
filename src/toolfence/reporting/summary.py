from __future__ import annotations

from collections import defaultdict

from toolfence.models import ScanReport


def report_to_summary(report: ScanReport) -> str:
    lines = [
        "ToolFence scan summary",
        f"Generated: {report.inventory.generated_at}",
        f"Host: {report.inventory.hostname} ({report.inventory.platform})",
        "",
        "Inventory",
        f"  Agent configs: {report.summary.agents}",
        f"  MCP servers:   {report.summary.mcp_servers}",
        f"  Skills:        {report.summary.skills}",
        "",
        "Findings",
        f"  Risk score:    {report.summary.risk_score}",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"  {severity.title():<9} {report.summary.by_severity.get(severity, 0)}")

    if not report.findings:
        lines.extend(["", "No findings."])
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[str]] = defaultdict(list)
    for finding in report.findings[:50]:
        location = ""
        if finding.evidence:
            location = finding.evidence.path
            if finding.evidence.line:
                location += f":{finding.evidence.line}"
        grouped[finding.severity].append(
            f"- [{finding.rule_id}] {finding.title}: {finding.message}"
            + (f" ({location})" if location else "")
        )

    lines.append("")
    lines.append("Top findings")
    for severity in ("critical", "high", "medium", "low", "info"):
        if grouped[severity]:
            lines.append(f"{severity.title()}:")
            lines.extend(grouped[severity])
    if len(report.findings) > 50:
        lines.append(f"... {len(report.findings) - 50} more findings omitted from summary output.")
    return "\n".join(lines) + "\n"

