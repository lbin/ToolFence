from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(slots=True)
class Evidence:
    path: str
    line: int | None = None
    snippet: str | None = None


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    message: str
    target_type: str
    target_id: str
    evidence: Evidence | None = None
    remediation: str | None = None
    confidence: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.evidence is None:
            data["evidence"] = None
        return data


@dataclass(slots=True)
class AgentConfig:
    client: str
    path: str
    kind: str
    exists: bool
    parse_status: str = "unread"
    error: str | None = None
    fingerprint: str | None = None


@dataclass(slots=True)
class McpServer:
    name: str
    client: str
    config_path: str
    transport: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env_keys: list[str] = field(default_factory=list)
    package: str | None = None
    declared_capabilities: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None

    @property
    def asset_id(self) -> str:
        return f"mcp:{self.client}:{self.name}:{self.config_path}"


@dataclass(slots=True)
class SkillAsset:
    name: str
    path: str
    source: str
    instruction_files: list[str] = field(default_factory=list)
    script_files: list[str] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    file_count: int = 0
    fingerprint: str | None = None

    @property
    def asset_id(self) -> str:
        return f"skill:{self.name}:{self.path}"


@dataclass(slots=True)
class Inventory:
    generated_at: str
    hostname: str
    platform: str
    home: str
    roots: list[str]
    agent_configs: list[AgentConfig] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    skills: list[SkillAsset] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ReportSummary:
    findings_total: int
    by_severity: dict[str, int]
    risk_score: int
    agents: int
    mcp_servers: int
    skills: int


@dataclass(slots=True)
class ScanReport:
    schema_version: str
    tool: dict[str, str]
    inventory: Inventory
    findings: list[Finding]
    summary: ReportSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "inventory": self.inventory.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": asdict(self.summary),
        }


def severity_at_least(value: str, minimum: str) -> bool:
    return SEVERITY_ORDER[value] >= SEVERITY_ORDER[minimum]


def summarize_findings(inventory: Inventory, findings: list[Finding]) -> ReportSummary:
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        by_severity[finding.severity] += 1

    weights = {
        "critical": 100,
        "high": 70,
        "medium": 35,
        "low": 10,
        "info": 2,
    }
    raw_score = sum(weights[finding.severity] for finding in findings)
    return ReportSummary(
        findings_total=len(findings),
        by_severity=by_severity,
        risk_score=min(raw_score, 1000),
        agents=len([config for config in inventory.agent_configs if config.exists]),
        mcp_servers=len(inventory.mcp_servers),
        skills=len(inventory.skills),
    )

