from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


DECISION_ORDER = {
    "allow": 0,
    "log": 1,
    "require_approval": 2,
    "deny": 3,
}


@dataclass(slots=True)
class RuntimeFinding:
    rule_id: str
    category: str
    severity: str
    reason: str
    evidence: str | None = None
    action: str = "log"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeDecision:
    decision: str
    reason: str
    rule_id: str | None = None
    severity: str = "info"
    category: str = "runtime"
    findings: list[RuntimeFinding] = field(default_factory=list)
    sanitized: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "findings": [finding.to_dict() for finding in self.findings],
            "sanitized": self.sanitized,
            "metadata": self.metadata,
        }


def stronger_decision(current: RuntimeDecision | None, candidate: RuntimeDecision) -> RuntimeDecision:
    if current is None:
        return candidate
    if DECISION_ORDER[candidate.decision] > DECISION_ORDER[current.decision]:
        return candidate
    return current

