from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from toolfence.runtime.models import RuntimeDecision


@dataclass(slots=True)
class ProxyDecision:
    action: str
    reason: str
    rule_id: str
    tool_name: str | None = None
    runtime_decision: RuntimeDecision | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.runtime_decision is not None:
            data["runtime_decision"] = self.runtime_decision.to_dict()
        return data


@dataclass(slots=True)
class ProxyResult:
    message: dict[str, Any]
    decisions: list[ProxyDecision] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "decisions": [decision.to_dict() for decision in self.decisions],
        }

