from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ToolRule:
    rule_id: str
    action: str
    reason: str
    name_pattern: str | None = None
    description_pattern: str | None = None
    argument_pattern: str | None = None
    severity: str = "medium"

    def matches_tool(self, tool: dict[str, Any]) -> bool:
        if self.name_pattern and not re.search(self.name_pattern, str(tool.get("name", "")), re.IGNORECASE):
            return False
        if self.description_pattern and not re.search(
            self.description_pattern,
            str(tool.get("description", "")),
            re.IGNORECASE,
        ):
            return False
        return True

    def matches_call(self, name: str, arguments: dict[str, Any]) -> bool:
        if self.name_pattern and not re.search(self.name_pattern, name, re.IGNORECASE):
            return False
        if self.argument_pattern and not re.search(self.argument_pattern, json.dumps(arguments, sort_keys=True), re.IGNORECASE):
            return False
        return True


@dataclass(slots=True)
class ToolClassifier:
    kind: str
    name_pattern: str
    argument_keys: list[str]

    def matches(self, name: str) -> bool:
        return bool(re.search(self.name_pattern, name, re.IGNORECASE))


class McpProxyPolicy:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        discovery = data.get("discovery", {})
        invocation = data.get("invocation", {})
        self.default_visibility = discovery.get("default_visibility", "show")
        self.discovery_deny = [_rule(item) for item in discovery.get("deny_tools", [])]
        self.discovery_allow = [_rule(item) for item in discovery.get("allow_tools", [])]
        self.invocation_deny = [_rule(item) for item in invocation.get("deny_tools", [])]
        self.invocation_approval = [_rule(item) for item in invocation.get("require_approval_tools", [])]
        self.classifiers = [
            ToolClassifier(
                kind=item["kind"],
                name_pattern=item["name_pattern"],
                argument_keys=list(item.get("argument_keys", [])),
            )
            for item in invocation.get("classifiers", [])
        ]

    @classmethod
    def from_file(cls, path: Path) -> "McpProxyPolicy":
        with path.open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))


def _rule(item: dict[str, Any]) -> ToolRule:
    return ToolRule(
        rule_id=item["id"],
        action=item.get("action", "deny"),
        reason=item.get("reason", ""),
        name_pattern=item.get("name_pattern"),
        description_pattern=item.get("description_pattern"),
        argument_pattern=item.get("argument_pattern"),
        severity=item.get("severity", "medium"),
    )

