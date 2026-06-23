from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class PolicyDecision:
    decision: str
    rule_id: str | None
    reason: str


def evaluate_event(policy_path: Path, event_path: Path) -> PolicyDecision:
    with policy_path.open("r", encoding="utf-8") as handle:
        policy = json.load(handle)
    with event_path.open("r", encoding="utf-8") as handle:
        event = json.load(handle)

    for rule in policy.get("rules", []):
        if _matches(rule.get("when", {}), event):
            return PolicyDecision(
                decision=rule.get("effect", "deny"),
                rule_id=rule.get("id"),
                reason=rule.get("reason", "matched policy rule"),
            )
    return PolicyDecision(decision=policy.get("default_effect", "allow"), rule_id=None, reason="default policy")


def _matches(conditions: dict[str, Any], event: dict[str, Any]) -> bool:
    for key, expected in conditions.items():
        actual = _get_path(event, key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, dict) and "glob" in expected:
            if not fnmatch.fnmatch(str(actual or ""), expected["glob"]):
                return False
        elif isinstance(expected, dict) and "not_in" in expected:
            if actual in expected["not_in"]:
                return False
        elif actual != expected:
            return False
    return True


def _get_path(value: dict[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current

