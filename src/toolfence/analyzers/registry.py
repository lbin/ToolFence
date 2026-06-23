from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SignatureRule:
    rule_id: str
    title: str
    severity: str
    category: str
    scope: list[str]
    pattern: re.Pattern[str]
    message: str
    remediation: str
    confidence: str = "medium"


@dataclass(slots=True)
class ListEntry:
    entry_id: str
    description: str
    severity: str
    match: dict[str, str]
    action: str = "flag"
    metadata: dict[str, Any] | None = None


@dataclass(slots=True)
class Registry:
    signature_rules: list[SignatureRule]
    mcp_allowlist: list[ListEntry]
    mcp_blocklist: list[ListEntry]
    skill_allowlist: list[ListEntry]
    skill_blocklist: list[ListEntry]


def load_registry(rules_dir: Path) -> Registry:
    builtin = _load_json(rules_dir / "builtin-rules.json")
    return Registry(
        signature_rules=[
            SignatureRule(
                rule_id=item["id"],
                title=item["title"],
                severity=item["severity"],
                category=item["category"],
                scope=list(item["scope"]),
                pattern=re.compile(item["pattern"]),
                message=item["message"],
                remediation=item.get("remediation", ""),
                confidence=item.get("confidence", "medium"),
            )
            for item in builtin.get("rules", [])
        ],
        mcp_allowlist=_load_list(rules_dir / "allowlist" / "mcp-servers.json"),
        mcp_blocklist=_load_list(rules_dir / "blocklist" / "mcp-servers.json"),
        skill_allowlist=_load_list(rules_dir / "allowlist" / "skills.json"),
        skill_blocklist=_load_list(rules_dir / "blocklist" / "skills.json"),
    )


def validate_registry(rules_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        load_registry(rules_dir)
    except Exception as exc:  # noqa: BLE001 - used by CLI validation.
        errors.append(str(exc))
    for path in sorted(rules_dir.rglob("*.json")):
        try:
            data = _load_json(path)
            if path.name.endswith(".json") and "runtime" in path.parts:
                _validate_runtime_policy(data, path)
        except Exception as exc:  # noqa: BLE001 - used by CLI validation.
            errors.append(f"{path}: {exc}")
    return errors


def _validate_runtime_policy(data: dict[str, Any], path: Path) -> None:
    if data.get("schema_version") != "toolfence.runtime-policy.v1":
        return
    for bucket in ("blacklist", "whitelist", "supervised"):
        for rule in data.get("command_rules", {}).get(bucket, []):
            re.compile(rule["pattern"])
    for pattern in data.get("network_rules", {}).get("denied_domains", []):
        if not isinstance(pattern, str):
            raise ValueError(f"{path}: network denied domain pattern must be a string")
    for name, rule in data.get("sanitizer_rules", {}).get("patterns", {}).items():
        re.compile(rule["pattern"])
        if "replacement" not in rule:
            raise ValueError(f"{path}: sanitizer pattern {name} is missing replacement")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_list(path: Path) -> list[ListEntry]:
    if not path.exists():
        return []
    data = _load_json(path)
    entries = []
    for item in data.get("entries", []):
        entries.append(
            ListEntry(
                entry_id=item["id"],
                description=item.get("description", ""),
                severity=item.get("severity", "medium"),
                match=dict(item.get("match", {})),
                action=item.get("action", "flag"),
                metadata=item.get("metadata", {}),
            )
        )
    return entries
