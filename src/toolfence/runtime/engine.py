from __future__ import annotations

import fnmatch
import json
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from toolfence.runtime.models import RuntimeDecision, RuntimeFinding, stronger_decision
from toolfence.runtime.normalizer import CommandNormalizer
from toolfence.runtime.sanitizer import Sanitizer
from toolfence.runtime.script_analyzer import ScriptAnalyzer


ACTION_TO_DECISION = {
    "allow": "allow",
    "log": "log",
    "approve": "require_approval",
    "require_approval": "require_approval",
    "deny": "deny",
}


class RuntimeEngine:
    def __init__(self, policy: dict[str, Any], cwd: Path | None = None):
        self.policy = policy
        self.cwd = cwd or Path.cwd()
        self.normalizer = CommandNormalizer()
        self.sanitizer = Sanitizer.from_policy(policy)
        self.script_analyzer = ScriptAnalyzer()

    @classmethod
    def from_file(cls, path: Path, cwd: Path | None = None) -> "RuntimeEngine":
        with path.open("r", encoding="utf-8") as handle:
            return cls(json.load(handle), cwd=cwd)

    def evaluate(self, event: dict[str, Any]) -> RuntimeDecision:
        if self.policy.get("panic", {}).get("enabled") is True:
            return RuntimeDecision(
                decision="deny",
                rule_id="TF-RUNTIME-PANIC",
                reason="panic mode is enabled",
                severity="critical",
                category="panic",
            )

        tool = event.get("tool", {})
        kind = str(tool.get("kind") or tool.get("type") or "").lower()
        scope_decision = self._check_task_scope(event, kind)
        if scope_decision and scope_decision.decision == "deny":
            return self._with_sanitized(event, scope_decision)

        decision: RuntimeDecision
        if kind in {"shell", "command", "exec", "process"}:
            decision = self._check_command(str(tool.get("command") or event.get("operation") or ""))
        elif kind in {"file_read", "file_write", "file", "read", "write", "edit", "list_directory"}:
            decision = self._check_file(str(tool.get("path") or tool.get("target") or ""), kind)
        elif kind in {"network", "http", "http_request", "browser"}:
            decision = self._check_network(str(tool.get("url") or event.get("egress", {}).get("url") or event.get("egress", {}).get("domain") or ""))
        else:
            decision = RuntimeDecision(
                decision="allow",
                reason="tool kind did not match runtime checks",
                rule_id="TF-RUNTIME-DEFAULT",
                category="runtime",
            )

        if scope_decision:
            decision = stronger_decision(decision, scope_decision)
        return self._with_sanitized(event, decision)

    def _check_command(self, command: str) -> RuntimeDecision:
        if not command.strip():
            return RuntimeDecision("deny", "empty command", "TF-RUNTIME-EMPTY-COMMAND", "medium", "command")

        normalized, warnings = self.normalizer.normalize(command)
        level = self.normalizer.obfuscation_level(command)
        if level == "high":
            return RuntimeDecision(
                decision="deny",
                rule_id="TF-RUNTIME-COMMAND-OBFUSCATION",
                reason=f"high command obfuscation detected: {', '.join(warnings)}",
                severity="high",
                category="command",
                metadata={"normalized": normalized, "warnings": warnings},
            )
        if level == "medium":
            candidate: RuntimeDecision | None = RuntimeDecision(
                decision="require_approval",
                rule_id="TF-RUNTIME-COMMAND-OBFUSCATION",
                reason=f"medium command obfuscation detected: {', '.join(warnings)}",
                severity="medium",
                category="command",
                metadata={"normalized": normalized, "warnings": warnings},
            )
        else:
            candidate = None

        file_decision = self._check_file_read_in_command(command)
        if file_decision:
            candidate = stronger_decision(candidate, file_decision)

        script_decision = self._check_script_in_command(command)
        if script_decision:
            candidate = stronger_decision(candidate, script_decision)

        for bucket in ("blacklist", "supervised", "whitelist"):
            for rule in self.policy.get("command_rules", {}).get(bucket, []):
                pattern = rule.get("pattern", "")
                if re.search(pattern, command) or re.search(pattern, normalized):
                    decision = ACTION_TO_DECISION.get(rule.get("action", "log"), "log")
                    runtime_decision = RuntimeDecision(
                        decision=decision,
                        rule_id=rule.get("id") or f"TF-RUNTIME-COMMAND-{bucket.upper()}",
                        reason=rule.get("reason") or f"command matched {bucket}",
                        severity=rule.get("severity", "medium"),
                        category="command",
                        metadata={"pattern": pattern, "normalized": normalized if normalized != command else None},
                    )
                    candidate = stronger_decision(candidate, runtime_decision)
                    if decision == "deny":
                        return candidate

        return candidate or RuntimeDecision("allow", "command allowed by default", "TF-RUNTIME-COMMAND-DEFAULT", "info", "command")

    def _check_file(self, path_text: str, kind: str) -> RuntimeDecision:
        if not path_text:
            return RuntimeDecision("deny", "missing file path", "TF-RUNTIME-FILE-MISSING-PATH", "medium", "file")
        path = _normalize_path(path_text, self.cwd)
        file_rules = self.policy.get("file_rules", {})

        for pattern in file_rules.get("denied_paths", []):
            if _path_matches(path, pattern):
                return RuntimeDecision(
                    "deny",
                    f"file path denied by policy: {pattern}",
                    "TF-RUNTIME-FILE-DENIED",
                    "high",
                    "file",
                    metadata={"path": str(path), "pattern": pattern, "kind": kind},
                )

        for pattern in file_rules.get("sensitive_patterns", []):
            if fnmatch.fnmatch(path.name.lower(), pattern.lower()):
                return RuntimeDecision(
                    "require_approval",
                    f"file path matches sensitive pattern: {pattern}",
                    "TF-RUNTIME-FILE-SENSITIVE",
                    "medium",
                    "file",
                    metadata={"path": str(path), "pattern": pattern, "kind": kind},
                )

        allowed = file_rules.get("allowed_paths", [])
        if allowed and any(_path_matches(path, pattern) for pattern in allowed):
            return RuntimeDecision("allow", "file path allowed by policy", "TF-RUNTIME-FILE-ALLOWLIST", "info", "file")
        if allowed and kind in {"file_write", "write", "edit"}:
            return RuntimeDecision(
                "require_approval",
                "file write outside allowlist requires approval",
                "TF-RUNTIME-FILE-WRITE-OUTSIDE-SCOPE",
                "medium",
                "file",
                metadata={"path": str(path)},
            )
        return RuntimeDecision("allow", "file path allowed by default", "TF-RUNTIME-FILE-DEFAULT", "info", "file")

    def _check_network(self, target: str) -> RuntimeDecision:
        if not target:
            return RuntimeDecision("deny", "missing network target", "TF-RUNTIME-NETWORK-MISSING-TARGET", "medium", "network")
        domain = _domain(target)
        network_rules = self.policy.get("network_rules", {})
        for pattern in network_rules.get("denied_domains", []):
            if _domain_matches(domain, pattern) or _domain_matches(target, pattern):
                return RuntimeDecision(
                    "deny",
                    f"network target denied by policy: {pattern}",
                    "TF-RUNTIME-NETWORK-DENIED",
                    "high",
                    "network",
                    metadata={"target": target, "domain": domain, "pattern": pattern},
                )
        for pattern in network_rules.get("allowed_domains", []):
            if _domain_matches(domain, pattern):
                return RuntimeDecision("allow", "network target allowed by policy", "TF-RUNTIME-NETWORK-ALLOWLIST", "info", "network")
        default = ACTION_TO_DECISION.get(network_rules.get("default_action", "require_approval"), "require_approval")
        return RuntimeDecision(
            default,
            "network target is not in allowlist",
            "TF-RUNTIME-NETWORK-DEFAULT",
            "medium",
            "network",
            metadata={"target": target, "domain": domain},
        )

    def _check_task_scope(self, event: dict[str, Any], kind: str) -> RuntimeDecision | None:
        scope = event.get("task_scope") or self.policy.get("task_scope") or {}
        disabled = {str(item).lower() for item in scope.get("disabled_tools", [])}
        if kind and kind in disabled:
            return RuntimeDecision("deny", f"tool kind disabled by task scope: {kind}", "TF-RUNTIME-SCOPE-DISABLED-TOOL", "high", "task-scope")
        return None

    def _check_file_read_in_command(self, command: str) -> RuntimeDecision | None:
        match = re.match(r"^\s*(cat|head|tail|less|more|grep|strings|xxd|hexdump|wc)\s+(?P<rest>.+)$", command)
        if not match:
            return None
        try:
            parts = shlex.split(match.group("rest"))
        except ValueError:
            return None
        for part in parts:
            if part.startswith("-"):
                continue
            if part.startswith("/") or part.startswith("~/") or part.startswith("."):
                decision = self._check_file(part, "file_read")
                if decision.decision in {"deny", "require_approval"}:
                    return decision
        return None

    def _check_script_in_command(self, command: str) -> RuntimeDecision | None:
        try:
            parts = shlex.split(command)
        except ValueError:
            return None
        if len(parts) < 2:
            return None
        interpreter = Path(parts[0]).name.lower()
        if interpreter not in {"python", "python3", "node", "bash", "sh", "zsh"}:
            return None
        script = parts[1]
        if script.startswith("-"):
            return None
        path = _normalize_path(script, self.cwd)
        if path.suffix.lower() not in {".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".zsh"}:
            return None
        analysis = self.script_analyzer.analyze(path)
        if analysis.recommended_action == "allow":
            return None
        findings = [
            RuntimeFinding(
                rule_id="TF-RUNTIME-SCRIPT-FINDING",
                category=finding.category,
                severity=finding.severity,
                reason=finding.description,
                evidence=finding.evidence,
                action=analysis.recommended_action,
            )
            for finding in analysis.findings
        ]
        return RuntimeDecision(
            decision=analysis.recommended_action,
            rule_id="TF-RUNTIME-SCRIPT-ANALYSIS",
            reason=f"script analysis recommends {analysis.recommended_action}: {path}",
            severity="critical" if analysis.recommended_action == "deny" else "medium",
            category="script-analysis",
            findings=findings,
            metadata={"script": analysis.to_dict()},
        )

    def _with_sanitized(self, event: dict[str, Any], decision: RuntimeDecision) -> RuntimeDecision:
        tool = event.get("tool", {})
        sanitized: dict[str, Any] = {}
        for key in ("input", "output", "command", "body", "content"):
            value = tool.get(key) or event.get(key)
            if isinstance(value, str):
                sanitized[key] = self.sanitizer.sanitize(value)
                matches = self.sanitizer.detect(value)
                if matches:
                    decision.findings.append(
                        RuntimeFinding(
                            rule_id="TF-RUNTIME-SENSITIVE-CONTENT",
                            category="sanitizer",
                            severity="high",
                            reason=f"sensitive content detected in {key}",
                            action="deny" if key in {"input", "body", "content"} else "log",
                        )
                    )
        decision.sanitized = sanitized
        return decision


def _normalize_path(path_text: str, cwd: Path) -> Path:
    expanded = Path(path_text).expanduser()
    if not expanded.is_absolute():
        expanded = cwd / expanded
    return expanded.resolve(strict=False)


def _path_matches(path: Path, pattern: str) -> bool:
    expanded = str(Path(pattern).expanduser())
    if pattern.endswith("/**"):
        base = expanded[:-3]
        return str(path) == base or str(path).startswith(base.rstrip("/") + "/")
    return fnmatch.fnmatch(str(path), expanded) or fnmatch.fnmatch(path.name, pattern)


def _domain(target: str) -> str:
    if "://" not in target:
        return target.split("/")[0].lower()
    parsed = urlparse(target)
    return (parsed.hostname or target).lower()


def _domain_matches(domain: str, pattern: str) -> bool:
    if not domain:
        return False
    lowered = pattern.lower()
    if lowered.startswith("*."):
        suffix = lowered[1:]
        return domain.endswith(suffix)
    if any(ch in lowered for ch in "*?[]"):
        return fnmatch.fnmatch(domain, lowered)
    try:
        return bool(re.fullmatch(lowered, domain))
    except re.error:
        return domain == lowered or domain.endswith("." + lowered)

