from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ScriptFinding:
    category: str
    severity: str
    description: str
    line: int | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class ScriptAnalysis:
    path: str
    risk: str
    recommended_action: str
    findings: list[ScriptFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "risk": self.risk,
            "recommended_action": self.recommended_action,
            "findings": [finding.to_dict() for finding in self.findings],
        }


PY_CRITICAL_IMPORTS = {
    "ctypes": "native memory access",
    "cffi": "native code execution",
    "pickle": "unsafe deserialization",
    "marshal": "bytecode deserialization",
}
PY_SUPERVISED_IMPORTS = {
    "subprocess": "process execution",
    "os": "operating system access",
    "shutil": "file mutation",
    "socket": "raw network access",
    "requests": "HTTP network access",
    "urllib": "network access",
    "smtplib": "email sending",
    "paramiko": "SSH access",
    "importlib": "dynamic import",
}
PY_CRITICAL_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
}
PY_CRITICAL_BUILTINS = {"eval", "exec", "compile", "__import__"}
RAW_PATTERNS = [
    ("metadata_ssrf", "critical", "cloud metadata endpoint access", r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"),
    ("reverse_shell", "critical", "reverse shell pattern", r"bash\s+-i\s+>&|/dev/tcp/|nc\s+-[el].*sh|socat\s+.*exec:"),
    ("credential_access", "critical", "credential file access", r"/etc/shadow|\.ssh/id_(rsa|ecdsa|ed25519)|\.aws/credentials|\.docker/config\.json"),
    ("exfiltration", "high", "POST with file content", r"requests\.post.*open\(|curl.*(--data-binary|-d)\s+@"),
    ("egress_sink", "high", "request to paste or tunnel endpoint", r"pastebin\.com|transfer\.sh|ngrok\.io|localtunnel\.me|webhook\.site|requestbin\."),
    ("obfuscated_exec", "high", "encoded payload execution", r"base64\s*(-d|--decode).*\|.*(bash|sh|python)|echo\s+[A-Za-z0-9+/=]{30,}\s*\|\s*base64"),
    ("dynamic_import", "high", "dynamic import", r"__import__\s*\(|importlib\.import_module\s*\("),
]


class ScriptAnalyzer:
    def analyze(self, path: Path, max_bytes: int = 250_000) -> ScriptAnalysis:
        resolved = path.expanduser().resolve()
        if not resolved.exists() or not resolved.is_file():
            return ScriptAnalysis(
                path=str(resolved),
                risk="dangerous",
                recommended_action="deny",
                findings=[
                    ScriptFinding(
                        category="missing_script",
                        severity="critical",
                        description="script file does not exist",
                    )
                ],
            )
        text = resolved.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
        findings = self._raw_findings(text)
        if resolved.suffix == ".py":
            findings.extend(self._python_findings(text))

        severities = {finding.severity for finding in findings}
        if "critical" in severities:
            action = "deny"
            risk = "dangerous"
        elif "high" in severities or "medium" in severities:
            action = "require_approval"
            risk = "suspicious"
        else:
            action = "allow"
            risk = "safe"
        return ScriptAnalysis(str(resolved), risk, action, findings)

    def _raw_findings(self, text: str) -> list[ScriptFinding]:
        findings = []
        for category, severity, description, pattern in RAW_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for match in compiled.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    ScriptFinding(category, severity, description, line=line, evidence=match.group(0)[:160])
                )
        return findings

    def _python_findings(self, text: str) -> list[ScriptFinding]:
        findings = []
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            return [
                ScriptFinding(
                    category="python_parse_error",
                    severity="medium",
                    description="Python script could not be parsed",
                    line=exc.lineno,
                    evidence=exc.msg,
                )
            ]

        imports: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.name.split(".")[0]] = node.lineno
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports[node.module.split(".")[0]] = node.lineno

        for name, line in imports.items():
            if name in PY_CRITICAL_IMPORTS:
                findings.append(
                    ScriptFinding("dangerous_import", "critical", PY_CRITICAL_IMPORTS[name], line=line, evidence=name)
                )
            elif name in PY_SUPERVISED_IMPORTS:
                findings.append(
                    ScriptFinding("supervised_import", "medium", PY_SUPERVISED_IMPORTS[name], line=line, evidence=name)
                )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name in PY_CRITICAL_BUILTINS:
                findings.append(
                    ScriptFinding("dangerous_call", "critical", f"dangerous builtin {name}", line=node.lineno, evidence=name)
                )
            if "." in name:
                module, func = name.rsplit(".", 1)
                if (module.split(".")[0], func) in PY_CRITICAL_CALLS:
                    findings.append(
                        ScriptFinding("dangerous_call", "critical", f"process execution via {name}", line=node.lineno, evidence=name)
                    )
        return findings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""

