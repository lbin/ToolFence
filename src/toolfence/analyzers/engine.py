from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from toolfence.analyzers.registry import ListEntry, Registry, load_registry
from toolfence.models import Evidence, Finding, Inventory, McpServer, SkillAsset
from toolfence.utils import command_basename, domain_from_url, line_matches, safe_read_text


SEVERITY_FOR_ALLOWLIST_MISS = {
    "off": None,
    "warn": "low",
    "enforce": "medium",
}


def analyze_inventory(
    inventory: Inventory,
    rules_dir: Path,
    allowlist_mode: str = "off",
    max_file_bytes: int = 250_000,
) -> list[Finding]:
    registry = load_registry(rules_dir)
    findings: list[Finding] = []
    findings.extend(_analyze_mcp_servers(inventory, registry, allowlist_mode))
    findings.extend(_analyze_skills(inventory, registry, allowlist_mode, max_file_bytes))
    findings.extend(_analyze_config_parse_errors(inventory))
    return sorted(
        findings,
        key=lambda finding: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[finding.severity],
            finding.rule_id,
            finding.target_id,
        ),
    )


def _analyze_mcp_servers(
    inventory: Inventory,
    registry: Registry,
    allowlist_mode: str,
) -> list[Finding]:
    findings: list[Finding] = []
    names = Counter(server.name.lower() for server in inventory.mcp_servers)
    paths_by_name: dict[str, list[str]] = defaultdict(list)
    for server in inventory.mcp_servers:
        paths_by_name[server.name.lower()].append(server.config_path)

    for server in inventory.mcp_servers:
        findings.extend(_apply_mcp_blocklist(server, registry.mcp_blocklist))
        findings.extend(_apply_mcp_signature_rules(server, registry))
        findings.extend(_mcp_heuristics(server))

        if names[server.name.lower()] > 1:
            findings.append(
                Finding(
                    rule_id="TF-MCP-DUPLICATE-NAME",
                    title="Duplicate MCP server name",
                    severity="medium",
                    category="tool-shadowing",
                    message=(
                        f"MCP server name '{server.name}' appears in multiple configs: "
                        + ", ".join(sorted(set(paths_by_name[server.name.lower()])))
                    ),
                    target_type="mcp_server",
                    target_id=server.asset_id,
                    evidence=Evidence(path=server.config_path),
                    remediation="Use unique server names per client/project and remove stale duplicates.",
                    confidence="high",
                )
            )

        allow_severity = SEVERITY_FOR_ALLOWLIST_MISS.get(allowlist_mode)
        if allow_severity and not _matches_any(server, registry.mcp_allowlist):
            findings.append(
                Finding(
                    rule_id="TF-MCP-NOT-IN-ALLOWLIST",
                    title="MCP server is not in allowlist",
                    severity=allow_severity,
                    category="supply-chain",
                    message=(
                        f"MCP server '{server.name}' is not matched by the configured allowlist. "
                        "Review origin, maintainer, version pinning, and declared capabilities."
                    ),
                    target_type="mcp_server",
                    target_id=server.asset_id,
                    evidence=Evidence(path=server.config_path),
                    remediation="Add a reviewed allowlist entry or remove the server.",
                    confidence="medium",
                )
            )
    return findings


def _apply_mcp_blocklist(server: McpServer, entries: list[ListEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in entries:
        if _matches_entry(server, entry):
            findings.append(
                Finding(
                    rule_id=f"TF-MCP-BLOCKLIST-{entry.entry_id.upper()}",
                    title="MCP server matched blocklist",
                    severity=entry.severity,
                    category="blocklist",
                    message=entry.description or f"MCP server '{server.name}' matched blocklist entry {entry.entry_id}.",
                    target_type="mcp_server",
                    target_id=server.asset_id,
                    evidence=Evidence(path=server.config_path),
                    remediation="Disable this MCP server until it has been reviewed and replaced.",
                    confidence="high",
                    metadata={"entry_id": entry.entry_id, "action": entry.action},
                )
            )
    return findings


def _apply_mcp_signature_rules(server: McpServer, registry: Registry) -> list[Finding]:
    haystack = " ".join(
        item
        for item in [
            server.name,
            server.command or "",
            " ".join(server.args),
            server.url or "",
            " ".join(server.env_keys),
        ]
        if item
    )
    findings: list[Finding] = []
    for rule in registry.signature_rules:
        if "mcp" not in rule.scope and "mcp_command" not in rule.scope:
            continue
        if rule.pattern.search(haystack):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    category=rule.category,
                    message=rule.message.format(asset=server.name),
                    target_type="mcp_server",
                    target_id=server.asset_id,
                    evidence=Evidence(path=server.config_path, snippet=haystack[:500]),
                    remediation=rule.remediation,
                    confidence=rule.confidence,
                )
            )
    return findings


def _mcp_heuristics(server: McpServer) -> list[Finding]:
    findings: list[Finding] = []
    executable = command_basename(server.command)
    joined_args = " ".join(server.args)

    if executable in {"bash", "sh", "zsh", "fish", "powershell", "pwsh", "cmd"} and any(
        arg in {"-c", "/c"} for arg in server.args
    ):
        findings.append(
            Finding(
                rule_id="TF-MCP-SHELL-WRAPPER",
                title="MCP server launches through shell wrapper",
                severity="high",
                category="dangerous-command",
                message=f"MCP server '{server.name}' starts through a shell wrapper, which hides the actual executable.",
                target_type="mcp_server",
                target_id=server.asset_id,
                evidence=Evidence(path=server.config_path, snippet=f"{server.command} {joined_args}".strip()),
                remediation="Use a direct executable path with pinned arguments instead of a shell command string.",
                confidence="high",
            )
        )

    if executable in {"npx", "uvx", "pipx", "bunx", "pnpm", "yarn"} and not _has_pinned_package(server.package):
        findings.append(
            Finding(
                rule_id="TF-MCP-UNPINNED-PACKAGE",
                title="MCP server package is not version-pinned",
                severity="medium",
                category="supply-chain",
                message=f"MCP server '{server.name}' appears to launch a package without a pinned version.",
                target_type="mcp_server",
                target_id=server.asset_id,
                evidence=Evidence(path=server.config_path, snippet=f"{server.command} {joined_args}".strip()),
                remediation="Pin the package version or use a signed, internally mirrored package.",
                confidence="medium",
            )
        )

    if server.url:
        domain = domain_from_url(server.url) or ""
        if server.url.startswith("http://") and domain not in {"localhost", "127.0.0.1", "::1"}:
            findings.append(
                Finding(
                    rule_id="TF-MCP-CLEARTEXT-REMOTE",
                    title="Remote MCP server uses cleartext HTTP",
                    severity="high",
                    category="network",
                    message=f"MCP server '{server.name}' uses cleartext HTTP for a non-local endpoint.",
                    target_type="mcp_server",
                    target_id=server.asset_id,
                    evidence=Evidence(path=server.config_path, snippet=server.url),
                    remediation="Use HTTPS with server identity validation or move the server behind a local proxy.",
                    confidence="high",
                )
            )

    broad_paths = {"/", "~", "$HOME"}
    if any(arg in broad_paths for arg in server.args) and "filesystem" in server.declared_capabilities:
        findings.append(
            Finding(
                rule_id="TF-MCP-BROAD-FILESYSTEM-SCOPE",
                title="Filesystem MCP server has broad path scope",
                severity="high",
                category="excessive-permission",
                message=f"MCP server '{server.name}' may expose a broad filesystem scope to the agent.",
                target_type="mcp_server",
                target_id=server.asset_id,
                evidence=Evidence(path=server.config_path, snippet=f"{server.command} {joined_args}".strip()),
                remediation="Scope filesystem servers to project directories and deny sensitive home paths.",
                confidence="medium",
            )
        )

    sensitive_env_keys = [
        key
        for key in server.env_keys
        if re.search(r"(?i)(token|secret|password|private|credential|api[_-]?key)", key)
    ]
    if sensitive_env_keys:
        findings.append(
            Finding(
                rule_id="TF-MCP-SECRET-ENV",
                title="MCP server receives secret-like environment variables",
                severity="medium",
                category="secret-exposure",
                message=f"MCP server '{server.name}' receives secret-like env keys: {', '.join(sensitive_env_keys)}.",
                target_type="mcp_server",
                target_id=server.asset_id,
                evidence=Evidence(path=server.config_path),
                remediation="Prefer brokered credentials, scoped tokens, and policy checks before invocation.",
                confidence="medium",
            )
        )
    return findings


def _analyze_skills(
    inventory: Inventory,
    registry: Registry,
    allowlist_mode: str,
    max_file_bytes: int,
) -> list[Finding]:
    findings: list[Finding] = []
    for skill in inventory.skills:
        findings.extend(_apply_skill_blocklist(skill, registry.skill_blocklist))
        findings.extend(_apply_skill_signature_rules(skill, registry, max_file_bytes))
        findings.extend(_skill_heuristics(skill))

        allow_severity = SEVERITY_FOR_ALLOWLIST_MISS.get(allowlist_mode)
        if allow_severity and not _matches_any(skill, registry.skill_allowlist):
            findings.append(
                Finding(
                    rule_id="TF-SKILL-NOT-IN-ALLOWLIST",
                    title="Skill is not in allowlist",
                    severity=allow_severity,
                    category="supply-chain",
                    message=f"Skill '{skill.name}' is not matched by the configured allowlist.",
                    target_type="skill",
                    target_id=skill.asset_id,
                    evidence=Evidence(path=skill.path),
                    remediation="Add a reviewed allowlist entry with source, owner, and fingerprint, or remove the skill.",
                    confidence="medium",
                )
            )
    return findings


def _apply_skill_blocklist(skill: SkillAsset, entries: list[ListEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in entries:
        if _matches_entry(skill, entry):
            findings.append(
                Finding(
                    rule_id=f"TF-SKILL-BLOCKLIST-{entry.entry_id.upper()}",
                    title="Skill matched blocklist",
                    severity=entry.severity,
                    category="blocklist",
                    message=entry.description or f"Skill '{skill.name}' matched blocklist entry {entry.entry_id}.",
                    target_type="skill",
                    target_id=skill.asset_id,
                    evidence=Evidence(path=skill.path),
                    remediation="Disable this skill until it has been reviewed and replaced.",
                    confidence="high",
                    metadata={"entry_id": entry.entry_id, "action": entry.action},
                )
            )
    return findings


def _apply_skill_signature_rules(skill: SkillAsset, registry: Registry, max_file_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    root = Path(skill.path)
    for file_path in _safe_skill_files(root):
        try:
            text = safe_read_text(file_path, max_file_bytes)
        except OSError:
            continue
        for rule in registry.signature_rules:
            if "skill_file" not in rule.scope and "any_file" not in rule.scope:
                continue
            for line, snippet in line_matches(text, rule.pattern):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message.format(asset=skill.name),
                        target_type="skill",
                        target_id=skill.asset_id,
                        evidence=Evidence(path=str(file_path), line=line, snippet=snippet),
                        remediation=rule.remediation,
                        confidence=rule.confidence,
                    )
                )
    return findings


def _skill_heuristics(skill: SkillAsset) -> list[Finding]:
    findings: list[Finding] = []
    if skill.script_files and not skill.dependency_files:
        findings.append(
            Finding(
                rule_id="TF-SKILL-SCRIPTS-NO-DEPS",
                title="Skill contains executable scripts without dependency manifest",
                severity="low",
                category="supply-chain",
                message=f"Skill '{skill.name}' contains scripts but no dependency manifest.",
                target_type="skill",
                target_id=skill.asset_id,
                evidence=Evidence(path=skill.path),
                remediation="Add a dependency manifest and review script entrypoints.",
                confidence="medium",
            )
        )

    if skill.external_urls:
        non_https = [url for url in skill.external_urls if url.startswith("http://")]
        if non_https:
            findings.append(
                Finding(
                    rule_id="TF-SKILL-CLEARTEXT-URL",
                    title="Skill references cleartext URLs",
                    severity="medium",
                    category="network",
                    message=f"Skill '{skill.name}' references cleartext URLs.",
                    target_type="skill",
                    target_id=skill.asset_id,
                    evidence=Evidence(path=skill.path, snippet=", ".join(non_https[:5])),
                    remediation="Use HTTPS sources and pin exact versions or content hashes.",
                    confidence="medium",
                )
            )
    return findings


def _safe_skill_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.stat().st_size > 2_000_000:
            continue
        if path.suffix.lower() in {".md", ".txt", ".py", ".js", ".mjs", ".ts", ".sh", ".json", ".toml", ".yaml", ".yml"}:
            yield path


def _analyze_config_parse_errors(inventory: Inventory) -> list[Finding]:
    findings = []
    for config in inventory.agent_configs:
        if config.exists and config.parse_status == "error":
            findings.append(
                Finding(
                    rule_id="TF-CONFIG-PARSE-ERROR",
                    title="Agent config could not be parsed",
                    severity="low",
                    category="inventory",
                    message=f"Could not parse {config.client} config at {config.path}: {config.error}",
                    target_type="agent_config",
                    target_id=config.path,
                    evidence=Evidence(path=config.path),
                    remediation="Fix the config syntax so ToolFence can inventory it.",
                    confidence="high",
                )
            )
    return findings


def _matches_any(asset: McpServer | SkillAsset, entries: list[ListEntry]) -> bool:
    return any(_matches_entry(asset, entry) for entry in entries)


def _matches_entry(asset: McpServer | SkillAsset, entry: ListEntry) -> bool:
    for key, pattern in entry.match.items():
        value = _asset_value(asset, key)
        if value is None:
            return False
        if not re.search(pattern, value, re.IGNORECASE):
            return False
    return True


def _asset_value(asset: McpServer | SkillAsset, key: str) -> str | None:
    if isinstance(asset, McpServer):
        values = {
            "name": asset.name,
            "client": asset.client,
            "command": asset.command or "",
            "args": " ".join(asset.args),
            "url": asset.url or "",
            "url_domain": domain_from_url(asset.url or "") or "",
            "package": asset.package or "",
            "transport": asset.transport,
            "capabilities": " ".join(asset.declared_capabilities),
            "fingerprint": asset.fingerprint or "",
        }
        return values.get(key)

    values = {
        "name": asset.name,
        "path": asset.path,
        "source": asset.source,
        "fingerprint": asset.fingerprint or "",
        "dependencies": " ".join(asset.dependencies),
        "urls": " ".join(asset.external_urls),
    }
    return values.get(key)


def _has_pinned_package(package: str | None) -> bool:
    if not package:
        return False
    if package.endswith("@latest"):
        return False
    if "@" not in package:
        return False
    if package.startswith("@"):
        parts = package.rsplit("@", 1)
        return len(parts) == 2 and bool(parts[1])
    return True

