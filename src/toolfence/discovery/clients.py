from __future__ import annotations

from pathlib import Path

from toolfence.models import AgentConfig
from toolfence.utils import expand_path, sha256_file


CONFIG_CANDIDATES: tuple[tuple[str, str, str], ...] = (
    ("Claude Desktop", "mcp_config", "~/Library/Application Support/Claude/claude_desktop_config.json"),
    ("Claude Desktop", "mcp_config", "~/.config/Claude/claude_desktop_config.json"),
    ("Claude Code", "mcp_config", "~/.claude.json"),
    ("Claude Code", "mcp_config", "~/.claude/settings.json"),
    ("Claude Code", "mcp_config", "~/.claude/mcp.json"),
    ("Claude Code", "mcp_config", "~/.config/claude-code/mcp.json"),
    ("Cursor", "mcp_config", "~/.cursor/mcp.json"),
    ("Cursor", "settings", "~/.cursor/config.json"),
    ("Cursor", "settings", "~/Library/Application Support/Cursor/User/settings.json"),
    ("Windsurf", "mcp_config", "~/.codeium/windsurf/mcp_config.json"),
    ("Windsurf", "settings", "~/Library/Application Support/Windsurf/User/settings.json"),
    ("Codex", "settings", "~/.codex/config.toml"),
    ("Codex", "mcp_config", "~/.codex/mcp.json"),
    ("Gemini CLI", "settings", "~/.gemini/settings.json"),
    ("Gemini CLI", "mcp_config", "~/.gemini/mcp.json"),
    ("Amazon Q", "mcp_config", "~/.aws/amazonq/mcp.json"),
    ("Amazon Q", "mcp_config", "~/.config/amazonq/mcp.json"),
)

PROJECT_CONFIGS: tuple[tuple[str, str], ...] = (
    ("Project", ".mcp.json"),
    ("Project", "mcp.json"),
    ("Project", ".cursor/mcp.json"),
    ("Project", ".vscode/mcp.json"),
    ("Project", ".claude/mcp.json"),
    ("Project", ".codex/mcp.json"),
    ("Project", "claude_desktop_config.json"),
)


def discover_agent_configs(
    home: Path,
    roots: list[Path],
    include_paths: list[Path] | None = None,
    use_default_paths: bool = True,
) -> list[AgentConfig]:
    configs: dict[str, AgentConfig] = {}

    if use_default_paths:
        for client, kind, candidate in CONFIG_CANDIDATES:
            path = expand_path(candidate, home)
            _add_config(configs, client, kind, path)

        for root in roots:
            for client, relative in PROJECT_CONFIGS:
                _add_config(configs, client, "mcp_config", root / relative)

    for include_path in include_paths or []:
        client = "Included"
        kind = "skill_dir" if include_path.is_dir() else "mcp_config"
        _add_config(configs, client, kind, include_path)

    return sorted(configs.values(), key=lambda item: (item.client, item.path))


def _add_config(configs: dict[str, AgentConfig], client: str, kind: str, path: Path) -> None:
    resolved = str(path)
    exists = path.exists()
    fingerprint = None
    if exists and path.is_file():
        try:
            fingerprint = sha256_file(path)
        except OSError:
            fingerprint = None
    configs[resolved] = AgentConfig(
        client=client,
        path=resolved,
        kind=kind,
        exists=exists,
        fingerprint=fingerprint,
    )

