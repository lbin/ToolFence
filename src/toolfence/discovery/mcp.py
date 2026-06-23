from __future__ import annotations

import json
import shlex
import tomllib
from pathlib import Path
from typing import Any

from toolfence.models import AgentConfig, McpServer
from toolfence.utils import domain_from_url, redact_sensitive, stable_json_hash


SERVER_KEYS = ("mcpServers", "mcp_servers", "servers", "context_servers")
SENSITIVE_CAPABILITY_HINTS = {
    "browser": ("browser", "chrome", "playwright", "selenium"),
    "database": ("postgres", "mysql", "sqlite", "snowflake", "bigquery", "database", "db"),
    "email": ("gmail", "mail", "email", "imap", "smtp"),
    "filesystem": ("filesystem", "file", "fs", "path"),
    "github": ("github", "gitlab", "git"),
    "network": ("fetch", "http", "url", "browser", "sse"),
    "shell": ("shell", "bash", "terminal", "exec", "command"),
    "slack": ("slack",),
}


def discover_mcp_servers(agent_configs: list[AgentConfig]) -> list[McpServer]:
    servers: list[McpServer] = []
    for config in agent_configs:
        path = Path(config.path)
        if not config.exists or not path.is_file() or config.kind == "skill_dir":
            continue
        try:
            data = _load_config(path)
            config.parse_status = "ok"
        except Exception as exc:  # noqa: BLE001 - scanner must report and continue.
            config.parse_status = "error"
            config.error = str(exc)
            continue

        extracted = _extract_server_maps(data)
        for name, value in extracted:
            server = _server_from_value(name, value, config.client, config.path)
            if server is not None:
                servers.append(server)
    return servers


def _load_config(path: Path) -> Any:
    suffix = path.suffix.lower()
    with path.open("rb") as handle:
        if suffix == ".toml":
            return tomllib.load(handle)
        return json.load(handle)


def _extract_server_maps(data: Any) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if not isinstance(data, dict):
        return found

    for key in SERVER_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            found.extend((str(name), server) for name, server in value.items())

    mcp_value = data.get("mcp")
    if isinstance(mcp_value, dict):
        for key in SERVER_KEYS:
            value = mcp_value.get(key)
            if isinstance(value, dict):
                found.extend((str(name), server) for name, server in value.items())

    return found


def _server_from_value(name: str, value: Any, client: str, config_path: str) -> McpServer | None:
    if isinstance(value, str):
        value = {"url": value}
    if not isinstance(value, dict):
        return None

    command = _string_or_none(value.get("command") or value.get("cmd"))
    args = _string_list(value.get("args") or value.get("arguments") or [])
    url = _string_or_none(value.get("url") or value.get("endpoint"))
    transport = _transport(value, command, url)
    env = value.get("env") if isinstance(value.get("env"), dict) else {}
    raw = redact_sensitive(value)
    package = infer_package(command, args)
    capabilities = infer_capabilities(name, command, args, url)
    server = McpServer(
        name=name,
        client=client,
        config_path=config_path,
        transport=transport,
        command=command,
        args=args,
        url=url,
        env_keys=sorted(str(key) for key in env.keys()),
        package=package,
        declared_capabilities=capabilities,
        raw=raw,
    )
    server.fingerprint = stable_json_hash(
        {
            "name": name,
            "client": client,
            "transport": transport,
            "command": command,
            "args": args,
            "url_domain": domain_from_url(url) if url else None,
            "env_keys": server.env_keys,
            "package": package,
        }
    )
    return server


def _transport(value: dict[str, Any], command: str | None, url: str | None) -> str:
    declared = _string_or_none(value.get("transport") or value.get("type"))
    if declared:
        lowered = declared.lower()
        if "sse" in lowered:
            return "sse"
        if "streamable" in lowered:
            return "streamable-http"
        if "http" in lowered:
            return "http"
        if "stdio" in lowered:
            return "stdio"
        return lowered
    if command:
        return "stdio"
    if url and "sse" in url.lower():
        return "sse"
    if url:
        return "http"
    return "unknown"


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            return shlex.split(value)
        except ValueError:
            return [value]
    return []


def infer_package(command: str | None, args: list[str]) -> str | None:
    if not command:
        return None
    executable = Path(command).name.lower()
    launchers = {"npx", "pnpm", "yarn", "bunx", "uvx", "pipx"}
    if executable not in launchers:
        return None

    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in {"--package", "-p"}:
            skip_next = True
            continue
        if arg in {"--yes", "-y", "dlx", "exec", "run"}:
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def infer_capabilities(name: str, command: str | None, args: list[str], url: str | None) -> list[str]:
    haystack = " ".join(item for item in [name, command or "", *(args or []), url or ""] if item).lower()
    capabilities = []
    for capability, hints in SENSITIVE_CAPABILITY_HINTS.items():
        if any(hint in haystack for hint in hints):
            capabilities.append(capability)
    if url:
        capabilities.append("network")
    return sorted(set(capabilities))
