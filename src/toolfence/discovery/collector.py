from __future__ import annotations

from pathlib import Path

from toolfence.discovery.clients import discover_agent_configs
from toolfence.discovery.mcp import discover_mcp_servers
from toolfence.discovery.skills import discover_skills
from toolfence.models import Inventory
from toolfence.utils import hostname, now_iso, platform_label


def collect_inventory(
    home: Path,
    roots: list[Path],
    include_paths: list[Path] | None = None,
    max_file_bytes: int = 250_000,
    use_default_paths: bool = True,
) -> Inventory:
    agent_configs = discover_agent_configs(home, roots, include_paths, use_default_paths)
    mcp_servers = discover_mcp_servers(agent_configs)
    skills = discover_skills(home, roots, include_paths, max_file_bytes, use_default_paths)
    return Inventory(
        generated_at=now_iso(),
        hostname=hostname(),
        platform=platform_label(),
        home=str(home),
        roots=[str(root) for root in roots],
        agent_configs=agent_configs,
        mcp_servers=mcp_servers,
        skills=skills,
    )

