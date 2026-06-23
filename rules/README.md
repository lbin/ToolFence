# ToolFence Open Registry

This directory is the open registry for Skill/MCP security controls.

The intent is to make allowlist and blocklist data reviewable in source control:

- `allowlist/mcp-servers.json`: reviewed MCP server patterns.
- `blocklist/mcp-servers.json`: denied or high-risk MCP server behavior patterns.
- `allowlist/skills.json`: reviewed skill paths or exact fingerprints.
- `blocklist/skills.json`: denied or high-risk skill provenance patterns.
- `builtin-rules.json`: regex signature rules used by the V1 scanner.
- `policies/runtime-default.json`: starter policy template for the future runtime firewall.
- `runtime/clawguard-runtime.json`: v0.2 runtime policy template for command,
  file, network, sanitizer, task-scope, and panic checks inspired by ClawGuard.

Allowlist entries should become more exact over time. For enterprise enforcement,
prefer exact fingerprints, signed release provenance, owner metadata, declared
capabilities, version pins, and date of last review.

Blocklist entries should prefer behavior and indicators that can be verified
without accusing a specific open-source project unless there is public evidence.
