# ToolFence

Secure every tool call your AI agent makes.

ToolFence is an endpoint security control plane for AI agent tools, MCP servers,
and skills. V1 is an open-source scanner that inventories local agent tooling,
builds a Skill/MCP SBOM, applies risk rules, and emits JSON/SARIF reports that
can feed CI, pre-commit, or an enterprise console.

The scanner is deliberately shaped for the future runtime firewall: the same
asset model, allowlist, blocklist, capability metadata, and policy templates can
be reused when tool discovery and tool invocation are proxied.

## What V1 Covers

- Agent configs for Claude Desktop, Claude Code, Cursor, Windsurf, Codex,
  Gemini CLI, Amazon Q, and project-local MCP config files.
- MCP transports: stdio, SSE, streamable HTTP, and HTTP-style endpoints.
- Skill directories with instructions, scripts, dependencies, embedded URLs,
  and content fingerprints.
- Sensitive local path risk: `.ssh`, `.aws`, `.env`, Git credentials, browser
  profiles, Keychain references, Docker socket, and similar endpoint assets.
- Tool poisoning and shadowing signals: duplicate server names, shell wrappers,
  unpinned package launchers, broad filesystem scope, cleartext remote MCP.
- Prompt-injection-like hidden instructions, hardcoded secrets, dangerous shell
  commands, mutable remote code fetches, and egress sinks.
- Open allowlist/blocklist registry for Skill/MCP supply-chain governance.
- JSON and SARIF output for automation.

## Install

```bash
python -m pip install -e .
```

No runtime dependencies are required beyond Python 3.11+.

## Quick Start

Scan the current repo plus default endpoint agent locations:

```bash
toolfence scan
```

Generate a machine-readable SBOM and finding report:

```bash
toolfence scan --format json --output reports/toolfence.json
```

Generate SARIF for GitHub code scanning:

```bash
toolfence scan --format sarif --output toolfence-results.sarif --fail-on high
```

Scan only one supplied MCP config:

```bash
toolfence scan --no-default-paths --include examples/sample-mcp-config.json
```

Enforce an organization allowlist:

```bash
toolfence scan --allowlist-mode enforce --fail-on medium
```

Validate the open registry:

```bash
toolfence rules validate
```

Evaluate one future-firewall event against a starter runtime policy:

```bash
toolfence firewall check \
  --policy rules/policies/runtime-default.json \
  --event examples/runtime-event.json
```

Evaluate a ClawGuard-style runtime tool-call event:

```bash
toolfence runtime check \
  --policy rules/runtime/clawguard-runtime.json \
  --event examples/runtime-event.json \
  --audit-log reports/runtime-audit.jsonl
```

## Outputs

The JSON report contains:

- `inventory.agent_configs`: discovered agent config files and parse status.
- `inventory.mcp_servers`: normalized MCP server SBOM with transport, command,
  args, URL domain, env key names, package hints, capabilities, and fingerprint.
- `inventory.skills`: skill SBOM with instruction files, scripts, dependency
  manifests, dependencies, URLs, file count, and fingerprint.
- `findings`: rule id, severity, category, asset id, evidence, remediation.
- `summary`: counts by severity and a capped endpoint risk score.

SARIF output maps ToolFence findings to GitHub code scanning and other SARIF
consumers.

## Open Registry

The open registry lives in `rules/`:

- `rules/allowlist/mcp-servers.json`
- `rules/blocklist/mcp-servers.json`
- `rules/allowlist/skills.json`
- `rules/blocklist/skills.json`
- `rules/builtin-rules.json`
- `rules/policies/runtime-default.json`
- `rules/runtime/clawguard-runtime.json`

Allowlist entries are intentionally review-oriented. In real enterprise use,
prefer exact fingerprints, signed releases, internal package mirrors, code
owners, declared capabilities, version pins, and last-reviewed dates.

Blocklist entries should favor verifiable behavior and indicators: public
webhook egress, shell pipe install, Docker socket access, sensitive home paths,
temporary install directories, and similar signals.

## Integrations

Pre-commit:

```yaml
repos:
  - repo: https://github.com/toolfence/toolfence
    rev: v0.1.0
    hooks:
      - id: toolfence-scan
```

GitHub Action:

```yaml
- uses: toolfence/toolfence@v0.1.0
  with:
    root: "."
    format: "sarif"
    output: "toolfence-results.sarif"
    fail-on: "high"
```

## Architecture

See:

- `docs/architecture.md`
- `docs/clawguard-port.md`
- `docs/threat-model.md`
- `docs/ruleset.md`
- `docs/roadmap.md`

## Status

This is an alpha V1 scanner and registry. It is useful for inventory, risk
review, CI checks, and policy prototyping. Runtime blocking requires the V2 MCP
proxy/firewall layer described in the architecture docs.
