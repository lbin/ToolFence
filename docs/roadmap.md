# Roadmap

## V1: Inventory and Scanner

- Endpoint discovery for common agent clients.
- MCP config normalization.
- Skill inventory and fingerprinting.
- Open Skill/MCP allowlist and blocklist.
- Risk signatures and heuristics.
- JSON and SARIF reports.
- GitHub Action and pre-commit integration.

## V1.1: Better Supply Chain Evidence

- Signed registry releases.
- Lockfile extraction for skill dependencies.
- Package provenance hints for npm, PyPI, GitHub releases, and local paths.
- Semantic diff for skill instruction changes.
- Baseline comparison to detect unexpected endpoint drift.

## V0.2: Runtime Policy Core

- ClawGuard-inspired command/file/network runtime policy.
- Command obfuscation normalization and detection.
- Pre-execution script static analysis.
- Bidirectional sanitizer for runtime data and audit logs.
- JSONL audit logger.
- Approval queue and panic primitives for future UI/API integrations.
- `toolfence runtime check` CLI.

## V0.3: MCP Proxy Policy Engine

- MCP JSON-RPC `tools/list` filtering.
- MCP JSON-RPC `tools/call` evaluation.
- Tool classifiers for shell, file, and network operations.
- MCP error responses for deny and approval decisions.
- Default proxy policy in `rules/proxy/mcp-proxy-policy.json`.
- `toolfence proxy filter-tools` and `toolfence proxy check-call` CLI.

## V2: Runtime Firewall

- MCP proxy for `tools/list` and `tools/call`.
- Discovery-time filtering.
- Invocation-time ABAC/RBAC policy.
- Per-task scoped permission grants.
- Human approval queue.
- Data-flow tracking.
- Replayable audit log.

## V3: Enterprise Control Plane

- Fleet inventory.
- Central policy distribution.
- Endpoint posture dashboard.
- SIEM/SOC export.
- DLP integrations.
- Compliance reporting.
- Risk intelligence feed for MCP servers, skills, and agent tools.
