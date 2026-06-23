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

