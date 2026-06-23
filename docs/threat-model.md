# Threat Model

ToolFence focuses on endpoint agent capabilities, not generic LLM text
classification.

## Assets

- Source code, private repositories, customer data, tickets, documents, and
  internal APIs.
- Credentials in `.ssh`, `.aws`, `.env`, `.netrc`, Git credential stores,
  browser profiles, Keychain references, Docker config, Kubernetes config, and
  package-manager credentials.
- Agent tool configuration, MCP server definitions, skills, scripts, prompts,
  dependencies, and update channels.

## Attackers

- Malicious or compromised MCP server maintainer.
- Malicious skill author or skill update.
- Typosquatted package launched through `npx`, `uvx`, `pipx`, or similar.
- Prompt-injected content that convinces the agent to call risky tools.
- Insider or compromised endpoint trying to exfiltrate code or credentials.

## Primary Risks

- Tool poisoning: a tool description or skill instruction changes the model's
  behavior or hides malicious behavior.
- Tool shadowing: a malicious server uses a trusted-looking name.
- Overbroad local access: filesystem tools expose home directories or credential
  paths.
- Secret forwarding: credentials or private repo content are sent to external
  domains.
- Mutable supply chain: tools launch unpinned packages or fetch remote scripts.
- Runtime privilege escalation: shell, Docker socket, browser profile, email,
  GitHub, database, or internal admin tools are used without scoped policy.

## V1 Controls

- Inventory all known agent configs and skill roots.
- Normalize MCP server transport, command, args, URL, env key names, package
  hints, and declared capabilities.
- Fingerprint skills and configs to detect drift.
- Apply open signatures, blocklists, and allowlist enforcement mode.
- Emit SARIF/JSON for CI, pre-commit, and endpoint fleet aggregation.

## Required V2 Controls

- Intercept MCP tool discovery and invocation.
- Filter tools before they are exposed to the model.
- Deny, downgrade, or require approval for high-risk calls.
- Track source-to-destination data flow.
- Record audit events that can answer who, what, when, why, source data, tool,
  destination, decision, and result.

## Non-goals

- ToolFence V1 is not a malware sandbox.
- ToolFence V1 does not prove that a skill is safe.
- ToolFence V1 does not block runtime calls unless paired with a future proxy or
  an external enforcement layer.
- Prompt-injection signatures are supporting signals, not the product core.

