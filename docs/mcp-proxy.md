# MCP Proxy Policy Engine

ToolFence v0.3.0 adds the first executable slice of the V2 runtime firewall:
an MCP JSON-RPC policy engine.

It does not yet run a long-lived stdio, SSE, or streamable HTTP proxy. Instead,
it provides the core decision layer that those transports need:

- `tools/list` response filtering.
- `tools/call` request evaluation.
- Tool-call classification into runtime event kinds.
- Reuse of the v0.2 runtime command/file/network engine.
- MCP JSON-RPC error response generation for deny and approval decisions.

## Commands

Filter a `tools/list` response:

```bash
toolfence proxy filter-tools \
  --message examples/mcp-tools-list-response.json \
  --format json
```

Evaluate a `tools/call` request:

```bash
toolfence proxy check-call \
  --message examples/mcp-tool-call-shell.json \
  --emit-error-response \
  --format json
```

Default policies:

- `rules/proxy/mcp-proxy-policy.json`
- `rules/runtime/clawguard-runtime.json`

## Discovery-Time Filtering

The proxy policy can hide tools before the model sees them. This matters because
models plan with the tools exposed during discovery. Hiding risky tools is
stronger than showing the tool and hoping the model does not call it.

The default policy hides:

- Shell/terminal/exec style tools.
- Credential, password, token, and keychain tools.
- Destructive delete/remove/wipe tools.

## Invocation-Time Policy

For `tools/call`, ToolFence checks proxy-level rules first. Examples:

- `send_email` requires approval.
- `git_push` and PR merge tools require approval.
- Security-bypass tools are denied.

If a tool matches a classifier, ToolFence converts the MCP call into a runtime
event and delegates to the v0.2 runtime engine. For example:

- `execute_command` maps to shell command policy.
- `read_file` maps to file path policy.
- `write_file` maps to file write policy.
- `fetch` and `http_request` map to network policy.

## Next Step

The next implementation step is transport binding:

- stdio MCP proxy.
- SSE / streamable HTTP MCP proxy.
- persisted audit stream for discovery and invocation events.
- approval queue integration.

