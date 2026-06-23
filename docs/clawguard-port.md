# ClawGuard Capability Port

ToolFence v0.2.0 ports the useful security ideas from
[ClawGuard](https://github.com/Claw-Guard/ClawGuard) into a client-neutral
runtime core.

ClawGuard is OpenClaw-focused and runs as a sidecar daemon with `cg_*` tools,
approval queue, sanitizer, audit log, panic mode, and command/file/network
rules. ToolFence keeps the same control-plane direction but avoids binding the
implementation to OpenClaw. The v0.2.0 port is a reusable runtime policy engine
for the future MCP proxy/firewall.

## Ported Capabilities

- Command rules: blacklist, whitelist, and require-approval regex buckets.
- File controls: denied sensitive paths, sensitive filename patterns, and
  write-outside-scope approval.
- Network controls: domain allowlist, domain blocklist, and default approval for
  unknown destinations.
- Command normalization: command substitution, IFS abuse, escaped payloads,
  base64 decode pipelines, and eval-style obfuscation.
- Script analysis: pre-execution static checks for Python, shell, and generic
  script content.
- Sanitizer: secret/token/key redaction for runtime inputs, outputs, and audit.
- Audit: JSONL event records suitable for local review and enterprise shipping.
- Approval primitives: local queue model for future UI/API integrations.
- Panic primitive: emergency block-all state model.

## Deliberate Differences

- No OpenClaw plugin is vendored.
- No FastAPI daemon or dashboard is introduced in v0.2.0.
- Runtime policy is JSON, matching the rest of ToolFence's zero-dependency
  scanner and registry.
- CLI `toolfence runtime check` is the executable contract for now; the same
  engine will back the future MCP proxy.

## New Files

- `src/toolfence/runtime/engine.py`
- `src/toolfence/runtime/sanitizer.py`
- `src/toolfence/runtime/normalizer.py`
- `src/toolfence/runtime/script_analyzer.py`
- `src/toolfence/runtime/audit.py`
- `src/toolfence/runtime/approval.py`
- `src/toolfence/runtime/panic.py`
- `rules/runtime/clawguard-runtime.json`

## CLI

```bash
toolfence runtime check \
  --policy rules/runtime/clawguard-runtime.json \
  --event examples/runtime-event.json \
  --audit-log reports/runtime-audit.jsonl
```

Exit codes:

- `0`: allow or log.
- `1`: deny.
- `2`: require approval.

