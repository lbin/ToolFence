# Ruleset and Registry Design

ToolFence keeps policy data outside scanner code so security teams can review,
fork, and update it.

## Signature Rules

`rules/builtin-rules.json` contains regex signatures with:

- `id`
- `title`
- `severity`
- `category`
- `scope`
- `pattern`
- `message`
- `remediation`
- `confidence`

Scopes:

- `skill_file`: scan skill instructions, scripts, manifests, and text files.
- `mcp_command`: scan normalized MCP server name, command, args, URL, and env
  key names.
- `any_file`: additional text-file scope.

## Allowlist Entries

Allowlist entries match normalized asset fields. Supported MCP fields:

- `name`
- `client`
- `command`
- `args`
- `url`
- `url_domain`
- `package`
- `transport`
- `capabilities`
- `fingerprint`

Supported skill fields:

- `name`
- `path`
- `source`
- `fingerprint`
- `dependencies`
- `urls`

Use `--allowlist-mode warn` to surface unknown assets without failing most
workflows. Use `--allowlist-mode enforce --fail-on medium` when registry quality
is strong enough for CI or fleet policy.

## Blocklist Entries

Blocklists use the same match fields, but matches create findings regardless of
allowlist mode.

Prefer entries based on behavior:

- Shell pipe install.
- Public webhook egress.
- Docker socket access.
- Sensitive credential path exposure.
- Temporary or Downloads install path.

Avoid naming a specific open-source project unless there is public evidence and
the entry includes a source reference.

## Contribution Requirements

For allowlist entries:

- Explain what was reviewed.
- Prefer exact version or fingerprint.
- Add maintainer/source metadata when known.
- Include required controls such as read-only, path scope, or egress domain.

For blocklist entries:

- Provide a reproducible match pattern.
- Keep false positives narrow.
- Use severity according to exploitability and blast radius.
- Include rationale in metadata.

