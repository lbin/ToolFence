# Third-Party Notices

## ClawGuard

ToolFence v0.2.0 includes a client-neutral runtime policy core inspired by
ClawGuard's public design and source code:

- Repository: https://github.com/Claw-Guard/ClawGuard
- Reviewed commit: `348779084dfbc8935e072f751ddaea55653c0976`
- Declared license in `pyproject.toml`: MIT

ToolFence does not vendor the OpenClaw plugin, daemon, dashboard, or source tree.
The port keeps the concepts that fit ToolFence's control-plane roadmap:
command/file/network decisions, sanitizer, audit, approval, panic, command
normalization, and script analysis.

