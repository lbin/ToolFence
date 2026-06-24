from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from toolfence import __version__
from toolfence.analyzers import analyze_inventory
from toolfence.analyzers.registry import validate_registry
from toolfence.discovery import collect_inventory
from toolfence.firewall import evaluate_event
from toolfence.models import ScanReport, severity_at_least, summarize_findings
from toolfence.proxy import McpProxy, McpProxyPolicy
from toolfence.reporting import report_to_json, report_to_sarif, report_to_summary
from toolfence.runtime import AuditLogger, RuntimeEngine


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "rules":
        return _rules(args)
    if args.command == "firewall":
        return _firewall(args)
    if args.command == "runtime":
        return _runtime(args)
    if args.command == "proxy":
        return _proxy(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolfence",
        description="Inventory and risk scan AI agent MCP servers and skills.",
    )
    parser.add_argument("--version", action="version", version=f"toolfence {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan endpoint agent configs, MCP servers, and skills.")
    scan.add_argument("--root", action="append", default=[], help="Project root to scan. Defaults to cwd.")
    scan.add_argument("--home", default=str(Path.home()), help="Home directory used for endpoint config discovery.")
    scan.add_argument("--include", action="append", default=[], help="Extra config file or skill directory to include.")
    scan.add_argument("--rules-dir", default=None, help="Rules directory. Defaults to repository rules/.")
    scan.add_argument("--format", choices=("summary", "json", "sarif"), default="summary")
    scan.add_argument("--output", help="Write report to this path instead of stdout.")
    scan.add_argument("--allowlist-mode", choices=("off", "warn", "enforce"), default="off")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info"), help="Exit 1 on this severity or higher.")
    scan.add_argument("--max-file-bytes", type=int, default=250_000)
    scan.add_argument("--no-default-paths", action="store_true", help="Only scan --root and --include paths.")

    rules = subparsers.add_parser("rules", help="Validate or list the open rules registry.")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    validate = rules_sub.add_parser("validate", help="Validate rules, allowlist, and blocklist files.")
    validate.add_argument("--rules-dir", default=None)
    list_cmd = rules_sub.add_parser("list", help="Print the resolved rules directory.")
    list_cmd.add_argument("--rules-dir", default=None)

    firewall = subparsers.add_parser("firewall", help="Evaluate a tool-call event against a JSON policy template.")
    firewall_sub = firewall.add_subparsers(dest="firewall_command", required=True)
    check = firewall_sub.add_parser("check", help="Check one event JSON file.")
    check.add_argument("--policy", required=True)
    check.add_argument("--event", required=True)

    runtime = subparsers.add_parser("runtime", help="Evaluate runtime tool-call events with ToolFence v0.2 policy.")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_check = runtime_sub.add_parser("check", help="Check one runtime tool-call event JSON file.")
    runtime_check.add_argument("--policy", default=None, help="Runtime policy JSON. Defaults to rules/runtime/clawguard-runtime.json.")
    runtime_check.add_argument("--event", required=True, help="Runtime event JSON file.")
    runtime_check.add_argument("--cwd", default=None, help="Working directory used to resolve relative script/file paths.")
    runtime_check.add_argument("--audit-log", help="Append sanitized runtime decision to this JSONL audit log.")
    runtime_check.add_argument("--format", choices=("summary", "json"), default="summary")

    proxy = subparsers.add_parser("proxy", help="Evaluate MCP JSON-RPC messages with the v0.3 proxy policy engine.")
    proxy_sub = proxy.add_subparsers(dest="proxy_command", required=True)
    filter_tools = proxy_sub.add_parser("filter-tools", help="Filter an MCP tools/list response.")
    filter_tools.add_argument("--message", required=True, help="MCP tools/list response JSON.")
    filter_tools.add_argument("--proxy-policy", default=None, help="Proxy policy JSON. Defaults to rules/proxy/mcp-proxy-policy.json.")
    filter_tools.add_argument("--runtime-policy", default=None, help="Runtime policy JSON used to initialize the proxy.")
    filter_tools.add_argument("--format", choices=("summary", "json"), default="summary")
    check_call = proxy_sub.add_parser("check-call", help="Evaluate an MCP tools/call request.")
    check_call.add_argument("--message", required=True, help="MCP tools/call request JSON.")
    check_call.add_argument("--proxy-policy", default=None)
    check_call.add_argument("--runtime-policy", default=None)
    check_call.add_argument("--cwd", default=None)
    check_call.add_argument("--emit-error-response", action="store_true", help="Include MCP JSON-RPC error response in JSON output.")
    check_call.add_argument("--format", choices=("summary", "json"), default="summary")
    return parser


def _scan(args: argparse.Namespace) -> int:
    roots = [Path(item).expanduser().resolve() for item in args.root] or [Path.cwd().resolve()]
    include_paths = [Path(item).expanduser().resolve() for item in args.include]
    home = Path(args.home).expanduser().resolve()
    rules_dir = _rules_dir(args.rules_dir)

    inventory = collect_inventory(
        home=home,
        roots=roots,
        include_paths=include_paths,
        max_file_bytes=args.max_file_bytes,
        use_default_paths=not args.no_default_paths,
    )
    findings = analyze_inventory(
        inventory=inventory,
        rules_dir=rules_dir,
        allowlist_mode=args.allowlist_mode,
        max_file_bytes=args.max_file_bytes,
    )
    report = ScanReport(
        schema_version="toolfence.report.v1",
        tool={"name": "ToolFence", "version": __version__},
        inventory=inventory,
        findings=findings,
        summary=summarize_findings(inventory, findings),
    )
    rendered = _render_report(report, args.format)
    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if args.fail_on and any(severity_at_least(finding.severity, args.fail_on) for finding in findings):
        return 1
    return 0


def _rules(args: argparse.Namespace) -> int:
    rules_dir = _rules_dir(args.rules_dir)
    if args.rules_command == "list":
        print(rules_dir)
        return 0
    errors = validate_registry(rules_dir)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"Rules registry is valid: {rules_dir}")
    return 0


def _firewall(args: argparse.Namespace) -> int:
    if args.firewall_command != "check":
        return 2
    decision = evaluate_event(Path(args.policy), Path(args.event))
    print(f"{decision.decision.upper()}: {decision.reason}" + (f" ({decision.rule_id})" if decision.rule_id else ""))
    return 1 if decision.decision == "deny" else 0


def _runtime(args: argparse.Namespace) -> int:
    if args.runtime_command != "check":
        return 2
    policy_path = _runtime_policy_path(args.policy)
    event_path = Path(args.event).expanduser()
    with event_path.open("r", encoding="utf-8") as handle:
        event = json.load(handle)
    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else Path.cwd().resolve()
    engine = RuntimeEngine.from_file(policy_path, cwd=cwd)
    decision = engine.evaluate(event)

    if args.audit_log:
        AuditLogger(Path(args.audit_log), sanitizer=engine.sanitizer).append(event, decision)

    if args.format == "json":
        print(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"{decision.decision.upper()}: {decision.reason}" + (f" ({decision.rule_id})" if decision.rule_id else ""))
        if decision.findings:
            print("Findings:")
            for finding in decision.findings:
                print(f"- [{finding.severity}] {finding.category}: {finding.reason}")

    if decision.decision == "deny":
        return 1
    if decision.decision == "require_approval":
        return 2
    return 0


def _proxy(args: argparse.Namespace) -> int:
    message_path = Path(args.message).expanduser()
    with message_path.open("r", encoding="utf-8") as handle:
        message = json.load(handle)
    proxy = _build_proxy(args)

    if args.proxy_command == "filter-tools":
        result = proxy.filter_tools_response(message)
        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            tools = result.message.get("result", {}).get("tools", [])
            print(f"VISIBLE_TOOLS: {len(tools)}")
            if result.decisions:
                print("Filtered:")
                for decision in result.decisions:
                    print(f"- {decision.tool_name}: {decision.reason} ({decision.rule_id})")
        return 0

    if args.proxy_command == "check-call":
        decision = proxy.evaluate_tool_call_request(message)
        payload = {"decision": decision.to_dict()}
        if args.emit_error_response and decision.action in {"deny", "require_approval"}:
            payload["error_response"] = proxy.denied_response(message, decision)
        if args.format == "json":
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"{decision.action.upper()}: {decision.reason} ({decision.rule_id})")
            if decision.action in {"deny", "require_approval"} and args.emit_error_response:
                print(json.dumps(proxy.denied_response(message, decision), indent=2, ensure_ascii=False))
        if decision.action == "deny":
            return 1
        if decision.action == "require_approval":
            return 2
        return 0

    return 2


def _build_proxy(args: argparse.Namespace) -> McpProxy:
    cwd = Path(getattr(args, "cwd", None)).expanduser().resolve() if getattr(args, "cwd", None) else Path.cwd().resolve()
    proxy_policy = McpProxyPolicy.from_file(_proxy_policy_path(getattr(args, "proxy_policy", None)))
    runtime_engine = RuntimeEngine.from_file(_runtime_policy_path(getattr(args, "runtime_policy", None)), cwd=cwd)
    return McpProxy(proxy_policy, runtime_engine)


def _render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return report_to_json(report)
    if output_format == "sarif":
        return report_to_sarif(report)
    return report_to_summary(report)


def _rules_dir(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    candidate = Path(__file__).resolve().parents[2] / "rules"
    if candidate.exists():
        return candidate
    cwd_candidate = Path.cwd() / "rules"
    if cwd_candidate.exists():
        return cwd_candidate.resolve()
    return candidate


def _runtime_policy_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    rules_dir = _rules_dir(None)
    return rules_dir / "runtime" / "clawguard-runtime.json"


def _proxy_policy_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    rules_dir = _rules_dir(None)
    return rules_dir / "proxy" / "mcp-proxy-policy.json"


if __name__ == "__main__":
    raise SystemExit(main())
