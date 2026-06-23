from __future__ import annotations

import argparse
import sys
from pathlib import Path

from toolfence import __version__
from toolfence.analyzers import analyze_inventory
from toolfence.analyzers.registry import validate_registry
from toolfence.discovery import collect_inventory
from toolfence.firewall import evaluate_event
from toolfence.models import ScanReport, severity_at_least, summarize_findings
from toolfence.reporting import report_to_json, report_to_sarif, report_to_summary


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "rules":
        return _rules(args)
    if args.command == "firewall":
        return _firewall(args)
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


if __name__ == "__main__":
    raise SystemExit(main())

