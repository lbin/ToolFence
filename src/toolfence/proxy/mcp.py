from __future__ import annotations

from typing import Any

from toolfence.proxy.models import ProxyDecision, ProxyResult
from toolfence.proxy.policy import McpProxyPolicy
from toolfence.runtime import RuntimeEngine


class McpProxy:
    def __init__(self, proxy_policy: McpProxyPolicy, runtime_engine: RuntimeEngine):
        self.proxy_policy = proxy_policy
        self.runtime_engine = runtime_engine

    def filter_tools_response(self, message: dict[str, Any]) -> ProxyResult:
        tools = message.get("result", {}).get("tools")
        if not isinstance(tools, list):
            return ProxyResult(message=message)

        filtered = []
        decisions: list[ProxyDecision] = []
        for tool in tools:
            decision = self._discovery_decision(tool)
            if decision.action == "hide":
                decisions.append(decision)
                continue
            filtered.append(tool)
            if decision.action != "show":
                decisions.append(decision)

        updated = dict(message)
        result = dict(updated.get("result", {}))
        result["tools"] = filtered
        updated["result"] = result
        return ProxyResult(message=updated, decisions=decisions)

    def evaluate_tool_call_request(self, message: dict[str, Any]) -> ProxyDecision:
        if message.get("method") != "tools/call":
            return ProxyDecision("allow", "not a tools/call request", "TF-PROXY-NON-TOOL-CALL")
        params = message.get("params", {})
        name = str(params.get("name", ""))
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}

        for rule in self.proxy_policy.invocation_deny:
            if rule.matches_call(name, arguments):
                return ProxyDecision("deny", rule.reason, rule.rule_id, tool_name=name)

        for rule in self.proxy_policy.invocation_approval:
            if rule.matches_call(name, arguments):
                return ProxyDecision("require_approval", rule.reason, rule.rule_id, tool_name=name)

        event = self._runtime_event(name, arguments)
        if event is None:
            return ProxyDecision("allow", "tool call has no runtime classifier", "TF-PROXY-UNCLASSIFIED-TOOL", tool_name=name)
        runtime_decision = self.runtime_engine.evaluate(event)
        return ProxyDecision(
            action=runtime_decision.decision,
            reason=runtime_decision.reason,
            rule_id=runtime_decision.rule_id or "TF-PROXY-RUNTIME",
            tool_name=name,
            runtime_decision=runtime_decision,
        )

    def denied_response(self, request: dict[str, Any], decision: ProxyDecision) -> dict[str, Any]:
        code = -32001 if decision.action == "deny" else -32002
        return {
            "jsonrpc": request.get("jsonrpc", "2.0"),
            "id": request.get("id"),
            "error": {
                "code": code,
                "message": "ToolFence denied tool call" if decision.action == "deny" else "ToolFence requires approval",
                "data": decision.to_dict(),
            },
        }

    def _discovery_decision(self, tool: dict[str, Any]) -> ProxyDecision:
        name = str(tool.get("name", ""))
        for rule in self.proxy_policy.discovery_deny:
            if rule.matches_tool(tool):
                return ProxyDecision("hide", rule.reason, rule.rule_id, tool_name=name)

        if self.proxy_policy.default_visibility == "hide_unknown":
            for rule in self.proxy_policy.discovery_allow:
                if rule.matches_tool(tool):
                    return ProxyDecision("show", rule.reason, rule.rule_id, tool_name=name)
            return ProxyDecision("hide", "tool is not in discovery allowlist", "TF-PROXY-TOOL-NOT-ALLOWLISTED", tool_name=name)

        return ProxyDecision("show", "tool visible by default", "TF-PROXY-DISCOVERY-DEFAULT", tool_name=name)

    def _runtime_event(self, name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        for classifier in self.proxy_policy.classifiers:
            if not classifier.matches(name):
                continue
            value = _first_argument(arguments, classifier.argument_keys)
            tool: dict[str, Any] = {
                "kind": classifier.kind,
                "name": name,
                "arguments": arguments,
            }
            if classifier.kind in {"shell", "command"}:
                tool["command"] = str(value or "")
            elif classifier.kind in {"file_read", "file_write", "read", "write", "edit"}:
                tool["path"] = str(value or "")
            elif classifier.kind in {"http_request", "network", "browser"}:
                tool["url"] = str(value or "")
                tool["body"] = arguments.get("body") or arguments.get("content")
            else:
                tool["input"] = str(value or "")
            return {"tool": tool}
        return None


def _first_argument(arguments: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in arguments:
            return arguments[key]
    return None

