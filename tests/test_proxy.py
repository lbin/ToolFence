from __future__ import annotations

import json
import unittest
from pathlib import Path

from toolfence.proxy import McpProxy, McpProxyPolicy
from toolfence.runtime import RuntimeEngine


REPO_ROOT = Path(__file__).resolve().parents[1]
PROXY_POLICY = REPO_ROOT / "rules" / "proxy" / "mcp-proxy-policy.json"
RUNTIME_POLICY = REPO_ROOT / "rules" / "runtime" / "clawguard-runtime.json"


class McpProxyTests(unittest.TestCase):
    def _proxy(self) -> McpProxy:
        return McpProxy(
            McpProxyPolicy.from_file(PROXY_POLICY),
            RuntimeEngine.from_file(RUNTIME_POLICY, cwd=REPO_ROOT),
        )

    def test_filter_tools_hides_shell_capable_tool(self) -> None:
        message = json.loads((REPO_ROOT / "examples" / "mcp-tools-list-response.json").read_text(encoding="utf-8"))
        result = self._proxy().filter_tools_response(message)

        names = [tool["name"] for tool in result.message["result"]["tools"]]
        self.assertIn("read_file", names)
        self.assertIn("send_email", names)
        self.assertNotIn("execute_command", names)
        self.assertEqual(result.decisions[0].rule_id, "TF-PROXY-HIDE-SHELL-TOOLS")

    def test_shell_tool_call_is_denied_by_runtime_engine(self) -> None:
        message = json.loads((REPO_ROOT / "examples" / "mcp-tool-call-shell.json").read_text(encoding="utf-8"))
        proxy = self._proxy()
        decision = proxy.evaluate_tool_call_request(message)
        error_response = proxy.denied_response(message, decision)

        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.rule_id, "TF-RUNTIME-CMD-REMOTE-PIPE")
        self.assertEqual(error_response["error"]["code"], -32001)

    def test_file_tool_call_is_denied_for_sensitive_path(self) -> None:
        message = json.loads((REPO_ROOT / "examples" / "mcp-tool-call-file.json").read_text(encoding="utf-8"))
        decision = self._proxy().evaluate_tool_call_request(message)

        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.rule_id, "TF-RUNTIME-FILE-DENIED")

    def test_email_send_requires_approval_before_runtime_classification(self) -> None:
        message = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"to": "person@example.com", "body": "hello"}},
        }
        decision = self._proxy().evaluate_tool_call_request(message)

        self.assertEqual(decision.action, "require_approval")
        self.assertEqual(decision.rule_id, "TF-PROXY-APPROVE-EMAIL-SEND")


if __name__ == "__main__":
    unittest.main()

