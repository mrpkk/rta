"""Тесты MCP-эндпоинта ṚTA."""


class TestMcpProtocol:
    """MCP-эндпоинт обязателен: реестры агентов принимают только MCP."""

    def _respond(self, body: dict, verify=None, preds=None):
        import json as _json
        from rta import mcp
        raw = _json.dumps(body).encode("utf-8")

        def default_verify(_b):
            return 200, {"ok": True, "predicate": "balance_threshold",
                         "verdict": "порог достигнут",
                         "disclosed": "nothing: the public signals are empty"}

        def default_preds():
            return 200, {"predicates": [{"name": "balance_threshold",
                                          "threshold": "1000", "bits": 64,
                                          "label": "balance is at least 1000"}]}

        status, out = mcp.respond(raw, verify or default_verify,
                                  preds or default_preds)
        return status, _json.loads(out)

    def test_initialize_reports_protocol(self):
        status, out = self._respond({"jsonrpc": "2.0", "id": 1,
                                      "method": "initialize", "params": {}})
        assert status == 200
        assert out["result"]["protocolVersion"] == "2025-06-18"
        assert out["result"]["serverInfo"]["name"] == "rta"

    def test_tools_list_contains_both_tools(self):
        _status, out = self._respond({"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/list", "params": {}})
        names = [t["name"] for t in out["result"]["tools"]]
        assert "list_predicates" in names
        assert "verify_proof" in names

    def test_list_predicates_call(self):
        _status, out = self._respond({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "list_predicates", "arguments": {}}})
        assert out["result"]["structuredContent"]["predicates"]

    def test_verify_proof_call(self):
        _status, out = self._respond({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "verify_proof",
                       "arguments": {"predicate": "balance_threshold",
                                     "proof": {"pi_a": "x"}, "nonce": "n1"}}})
        payload = out["result"]["structuredContent"]
        assert payload["ok"] is True
        assert out["result"]["isError"] is False

    def test_missing_arguments_are_rejected(self):
        _status, out = self._respond({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "verify_proof", "arguments": {"predicate": "x"}}})
        assert "error" in out
        assert out["error"]["code"] == -32602

    def test_unknown_tool_is_rejected(self):
        _status, out = self._respond({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": "nope", "arguments": {}}})
        assert out["error"]["code"] == -32601

    def test_catalog_scanners_get_empty_lists(self):
        for method, key in (("resources/list", "resources"),
                            ("prompts/list", "prompts"),
                            ("resources/templates/list", "resourceTemplates")):
            _status, out = self._respond({"jsonrpc": "2.0", "id": 7,
                                           "method": method, "params": {}})
            assert out["result"][key] == [], method
