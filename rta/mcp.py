"""MCP-интерфейс к ṚTA: проверка ZK-доказательства как инструмент агента.

Зачем это: почти все крупные реестры агентов (Glama, Smithery, mcp.so,
mcpservers.org, mcprush) принимают **только MCP**. Пока у сервиса нет
MCP-эндпоинта, он физически некуда заявить — а каталоги сегодня наш
главный канал дистрибуции. Это не украшение, а блокированный канал.

Реализовано подмножество протокола: JSON-RPC 2.0 поверх HTTP, методы
`initialize`, `tools/list`, `tools/call`. Ничего лишнего: каталогам нужна
корректная работа этих трёх методов, а не полнота спецификации.

Инструменты:
- `list_predicates` — какие пороги вообще доказуемы (бесплатно);
- `verify_proof` — проверить доказательство (платно в режиме x402: за
  проверку платит владелец доказательства, а не получатель).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "rta"
SERVER_VERSION = "0.1.0"

LIST_TOOL: dict[str, Any] = {
    "name": "list_predicates",
    "title": "List provable thresholds",
    "annotations": {
        "title": "List provable thresholds",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "description": (
        "List the thresholds ṚTA can prove: for each predicate, the name, the "
        "threshold value, the circuit size and a plain-language label. Use "
        "before generating a proof, so the agent knows which statement it can "
        "prove without revealing the underlying value."
    ),
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}

VERIFY_TOOL: dict[str, Any] = {
    "name": "verify_proof",
    "title": "Verify a zero-knowledge proof of a threshold",
    "annotations": {
        "title": "Verify a zero-knowledge proof of a threshold",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "description": (
        "Verify a Groth16 zero-knowledge proof that a hidden value reached a "
        "threshold — for example 'the account balance is at least 1000'. The "
        "verifier learns that the threshold is met and never learns the value: "
        "the public signals are empty by construction. Returns whether the "
        "proof is valid, the predicate, and what the proof does NOT disclose. "
        "Use when a counterparty must show a threshold was met without "
        "revealing the number. A one-time nonce is required so the same proof "
        "cannot be replayed."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "predicate": {
                "type": "string",
                "description": "Which predicate the proof is for, e.g. balance_threshold.",
            },
            "proof": {
                "type": "object",
                "description": "The Groth16 proof as produced by snarkjs.",
            },
            "public_signals": {
                "type": "array",
                "description": "Public signals of the proof (usually empty: that is the point).",
            },
            "nonce": {
                "type": "string",
                "description": "One-time nonce obtained from POST /v1/nonce.",
            },
        },
        "required": ["predicate", "proof", "nonce"],
        "additionalProperties": False,
    },
}

# Инструменты, за которые берётся плата (в режиме x402).
PAID_TOOLS = frozenset({VERIFY_TOOL["name"]})

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL = -32603


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def as_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


def tools() -> list[dict[str, Any]]:
    return [LIST_TOOL, VERIFY_TOOL]


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, exc: RpcError) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": exc.as_dict()}


def respond(
    raw: bytes,
    verify: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]],
    list_predicates: Callable[[], tuple[int, dict[str, Any]]],
) -> tuple[int, bytes] | None:
    """Обработать один JSON-RPC запрос. None — это уведомление, ответа нет."""
    try:
        message = json.loads(raw or b"{}")
    except (json.JSONDecodeError, ValueError):
        return 200, json.dumps(_error(None, RpcError(
            JSONRPC_PARSE_ERROR, "не разобрать JSON"))).encode("utf-8")

    if not isinstance(message, dict):
        return 200, json.dumps(_error(None, RpcError(
            JSONRPC_INVALID_REQUEST, "запрос должен быть объектом"))).encode("utf-8")

    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if not isinstance(params, Mapping):
        return 200, json.dumps(_error(request_id, RpcError(
            JSONRPC_INVALID_PARAMS, "params должны быть объектом"))).encode("utf-8")

    try:
        if method == "initialize":
            return 200, json.dumps(_result(request_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })).encode("utf-8")
        if method == "tools/list":
            return 200, json.dumps(_result(request_id, {"tools": tools()})).encode("utf-8")
        if method == "tools/call":
            return 200, json.dumps(_result(request_id, _call_tool(params, verify,
                                                                list_predicates))).encode("utf-8")
        if method in ("notifications/initialized", "ping"):
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method in ("resources/list", "resources/templates/list", "prompts/list"):
            # Пустые списки вместо «метод не найден»: так требуют сканеры
            # каталогов. Отсутствие этих методов читается как сломанный
            # сервер и портит карточку листинга.
            key = "resourceTemplates" if method.endswith("templates/list") else method.split("/")[0]
            return 200, json.dumps(_result(request_id, {key: []})).encode("utf-8")
        return 200, json.dumps(_error(request_id, RpcError(
            JSONRPC_METHOD_NOT_FOUND,
            f"метод {method!r} не поддерживается"))).encode("utf-8")
    except RpcError as exc:
        return 200, json.dumps(_error(request_id, exc)).encode("utf-8")
    except Exception as exc:  # noqa: BLE001
        return 200, json.dumps(_error(request_id, RpcError(
            JSONRPC_INTERNAL,
            f"внутренняя ошибка: {type(exc).__name__}"))).encode("utf-8")


def _call_tool(
    params: Mapping[str, Any],
    verify: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]],
    list_predicates: Callable[[], tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, Mapping):
        raise RpcError(JSONRPC_INVALID_PARAMS, "arguments должны быть объектом")

    if name == LIST_TOOL["name"]:
        status, payload = list_predicates()
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload,
            "isError": status != 200,
        }

    if name != VERIFY_TOOL["name"]:
        raise RpcError(JSONRPC_METHOD_NOT_FOUND, f"no such tool: {name!r}")

    for required in ("predicate", "proof", "nonce"):
        if required not in arguments:
            raise RpcError(JSONRPC_INVALID_PARAMS,
                           f'нужен аргумент "{required}"')
    status, payload = verify({
        "predicate": arguments["predicate"],
        "proof": arguments["proof"],
        "public_signals": arguments.get("public_signals", []),
        "nonce": arguments["nonce"],
    })
    text = (
        f"{'ПРИНЯТО' if payload.get('ok') else 'ОТКЛОНЕНО'} · "
        f"{payload.get('predicate')} · {payload.get('verdict', '')}"
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": not payload.get("ok", False),
    }
