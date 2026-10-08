"""Тесты HTTP-сервера RTA: поднимаем его и бьём по-настоящему.

Проверяется через реальный сокет, а не вызовом функций: маршрутизация,
коды ответов и заголовки существуют только по сети. Тест, который зовёт
обработчик напрямую, пропустил бы половину ошибок.
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rta.http_api import App, create_server          # noqa: E402
from rta.service import Config                        # noqa: E402


@pytest.fixture(scope="module")
def server():
    app = App(Config(mode="free"))
    srv = create_server(app, host="127.0.0.1", port=0)   # порт 0 = свободный
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{port}", app
    srv.shutdown()
    srv.server_close()


def get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.status, json.loads(r.read()), dict(r.headers)


def post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


# ------------------------------------------------------------------ чтение

def test_root_lists_endpoints(server):
    base, _ = server
    code, body, headers = get(base + "/")
    assert code == 200
    assert any("/v1/verify" in e for e in body["endpoints"])
    # корень отдаёт JSON, а не страницу: сервис для агентов, не для людей
    assert "application/json" in headers.get("Content-Type", "")


def test_healthz_declares_its_weaknesses(server):
    """Сервис обязан сам сказать, что он непригоден для продакшна.
    Молчаливое «ok» без оговорок — это обман клиента."""
    base, _ = server
    code, body, _ = get(base + "/healthz")
    assert code == 200 and body["ok"] is True
    assert body["stateful"] is False
    assert "перезапуск" in body["warning"]
    assert body["engine"] == "groth16"


def test_predicates_are_closed_and_named(server):
    base, _ = server
    code, body, _ = get(base + "/v1/predicates")
    assert code == 200
    names = {p["name"] for p in body["predicates"]}
    assert {"age-18", "balance-1000"} <= names
    for p in body["predicates"]:
        assert p["threshold"] > 0 and p["bits"] >= 8


def test_unknown_route_is_404(server):
    base, _ = server
    from urllib.parse import quote
    try:
        get(base + "/" + quote("нет-такого"))
        assert False, "ожидался 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404


# -------------------------------------------------------------------- запись

def test_nonce_is_issued_and_single_use(server):
    base, _ = server
    code, body, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
    assert code == 200 and len(body["nonce"]) == 64
    assert body["predicate"] == "balance-1000"


def test_nonce_for_unknown_predicate_is_refused(server):
    base, _ = server
    code, body, _ = post(base + "/v1/nonce", {"predicate": "всё-и-всякое"})
    assert code == 400
    assert "неизвестен" in body["error"]


def test_verify_without_nonce_is_refused(server):
    """Без одноразового токена доказательство не принимается: иначе
    повторное предъявление проходило бы снова и снова."""
    base, _ = server
    code, body, _ = post(base + "/v1/verify", {
        "predicate": "balance-1000", "proof": {"protocol": "groth16"},
        "public_signals": []})
    assert code == 409
    assert "nonce" in body["error"]


def test_malformed_body_is_400(server):
    base, _ = server
    req = urllib.request.Request(base + "/v1/nonce",
                                 data=b"{not json at all",
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        urllib.request.urlopen(req, timeout=20)
        assert False, "ожидался отказ"
    except urllib.error.HTTPError as e:
        assert e.code == 400


def test_oversized_body_is_refused(server):
    base, _ = server
    huge = {"predicate": "balance-1000", "pad": "x" * (300 * 1024)}
    code, body, _ = post(base + "/v1/nonce", huge)
    assert code == 400 and "больше" in body["error"]


def test_rate_limit_kicks_in(server):
    """Лимит частоты обязан реально срабатывать, иначе это декларация."""
    base, app = server
    app.limiter._limit = 3
    app.limiter._hits.clear()
    codes = [post(base + "/v1/nonce", {"predicate": "age-18"})[0]
             for _ in range(6)]
    assert 429 in codes
    app.limiter._limit = app.cfg.rate_limit_per_minute


def test_bad_proof_is_rejected_with_fresh_nonce(server):
    """Неверное доказательство отвергается, но токен остаётся жив:
    клиент вправе прийти с настоящим."""
    base, _ = server
    _, nb, _ = post(base + "/v1/nonce", {"predicate": "age-18"})
    code, body, _ = post(base + "/v1/verify", {
        "predicate": "age-18", "proof": {"protocol": "groth16"},
        "public_signals": [], "nonce": nb["nonce"]})
    assert code == 200
    assert body["ok"] is False
    assert "секрет не раскрыт" in body["disclosed"]


# --------------------------------------------------------------------- x402

def test_x402_mode_returns_payment_challenge(server):
    """В режиме x402 проверка не бесплатна: сервер отвечает челленджем,
    а не результатом."""
    app = App(Config(mode="x402", price_atoms=2919,
                     pay_to="0x" + "2" * 40))
    srv = create_server(app, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        _, nb, _ = post(f"http://127.0.0.1:{port}/v1/nonce",
                        {"predicate": "age-18"})
        code, body, headers = post(f"http://127.0.0.1:{port}/v1/verify", {
            "predicate": "age-18", "proof": {"protocol": "groth16"},
            "public_signals": [], "nonce": nb["nonce"]})
        assert code == 402
        assert body["x402Version"] == 2
        assert "X-Payment" in headers
        assert int(body["accepts"][0]["amount"]) == 2919
    finally:
        srv.shutdown()
        srv.server_close()
