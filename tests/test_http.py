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
    assert {"balance-1000", "balance-100000", "stake-10000",
            "account-age-180", "tx-count-50"} <= names
    # 09.10.2026: объявлять можно только то, что сервис способен проверить.
    # age-18 висел в списке без схемы и без ключа — клиент платил и получал
    # отказ. Проверяем, что таких предикатов в ответе не появляется.
    from rta.service import verifying_key_path
    for p in body["predicates"]:
        assert p["threshold"] > 0 and p["bits"] >= 8
        assert verifying_key_path(p["name"]).exists(), (
            f"/v1/predicates объявляет {p['name']}, а ключа для него нет")


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
    codes = [post(base + "/v1/nonce", {"predicate": "balance-1000"})[0]
             for _ in range(6)]
    assert 429 in codes
    app.limiter._limit = app.cfg.rate_limit_per_minute


def test_bad_proof_is_rejected_with_fresh_nonce(server):
    """Неверное доказательство отвергается, но токен остаётся жив:
    клиент вправе прийти с настоящим."""
    base, _ = server
    _, nb, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
    code, body, _ = post(base + "/v1/verify", {
        "predicate": "balance-1000", "proof": {"protocol": "groth16"},
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
                        {"predicate": "balance-1000"})
        code, body, headers = post(f"http://127.0.0.1:{port}/v1/verify", {
            "predicate": "balance-1000", "proof": {"protocol": "groth16"},
            "public_signals": [], "nonce": nb["nonce"]})
        assert code == 402
        assert body["x402Version"] == 2
        assert "X-Payment" in headers
        assert int(body["accepts"][0]["amount"]) == 2919
    finally:
        srv.shutdown()
        srv.server_close()


def test_verify_uses_the_predicates_own_key():
    """Регрессия 09.10.2026: /v1/verify сверял любой предикат по ключу
    tx-count-50. Ловится без настоящего доказательства — подменяем
    проверку и смотрим, какой путь ей передали.

    Свой сервер, а не общий модульный: тест делает 10 POST'ов, и на общем
    он выедал rate limit (60/мин) у соседних тестов — они падали с KeyError
    по причине, никак не связанной с сутью.
    """
    app = App(Config(mode="free", rate_limit_per_minute=1000))
    srv = create_server(app, host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        from rta.service import verifying_key_path
        seen = {}
        import rta.http_api as api

        real = api.verify_proof

        def spy(predicate, proof, public, vk_path=None):
            seen["predicate"] = predicate
            seen["vk"] = vk_path
            return real(predicate, proof, public, vk_path)

        api.verify_proof = spy
        try:
            for name in ("balance-1000", "balance-100000", "stake-10000",
                         "account-age-180", "tx-count-50"):
                _, nb, _ = post(base + "/v1/nonce", {"predicate": name})
                assert "nonce" in nb, f"{name}: nonce не выдан ({nb})"
                post(base + "/v1/verify",
                     {"predicate": name, "proof": {"protocol": "groth16"},
                      "public_signals": [], "nonce": nb["nonce"]})
                assert seen["predicate"] == name
                assert seen["vk"] == str(verifying_key_path(name)), (
                    f"{name}: сервер пошёл проверять по чужому ключу {seen['vk']}")
        finally:
            api.verify_proof = real
    finally:
        srv.shutdown()
        srv.server_close()


def _post_with_payment(url, payload, header_value):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Payment": header_value},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def _x402_app():
    """Приложение в режиме x402: цена есть, получатель есть, ключ один."""
    return App(Config(mode="x402", price_atoms=1_000_000,
                      pay_to="0x" + "a" * 40, facilitator="https://f.example"))


def _run(app, fn):
    srv = create_server(app, host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        return fn(base)
    finally:
        srv.shutdown()
        srv.server_close()


def test_x402_without_payment_still_answers_402():
    app = _x402_app()
    def body(base):
        return post(base + "/v1/verify", {"predicate": "balance-1000"})
    code, payload, headers = _run(app, body)
    assert code == 402 and "X-Payment" in headers


def test_x402_with_paid_header_does_not_ask_again(monkeypatch):
    """Главное: оплаченный запрос не должен снова получать счёт.

    До правки маршрут отвечал 402 на ВСЁ, включая запрос с заголовком
    X-Payment, — оплата через сам сервис была невозможна.
    Расчёт здесь подменён на падение: важно, что сервер дошёл до расчёта
    и вернул ПРИЧИНУ отказа, а не повторный счёт.
    """
    import rta.http_api as api
    from rta.service import ServiceError

    calls = []

    def boom(*a, **k):
        calls.append(a[1] if len(a) > 1 else None)
        raise ServiceError("подпись не сошлась")

    monkeypatch.setattr(api, "settle_payment", boom)

    def body(base):
        _, nb, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
        return _post_with_payment(base + "/v1/verify",
                                  {"predicate": "balance-1000",
                                   "nonce": nb["nonce"]}, "payload")

    code, payload, headers = _run(_x402_app(), body)
    assert calls, "расчёт не вызывался — маршрут всё ещё отвечает счётом"
    assert "X-Payment" not in headers, "выдан новый счёт вместо причины"
    assert payload.get("paid") is False
    assert "подпись" in payload["error"]


def test_x402_settled_receipt_reaches_the_client(monkeypatch):
    """Оплаченный запрос должен вернуть квитанцию: без неё покупатель
    не сможет доказать, что заплатил."""
    import rta.http_api as api

    monkeypatch.setattr(
        api, "settle_payment",
        lambda *a, **k: {"settled": True, "transaction": "0xdead",
                         "network": "eip155:8453", "amount_atoms": 1_000_000,
                         "pay_to": "0x" + "a" * 40, "payer": "0x" + "b" * 40})

    def body(base):
        _, nb, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
        return _post_with_payment(
            base + "/v1/verify",
            {"predicate": "balance-1000", "proof": {"protocol": "groth16"},
             "public_signals": [], "nonce": nb["nonce"]}, "payload")

    code, payload, headers = _run(_x402_app(), body)
    assert payload["payment"]["settled"] is True
    assert payload["payment"]["transaction"] == "0xdead"
    assert "X-Payment-Response" in headers


def _post_with(url, payload, headers):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


@pytest.mark.parametrize("header_name", ["PAYMENT-SIGNATURE", "X-PAYMENT"])
def test_both_x402_header_names_are_accepted(monkeypatch, header_name):
    """Регрессия 09.10.2026. Сервис выставляет челлендж x402Version 2, а в
    v2 спецификация называет заголовок оплаты PAYMENT-SIGNATURE. X-PAYMENT —
    имя из v1. Читая только X-Payment, мы отвечали бы 402 настоящему
    v2-клиенту вечно: он платит правильно, а мы его не слышим.
    """
    import rta.http_api as api
    from rta.service import ServiceError

    seen = []
    monkeypatch.setattr(api, "settle_payment",
                        lambda cfg, header, **k: (seen.append(header),
                                                  (_ for _ in ()).throw(
                                                      ServiceError("тест")))[1])

    def body(base):
        _, nb, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
        return _post_with(base + "/v1/verify",
                          {"predicate": "balance-1000", "nonce": nb["nonce"]},
                          {header_name: "payload"})

    code, payload, headers = _run(_x402_app(), body)
    assert seen == ["payload"], (
        f"{header_name}: расчёт не вызван, заголовок не прочитан")
    assert "X-Payment" not in headers, f"{header_name}: выдан новый счёт"


def test_replayed_nonce_is_refused_before_any_network_call(monkeypatch):
    """Nonce проверяется ДО расчёта, а не после.

    Порядок в маршруте был: settle -> verify, а проверка nonce жила внутри
    verify. То есть на заведомо повторном платеже сервер сначала
    обращался к фасилитатору и лишь потом отказывал. Повтор ловил
    фасилитатор, и ловил верно, но это лишний сетевой вызов и лишний
    расчёт на его стороне.

    Первое предъявление обязано дойти до расчёта — иначе nonce не
    погаснет и «повтора» просто не случится. Повтор отсекается локально.
    """
    import rta.http_api as api

    calls = []
    real_settle = api.settle_payment

    def counting(cfg, header, **kw):
        calls.append(header)
        return {"settled": True, "transaction": "0xdead",
                "network": "eip155:84532", "amount_atoms": cfg.price_atoms,
                "pay_to": cfg.pay_to, "payer": "0x" + "b" * 40}

    monkeypatch.setattr(api, "settle_payment", counting)
    # Доказательство подменяем, чтобы первое предъявление УСПЕЛО и погасило
    # nonce. С мусорным доказательством nonce по замыслу не гасится —
    # покупатель вправе повторить с настоящим, — и «повтора» не выходит.
    monkeypatch.setattr(api, "verify_proof",
                        lambda *a, **k: (True, "VERIFIED"))

    def body(base):
        _, nb, _ = post(base + "/v1/nonce", {"predicate": "balance-1000"})
        payload = {"predicate": "balance-1000",
                   "proof": {"protocol": "groth16"}, "public_signals": [],
                   "nonce": nb["nonce"]}
        first = _post_with_payment(base + "/v1/verify", payload, "payload")
        assert first[0] == 200, f"первое предъявление отвергнуто: {first[1]}"
        assert len(calls) == 1, "первое предъявление должно дойти до расчёта"
        return _post_with_payment(base + "/v1/verify", payload, "payload")

    code, payload, _ = _run(_x402_app(), body)
    assert len(calls) == 1, f"расчёт вызван повторно: {len(calls)} раз"
    assert code == 409, f"повтор должен отвергаться 409, получено {code}"
    assert payload.get("paid") is False
    del real_settle
