"""Тесты HTTP-слоя RTA.

Здесь важнее код, чем обычно, потому что сервис — первое, к чему пойдёт
чужой код. Проверяется в том числе то, чего сервис НЕ должен позволять:
назначить себе цену, проверить неизвестный предикат, предъявить доказательство
дважды или раскрыть секрет через публичные сигналы.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_ATTEST = str(Path(__file__).resolve().parents[2] / "attest")
if _ATTEST not in sys.path:
    sys.path.insert(0, _ATTEST)

from rta.service import (Config, NonceStore, PREDICATES, RateLimiter,  # noqa: E402
                         ServiceError, economics, verify_proof)


# ------------------------------------------------------------- конфигурация

def test_free_mode_needs_nothing():
    c = Config.from_env()
    assert c.mode == "free" and c.price_atoms == 0


def test_x402_mode_requires_price_and_address(monkeypatch):
    """Молча пропущенный адрес — это «все платежи уйдут неизвестно куда»,
    и подпись это уже не спасёт."""
    monkeypatch.setenv("RTA_MODE", "x402")
    monkeypatch.setenv("RTA_PRICE_ATOMS", "0")
    monkeypatch.setenv("RTA_PAY_TO", "")
    with pytest.raises(ServiceError):
        Config.from_env()

    monkeypatch.setenv("RTA_PRICE_ATOMS", "5000")
    monkeypatch.setenv("RTA_PAY_TO", "не адрес")
    with pytest.raises(ServiceError):
        Config.from_env()


def test_x402_mode_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("RTA_MODE", "бесплатно-please")
    with pytest.raises(ServiceError):
        Config.from_env()


# ------------------------------------------------------------- одноразовость

def test_nonce_is_single_use():
    store = NonceStore()
    n = store.issue()
    assert store.status(n) == "issued"
    store.consume(n)
    assert store.status(n) == "used"
    with pytest.raises(ServiceError):
        store.consume(n)


def test_unissued_nonce_is_rejected():
    store = NonceStore()
    with pytest.raises(ServiceError):
        store.consume("0" * 64)


def test_expired_nonces_are_pruned():
    store = NonceStore(ttl_seconds=0)
    n = store.issue()
    store._issued[n] = 0.0          # выдана «давно»
    assert store.prune() == 1
    assert store.status(n) == "unknown"


def test_nonces_do_not_repeat():
    store = NonceStore()
    issued = {store.issue() for _ in range(200)}
    assert len(issued) == 200


# --------------------------------------------------------------- лимит частоты

def test_rate_limiter_blocks_over_limit():
    rl = RateLimiter(per_minute=3)
    assert [rl.allow() for _ in range(3)] == [True, True, True]
    assert rl.allow() is False


def test_rate_limiter_reports_remaining():
    rl = RateLimiter(per_minute=2)
    rl.allow()
    assert rl.remaining() == 1


# ---------------------------------------------------------------- предикаты

def test_predicate_list_is_closed():
    """Клиент не может прислать имя схемы и получить проверку чего угодно."""
    assert "balance-1000" in PREDICATES
    with pytest.raises(ServiceError):
        verify_proof("любая-схема-какая-угодно", {}, [], None)


def test_every_predicate_declares_its_width():
    for name, spec in PREDICATES.items():
        assert spec["bits"] in (8, 16, 32, 48), name
        assert spec["threshold"] > 0, name
        assert spec["label"], name


def test_threshold_must_fit_the_width():
    """Порог шире разрядности недостижим, и схема врала бы именем."""
    for name, spec in PREDICATES.items():
        assert spec["threshold"] < (1 << spec["bits"]), name


# ----------------------------------------------------------- проверка доказательства

def test_unknown_public_signals_are_rejected():
    """Доказательство с непустыми публичными сигналами РАСКРЫВАЕТ данные.
    Называть такое нулевым знанием было бы враньём — отвергаем."""
    proc_verify = Path(__file__).resolve().parent.parent / "build" / "verify-service.mjs"
    assert proc_verify.exists(), "проверяющий скрипт на месте"

    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "proof.json").write_text(json.dumps({"protocol": "groth16"}))
        (t / "public.json").write_text(json.dumps(["42"]))
        out = subprocess.run(
            ["node", str(proc_verify), str(t / "proof.json"),
             str(t / "public.json"), str(t / "non-existent-vk.json")],
            capture_output=True, text=True, timeout=60)
    assert out.returncode != 0
    assert "REJECTED" in out.stdout


def test_missing_key_is_a_rejection_not_a_pass():
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "proof.json").write_text(json.dumps({"protocol": "groth16"}))
        (t / "public.json").write_text(json.dumps([]))
        out = subprocess.run(
            ["node", str(Path(__file__).resolve().parent.parent
                         / "build" / "verify-service.mjs"),
             str(t / "proof.json"), str(t / "public.json"),
             str(t / "нет-такого-ключа.json")],
            capture_output=True, text=True, timeout=60)
    assert out.returncode != 0
    assert "REJECTED" in out.stdout


def test_verify_proof_returns_false_on_bad_input():
    # Предикат здесь — любой реально собираемый. Раньше стоял age-18,
    # который убран 09.10.2026 как несобираемый: проверка не проходит
    # не из-за мусора во входе, а потому что схемы нет.
    ok, why = verify_proof("balance-1000", {"protocol": "groth16"}, [],
                           "/tmp/не-существует.json")
    assert ok is False and why


# ----------------------------------------------------------------- экономика

def test_economics_computed_not_hardcoded():
    """Цифры берутся из живого расчёта. Константа в README через полгода
    станет ложью, а продавать дешевле расчёта — значит терять на каждом
    вызове."""
    e = economics(_ATTEST)
    assert e["cost_usd"] > 0
    assert e["min_price_usd"] > e["cost_usd"]
    assert e["margin_multiplier"] >= 1
    assert e["min_price_atoms"] >= 1


def test_min_price_is_above_cost_in_atoms():
    e = economics(_ATTEST)
    cost_atoms = e["cost_usd"] * 1_000_000
    assert e["min_price_atoms"] > cost_atoms


def test_challenge_built_with_server_side_price():
    """Цена в челлендже — из конфигурации сервера, не из запроса клиента."""
    from rta.service import build_payment_challenge
    e = economics(_ATTEST)
    cfg = Config(mode="x402", price_atoms=e["min_price_atoms"],
                 pay_to="0x" + "2" * 40)
    header, body = build_payment_challenge(
        cfg, "https://rta.example/prove",
        attestation_sys_path=_ATTEST)
    assert body["x402Version"] == 2
    accepts = body["accepts"][0]
    assert int(accepts["amount"]) == e["min_price_atoms"]
    assert accepts["payTo"] == cfg.pay_to


def test_price_below_cost_is_refused_by_the_shared_layer():
    """Отказ приходит из attest: цена ниже себестоимости расчёта. Своя
    проверка здесь была бы второй, расходящейся копией."""
    from rta.service import build_payment_challenge
    cfg = Config(mode="x402", price_atoms=1, pay_to="0x" + "2" * 40)
    with pytest.raises(ValueError):
        build_payment_challenge(cfg, "https://rta.example/prove",
                                attestation_sys_path=_ATTEST)


# ── КЛЮЧ ВЕРИФИКАЦИИ ДОЛЖЕН СООТВЕТСТВОВАТЬ ПРЕДИКАТУ (09.10.2026) ──
#
# Найдено на живой сессии: /v1/verify подставлял один и тот же файл
# build/vk.json для любого предиката. Этот файл — побайтовая копия
# tx_count_50_vk.json (одинаковый md5), то есть четыре схемы из пяти
# проверялись по чужому ключу: валидное доказательство balance_1000
# отвергалось, потому что сверялось не с тем ключом.

def test_each_predicate_resolves_to_its_own_verifying_key():
    """Ключ выбирается по предикату, а не один на все."""
    from rta.service import verifying_key_path
    seen = {}
    for name in PREDICATES:
        p = verifying_key_path(name)
        seen.setdefault(p.read_bytes(), []).append(name)
        assert p.exists(), f"{name}: нет ключа {p.name}"
    # уникальный ключ на каждый предикат — главное утверждение
    for key_bytes, names in seen.items():
        assert len(names) == 1, f"ключ делят предикаты: {names}"


def test_predicate_key_is_not_the_tx_count_key():
    """Конкретная регрессия: нельзя возвращаться к одному vk.json."""
    from rta.service import verifying_key_path
    tx_key = verifying_key_path("tx-count-50").read_bytes()
    for name in ("balance-1000", "balance-100000", "stake-10000",
                 "account-age-180"):
        assert verifying_key_path(name).read_bytes() != tx_key, (
            f"{name} сверяется с ключом tx-count-50 — это исходный баг")


def test_advertised_predicates_all_have_circuits():
    """Объявленный предикат обязан быть собираемым. Раньше в списке висел
    age-18: ни схемы в gen-circuits.mjs, ни скомпилированного ключа."""
    from rta.service import verifying_key_path
    for name in PREDICATES:
        assert verifying_key_path(name).exists(), (
            f"{name} объявлен в /v1/predicates, но ключа для него нет")


def test_unknown_predicate_key_raises():
    from rta.service import verifying_key_path
    with pytest.raises(ValueError):
        verifying_key_path("age-18")


# ── x402: ОПЛАТА ДОЛЖНА ПРИНИМАТЬСЯ, А НЕ ТОЛЬКО ЗАПРАШИВАТЬСЯ (09.10.2026)
#
# До правки /v1/verify в режиме x402 на ЛЮБОЙ запрос отвечал 402 и больше
# ничего не делал: ни подписи не проверял, ни расчёта не просил. Сервис
# выдавал счёт, который невозможно было оплатить через него же.

def test_config_carries_a_facilitator(monkeypatch):
    monkeypatch.setenv("RTA_MODE", "x402")
    monkeypatch.setenv("RTA_PRICE_ATOMS", "1000000")
    monkeypatch.setenv("RTA_PAY_TO", "0x" + "a" * 40)
    monkeypatch.delenv("RTA_FACILITATOR", raising=False)
    from rta.service import Config as C
    assert C.from_env().facilitator.startswith("https://")

    monkeypatch.setenv("RTA_FACILITATOR", "https://facilitator.example")
    assert C.from_env().facilitator == "https://facilitator.example"


def test_settle_rejects_a_request_without_payment_header():
    """Платежа нет — расчёт не выполняется и не должен выдаваться за успех."""
    from rta.service import settle_payment
    cfg = Config(mode="x402", price_atoms=1_000_000, pay_to="0x" + "a" * 40)
    with pytest.raises(ServiceError):
        settle_payment(cfg, header_value=None,
                       attestation_sys_path=_ATTEST)


def test_settle_never_calls_the_facilitator_for_a_bad_signature(monkeypatch):
    """Подпись не сошлась — запрос к сети не уходит. Иначе сервер сам
    станет орудием чужих транзакций: принимает мусор и просит перевод."""
    from rta.service import settle_payment
    import rta.service as svc

    called = []
    monkeypatch.setattr(svc, "_post_to_facilitator",
                        lambda *a, **k: called.append(a) or {}, raising=False)

    cfg = Config(mode="x402", price_atoms=1_000_000, pay_to="0x" + "a" * 40)
    with pytest.raises(ServiceError):
        settle_payment(cfg, header_value="not-a-real-payload",
                       attestation_sys_path=_ATTEST)
    assert not called, "сетевой запрос сделан ДО проверки подписи"


def test_settle_requires_facilitator_to_report_success(monkeypatch):
    """Ответ facilitator без success:true — это провал, а не «наверное ок».
    Иначе сервер отдаёт доказательство бесплатно."""
    from rta.service import settle_payment
    import rta.service as svc

    monkeypatch.setattr(svc, "verify_payment", lambda *a, **k: object(),
                        raising=False)
    monkeypatch.setattr(svc, "_post_to_facilitator",
                        lambda *a, **k: {"transaction": "0xabc"}, raising=False)
    cfg = Config(mode="x402", price_atoms=1_000_000, pay_to="0x" + "a" * 40)
    with pytest.raises(ServiceError):
        settle_payment(cfg, header_value="payload", attestation_sys_path=_ATTEST)


# ── СЕТЬ И КОНТРАКТ ТОКЕНА (09.10.2026) ──
#
# Mainnet и testnet — это РАЗНЫЕ токены по разным адресам. Перепутать —
# значит подписать перевод по несуществующему контракту: подпись сойдётся,
# деньги уйдут в никуда.

def test_sepolia_and_mainnet_use_different_usdc():
    from rta.service import usdc_for, DEFAULT_NETWORK, NETWORK_SEPOLIA
    main = usdc_for(DEFAULT_NETWORK)
    sep = usdc_for(NETWORK_SEPOLIA)
    assert main != sep, "контракт USDC одинаковый в mainnet и Sepolia"
    assert main == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    assert sep == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def test_unknown_network_is_refused_not_defaulted():
    """Молчаливый переход на mainnet при опечатке в сети хуже отказа:
    сервис стал бы выставлять счёт не в той сети."""
    from rta.service import usdc_for
    with pytest.raises(ServiceError):
        usdc_for("eip155:9999")


def test_env_selects_sepolia(monkeypatch):
    monkeypatch.setenv("RTA_MODE", "x402")
    monkeypatch.setenv("RTA_PRICE_ATOMS", "1000")
    monkeypatch.setenv("RTA_PAY_TO", "0x" + "a" * 40)
    monkeypatch.setenv("RTA_NETWORK", "eip155:84532")
    from rta.service import Config as C
    cfg = C.from_env()
    assert cfg.network == "eip155:84532"


def test_env_refuses_unknown_network_before_starting(monkeypatch):
    monkeypatch.setenv("RTA_MODE", "x402")
    monkeypatch.setenv("RTA_PRICE_ATOMS", "1000")
    monkeypatch.setenv("RTA_PAY_TO", "0x" + "a" * 40)
    monkeypatch.setenv("RTA_NETWORK", "eip155:1")     # Ethereum mainnet
    from rta.service import Config as C
    with pytest.raises(ServiceError):
        C.from_env()
