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
    ok, why = verify_proof("age-18", {"protocol": "groth16"}, [],
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
