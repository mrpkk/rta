"""HTTP-сервис RTA: доказательство порога по сети, оплата по x402.

Зачем сервис поверх библиотеки: библиотеку можно вызвать только из своего
кода. Пока нет сетевого адреса, продукт нельзя ни купить, ни попробовать
стороннему разработчику.

Что сервис НЕ делает (и это важно понимать до первого запроса):
  · не генерирует доказательства — это делает клиент, у него секрет.
    Сервер только проверяет. Это и есть правильная расстановка ролей:
    секрет никогда не покидает машину доказывающего.
  · не доверяет параметрам запроса: стоимость, адрес получателя и имя
    сервиса берутся из конфигурации сервера, а не из тела запроса.
  · не хранит доказательства. Повтор ловится через nonce, а не через
    «у нас уже есть такой хэш в базе».

Два режима запуска:
  · `free` — без оплаты, для стенда и самотестов. Явно в ответе.
  · `x402` — настоящий платёжный челлендж по протоколу HTTP 402.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_NODE_DIR = _HERE.parent / "build"

# Предикаты, которые сервис вообще готов проверять. Список закрытый:
# клиент не может прислать имя схемы и получить проверку чего угодно.
PREDICATES: dict[str, dict] = {
    "age-18": {"bits": 8, "threshold": 18, "label": "возраст >= 18"},
    "balance-1000": {"bits": 32, "threshold": 1000, "label": "баланс >= 1000"},
    "balance-100000": {"bits": 48, "threshold": 100000,
                       "label": "баланс >= 100000"},
    "account-age-180": {"bits": 16, "threshold": 180,
                        "label": "возраст аккаунта >= 180 дней"},
    "tx-count-50": {"bits": 16, "threshold": 50,
                    "label": "не меньше 50 операций"},
    "stake-10000": {"bits": 32, "threshold": 10000,
                    "label": "залог >= 10000"},
}


class ServiceError(ValueError):
    """Запрос негоден. Отказ проверки, а не «чисто»."""


@dataclass(frozen=True)
class Config:
    """Конфигурация сервера.

    Цена и адрес получателя — только отсюда. Тело запроса на них не влияет,
    иначе клиент сам назначил бы, сколько стоит доказательство.
    """
    mode: str = "free"                 # free | x402
    price_atoms: int = 0
    pay_to: str = ""
    max_timeout_seconds: int = 300
    rate_limit_per_minute: int = 60

    @classmethod
    def from_env(cls) -> "Config":
        mode = os.getenv("RTA_MODE", "free")
        if mode not in ("free", "x402"):
            raise ServiceError(f"RTA_MODE должен быть free или x402, "
                               f"получено {mode!r}")
        price = int(os.getenv("RTA_PRICE_ATOMS", "0"))
        pay_to = os.getenv("RTA_PAY_TO", "")
        if mode == "x402":
            if price <= 0:
                raise ServiceError("RTA_MODE=x402 требует RTA_PRICE_ATOMS > 0")
            import re
            if not re.fullmatch(r"0x[a-fA-F0-9]{40}", pay_to):
                raise ServiceError("RTA_MODE=x402 требует RTA_PAY_TO: "
                                   "адрес 0x… из 40 шестнадцатеричных знаков")
        return cls(mode=mode, price_atoms=price, pay_to=pay_to)


class NonceStore:
    """Одноразовость проверок в пределах процесса.

    Граница честная: при перезапуске процесса память пуста, и ранее
    выданные nonce перестают действовать. Постоянное хранилище нужно
    для продакшна — здесь оно намеренно не сделано, потому что тихо
    хранить nonce в файле хуже, чем объявить об этом.
    """

    def __init__(self, ttl_seconds: int = 900):
        self._issued: dict[str, float] = {}
        self._used: set[str] = set()
        self._ttl = ttl_seconds

    def issue(self) -> str:
        import secrets
        nonce = secrets.token_hex(32)
        self._issued[nonce] = time.time()
        return nonce

    def status(self, nonce: str) -> str:
        if nonce in self._used:
            return "used"
        if nonce in self._issued:
            return "issued"
        return "unknown"

    def consume(self, nonce: str) -> None:
        if self.status(nonce) != "issued":
            raise ServiceError(f"nonce недействителен или уже использован "
                               f"({self.status(nonce)})")
        self._used.add(nonce)

    def prune(self) -> int:
        now = time.time()
        stale = [n for n, at in self._issued.items()
                 if n not in self._used and now - at > self._ttl]
        for n in stale:
            del self._issued[n]
        return len(stale)


class RateLimiter:
    """Скользящее окно в одну минуту. Не персистентно — см. NonceStore."""

    def __init__(self, per_minute: int = 60):
        self._hits: list[float] = []
        self._limit = per_minute

    def allow(self) -> bool:
        now = time.time()
        self._hits = [t for t in self._hits if now - t < 60]
        if len(self._hits) >= self._limit:
            return False
        self._hits.append(now)
        return True

    def remaining(self) -> int:
        now = time.time()
        return max(0, self._limit - len([t for t in self._hits
                                         if now - t < 60]))


def _bits(value: int, n: int) -> list[int]:
    """Младшие n бит числа. Секрет разлагается у клиента, не здесь —
    функция нужна для тестов сервиса и для воспроизводимых примеров."""
    return [(value >> i) & 1 for i in range(n)]


def verify_proof(predicate: str, proof: dict, public_signals: list,
                 vk_path: str | None = None) -> tuple[bool, str]:
    """Проверить доказательство snarkjs-ом — единственным путём.

    Вызов внешнего процесса, а не импорта: snarkjs существует только на
    Node. Это медленно, зато нет слоя «почти как настоящая проверка».

    Свой верификатор на чистом Python написан и ОТВЕРГНУТ: на живой паре
    уравнение не сошлось, тест билинейности не проходит. Файл оставлен в
    `experimental/groth16_verify_UNPROVEN.py` с пометкой. Сервер, который
    молча отвергает верное, хуже сервера без проверки.

    Известная проблема среды, не кода: на этой машине (свободно ~1,2 ГБ из
    15,5) вызов snarkjs упирается в пул воркеров и может идти минутами при
    почти нулевом процессорном времени. Причина — нехватка памяти, а не
    алгоритм: под strace тот же вызов укладывается в 90 секунд.
    """
    if predicate not in PREDICATES:
        raise ServiceError(f"предикат {predicate!r} неизвестен; доступен: "
                           f"{', '.join(sorted(PREDICATES))}")
    node_script = _NODE_DIR / "verify-service.mjs"
    if not node_script.exists():
        raise ServiceError(f"проверяющий скрипт не найден: {node_script}")
    with tempfile.TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        (tmpd / "proof.json").write_text(json.dumps(proof))
        (tmpd / "public.json").write_text(json.dumps(public_signals))
        proc = subprocess.run(
            ["node", str(node_script), str(tmpd / "proof.json"),
             str(tmpd / "public.json"), vk_path or str(_NODE_DIR / "vk.json")],
            capture_output=True, text=True, timeout=60,
        )
    out = proc.stdout.strip().splitlines()
    if proc.returncode != 0 or not out:
        return False, (proc.stderr.strip()[:200] or "проверка не выполнена")
    last = out[-1].strip()
    return last == "VERIFIED", last[:200]


# ---------------------------------------------------------------- x402

def build_payment_challenge(cfg: Config, resource_url: str, *,
                            attestation_sys_path: str | None = None):
    """Собрать настоящий челлендж x402 v2 через проверенный код attest.

    Слой не дублируется: формат челленджа уже сверен с живым ответом
    agentsvc.io и покрыт тестами в attest. Своя копия здесь разъехалась
    бы с проверенной и была бы второй неправдой.

    Цена и адрес получателя — из конфигурации сервера. Тело запроса на них
    не влияет: иначе клиент сам назначил бы стоимость доказательства.
    """
    import sys as _sys
    if attestation_sys_path:
        _sys.path.insert(0, attestation_sys_path)
    from attest.service import build_challenge  # type: ignore

    header, body = build_challenge(
        resource=resource_url,
        pay_to=cfg.pay_to,
        price_atoms=cfg.price_atoms,
        description="Zero-knowledge proof that a private value meets a "
                    "threshold, without revealing the value",
        max_timeout_seconds=cfg.max_timeout_seconds,
        service_name="rta",
        tags=["zk", "proof", "privacy", "compliance"],
    )
    return header, body


def economics(attestation_sys_path: str | None = None) -> dict:
    """Себестоимость, минимальная цена и запас.

    Считается из живых значений, а не из константы: иначе через полгода
    цифра в README будет врать, а продавать дешевле расчёта — значит
    терять деньги на каждом вызове незаметно.
    """
    import sys as _sys
    if attestation_sys_path:
        _sys.path.insert(0, attestation_sys_path)
    from attest.service import (MIN_MARGIN_MULTIPLIER,  # type: ignore
                                settlement_cost_usd)
    cost = settlement_cost_usd()
    min_price = cost * MIN_MARGIN_MULTIPLIER
    return {
        "cost_usd": cost,
        "min_price_usd": min_price,
        "min_price_atoms": int(min_price * 1_000_000) + 1,
        "margin_multiplier": MIN_MARGIN_MULTIPLIER,
    }
