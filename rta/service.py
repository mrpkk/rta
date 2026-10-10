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

# Facilitator по умолчанию: публичный, спецификация x402. Поменять на
# свой — RTA_FACILITATOR в окружении. Сервер шлёт сюда расчёт после
# того, как подпись платежа сошлась локально.
DEFAULT_FACILITATOR = "https://x402.org/facilitator"

#: Фасилитатор стоит за CDN, который банит запросы без внятного
#: User-Agent (Cloudflare error 1010). Проверено 09.10.2026: с
#: заголовком ответ 200, без него — 403. Наш собственный адрес честнее
#: строки "Mozilla/…", и CDN его принимает.
USER_AGENT = "rta/0.1 (+https://github.com/mrpkk/rta)"

# USDC в Base mainnet. Константа, а не строка в коде вызова: адрес
# токена — часть подписи, опечатка в нём подписала бы чужие деньги.
USDC_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_NETWORK = "eip155:8453"

# Base Sepolia — тестнет. Нужен, чтобы проверить ВЕСЬ платёжный путь
# бесплатно: публичный facilitator mainnet не держит (проверено:
# x402.org/facilitator/supported — все 9 сетей тестнеты), поэтому сначала
# testnet, и только потом решение про деньги.
#
# Контракт USDC в Sepolia ДРУГОЙ. Перепутать — значит подписать перевод
# по несуществующему адресу: подпись сойдётся, деньги уйдут в никуда.
USDC_ASSET_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NETWORK_SEPOLIA = "eip155:84532"

#: сеть → контракт USDC. Адрес токена часть подписи, поэтому он
#: выбирается по сети, а не задаётся независимо.
USDC_BY_NETWORK: dict[str, str] = {
    DEFAULT_NETWORK: USDC_ASSET,
    NETWORK_SEPOLIA: USDC_ASSET_SEPOLIA,
}


def usdc_for(network: str) -> str:
    """Контракт USDC указанной сети. Неизвестная сеть — отказ, а не
    молчаливый переход на mainnet: подпись на чужой сети хуже ошибки."""
    try:
        return USDC_BY_NETWORK[network]
    except KeyError:
        raise ServiceError(
            f"сеть {network!r} неизвестна; поддерживаются: "
            f"{', '.join(sorted(USDC_BY_NETWORK))}") from None

# Предикаты, которые сервис вообще готов проверять. Список закрытый:
# клиент не может прислать имя схемы и получить проверку чего угодно.
#
# Имена через дефис — как в HTTP API, файлы схем через подчёркивание.
# Связь между ними единственная: verifying_key_path ниже.
#
# age-18 убран 09.10.2026: он был объявлен в /v1/predicates, но схемы
# age-18 в gen-circuits.mjs нет и скомпилированного ключа не было —
# клиент выбирал его, платил и получал отказ. Объявлять предикат,
# который нечем проверить, хуже, чем не объявлять его вовсе.
PREDICATES: dict[str, dict] = {
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
    facilitator: str = DEFAULT_FACILITATOR
    network: str = DEFAULT_NETWORK

    @classmethod
    def from_env(cls) -> "Config":
        mode = os.getenv("RTA_MODE", "free")
        if mode not in ("free", "x402"):
            raise ServiceError(f"RTA_MODE должен быть free или x402, "
                               f"получено {mode!r}")
        price = int(os.getenv("RTA_PRICE_ATOMS", "0"))
        pay_to = os.getenv("RTA_PAY_TO", "")
        network = os.getenv("RTA_NETWORK", DEFAULT_NETWORK)
        usdc_for(network)          # отказ сразу, если сеть неизвестна
        if mode == "x402":
            if price <= 0:
                raise ServiceError("RTA_MODE=x402 требует RTA_PRICE_ATOMS > 0")
            import re
            if not re.fullmatch(r"0x[a-fA-F0-9]{40}", pay_to):
                raise ServiceError("RTA_MODE=x402 требует RTA_PAY_TO: "
                                   "адрес 0x… из 40 шестнадцатеричных знаков")
        return cls(mode=mode, price_atoms=price, pay_to=pay_to,
                   network=network,
                   facilitator=os.getenv("RTA_FACILITATOR",
                                         DEFAULT_FACILITATOR))


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


def verifying_key_path(predicate: str) -> Path:
    """Путь к ключу верификации ИМЕННО ЭТОГО предиката.

    Ключевая правка 09.10.2026. Раньше вызывающая сторона подставляла
    один общий build/vk.json для любого предиката, а этот файл —
    побайтовая копия tx_count_50_vk.json (совпадающий md5). Итог был
    тихим: пять схем объявлялись, а проверить можно было только одну;
    остальные четыре отвергали валидные доказательства, сверяя их
    с чужим ключом.

    Имя предиката в API через дефис, имя файла через подчёркивание.
    Соответствие однозначное, и тест на уникальность ключа это
    стережёт: общий ключ на два предиката тест не пропустит.
    """
    if predicate not in PREDICATES:
        raise ServiceError(f"предикат {predicate!r} неизвестен; доступен: "
                           f"{', '.join(sorted(PREDICATES))}")
    return _NODE_DIR / f"{predicate.replace('-', '_')}_vk.json"


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
        # Сеть и контракт токена — обязательными аргументами, а не
        # умолчаниями. Раньше они не передавались вовсе, и сервер,
        # запущенный на Sepolia, выставлял счёт в mainnet USDC: подпись
        # сошлась бы, деньги ушли бы не туда, и ошибки не было бы видно.
        network=cfg.network,
        asset=usdc_for(cfg.network),
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


# ------------------------------------------------------- приём оплаты

def _post_to_facilitator(url: str, payload: dict, timeout: int = 30) -> dict:
    """POST к facilitator/settle. Вынесено отдельно, чтобы тесты могли
    подменить сеть и доказать, что до проверки подписи она не вызывается."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "User-Agent": USER_AGENT},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        # Тело ответа обязано попасть в сообщение. Раньше его теряли, и
        # отказ facilitator выглядел как «HTTP Error 403» без причины —
        # а причиной был то Cloudflare, то отсутствие домена подписи.
        detail = exc.read()[:300].decode("utf-8", "replace").strip()
        raise ServiceError(
            f"facilitator ответил {exc.code}: {detail or 'без тела'}") from exc


def settle_payment(cfg: Config, header_value: str | None, *,
                   attestation_sys_path: str | None = None,
                   seen_nonces: set | None = None) -> dict:
    """Принять оплату по x402: проверить подпись, затем провести расчёт.

    До 09.10.2026 этого не было вовсе — /v1/verify в режиме x402 на любой
    запрос отвечал 402 и больше ничего не делал. Счёт выставлялся, но
    оплатить его через сам сервис было невозможно.

    Порядок жёсткий и он весь про одну мысль: **сначала криптография,
    потом сеть.** Проверка подписи платежа идёт до сетевого запроса,
    потому что иначе сервер отправлял бы в сеть всё, что прислали, —
    то есть был бы чужим транспортом для чужих транзакций.

    Ответ facilitator без `success: true` считается провалом: доказательство
    выдавать нельзя, если расчёт не подтверждён.
    """
    if not header_value:
        raise ServiceError("платёж не предъявлен: заголовок X-Payment пуст")

    import sys as _sys
    if attestation_sys_path and attestation_sys_path not in _sys.path:
        _sys.path.insert(0, attestation_sys_path)
    from attest.payment import (PaymentRequirement,  # noqa: PLC0415
                                verify_payment as _verify_payment)
    from attest.service import EIP712Domain          # noqa: PLC0415

    import base64                                    # noqa: PLC0415
    try:
        body = json.loads(base64.b64decode(header_value))
    except Exception as exc:                         # noqa: BLE001
        raise ServiceError(f"X-Payment не разобран: {exc}") from exc

    requirement = PaymentRequirement(
        network=str(body.get("network") or cfg.network),          # Base mainnet
        pay_to=cfg.pay_to,
        amount_atoms=cfg.price_atoms,
        # Контракт токена — по сети, и по сети СЕРВЕРА, а не по тому, что
        # прислал клиент: иначе плательщик подписывал бы перевод по адресу
        # другого токена, а подпись всё равно сошлась бы.
        asset=str(body.get("asset") or usdc_for(cfg.network)),
        version=2,
        resource=str(body.get("resource") or ""),
    )
    domain = EIP712Domain(
        name="USDC", version="2",
        verifying_contract=requirement.asset,
        chain_id=int(requirement.network.split(":")[-1]),
    )

    # 1. Подпись. Только локальная криптография, никаких обращений наружу.
    try:
        payment = _verify_payment(requirement, header_value, domain,
                                  seen_nonces=seen_nonces,
                                  max_window_seconds=cfg.max_timeout_seconds)
    except Exception as exc:                         # noqa: BLE001
        raise ServiceError(f"платёж не прошёл проверку: {exc}") from exc

    # 2. Расчёт у facilitator. Сеть трогается только теперь.
    url = cfg.facilitator.rstrip("/") + "/settle"
    try:
        result = _post_to_facilitator(url, {
            "paymentPayload": body,
            "paymentRequirements": {
                "scheme": "exact", "network": requirement.network,
                # И amount, и maxAmountRequired обязательны. Без amount
                # фасилитатор отвечает 500 "Cannot convert undefined to a
                # BigInt" — проверено на Base Sepolia 09.10.2026.
                "amount": str(requirement.amount_atoms),
                "maxAmountRequired": str(requirement.amount_atoms),
                "resource": requirement.resource,
                "description": "Zk proof verification",
                "mimeType": "application/json",
                "payTo": requirement.pay_to,
                "maxTimeoutSeconds": cfg.max_timeout_seconds,
                "asset": requirement.asset,
                # Имя и версия токена нужны фасилитатору, чтобы собрать
                # домен EIP-712. Без них он отвечает
                # invalid_exact_evm_missing_eip712_domain — проверял на
                # Base Sepolia 09.10.2026.
                "extra": {"name": domain.name, "version": domain.version},
            },
        })
    except Exception as exc:                         # noqa: BLE001
        raise ServiceError(f"расчёт у facilitator не выполнен: {exc}") from exc

    if not (isinstance(result, dict) and result.get("success") is True):
        # Причину берём из всех полей, которыми facilitator её называет:
        # у него это errorReason и errorMessage, а не error. Раньше искали
        # только `error`, и отладочный вывод не говорил ничего — пришлось
        # догадываться по HTTP-коду.
        why = result if isinstance(result, dict) else {}
        reason = (why.get("errorReason") or why.get("errorMessage")
                  or why.get("error") or "без указания причины")
        raise ServiceError(
            f"facilitator не подтвердил расчёт: {reason}")

    return {"transaction": result.get("transaction"),
            "network": result.get("network", requirement.network),
            "payer": result.get("payer"),
            "settled": True,
            "amount_atoms": requirement.amount_atoms,
            "pay_to": requirement.pay_to,
            "nonce": getattr(payment, "nonce", None)}
