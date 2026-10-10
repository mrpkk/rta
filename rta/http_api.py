"""HTTP-маршруты RTA.

Что закрывает: слой сервиса и платёжный челлендж уже были, а самого
сервера с обработчиками не было. Без него продукт нельзя выставить по
сети — клиенту некуда обратиться.

Осознанные ограничения (это стенд, а не продакшн-сервис):
  · один процесс, состояние в памяти: перезапуск обнуляет выданные nonce
    и счётчики. Об этом сказано прямо в ответе на /healthz.
  · нет TLS: сервер слушает только localhost. Наружу выставляется через
    туннель, и это отдельное решение с отдельными рисками.
  · нет аутентификации: платёж по x402 и сам факт проверки не требуют
    личности клиента, но rate limit нужен обязательно.

Маршруты:
  GET  /healthz        живо ли сервис, что он умеет
  GET  /v1/predicates  закрытый список предикатов с порогами
  POST /v1/nonce       выдать одноразовый токен под одно доказательство
  POST /v1/verify      проверить доказательство (402 без оплаты)
  GET  /               человекочитаемая страница
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .service import (Config, NonceStore, PREDICATES, RateLimiter,
                      ServiceError, build_payment_challenge, economics,
                      settle_payment,
                      verify_proof, verifying_key_path)

_ATTEST = str(Path(__file__).resolve().parents[2] / "attest")
if _ATTEST not in sys.path:
    sys.path.insert(0, _ATTEST)

VERSION = "0.1.0"
MAX_BODY_BYTES = 256 * 1024


class App:
    """Состояние сервиса. Один объект на процесс — состояние в памяти."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or Config.from_env()
        self.nonces = NonceStore()
        self.limiter = RateLimiter(self.cfg.rate_limit_per_minute)
        self.started = time.time()
        self.counts = {"nonce": 0, "verify": 0, "accepted": 0, "rejected": 0}

    # ---------------------------------------------------------- маршруты

    def healthz(self) -> tuple[int, dict]:
        return 200, {
            "ok": True,
            "version": VERSION,
            "engine": "groth16",
            "curve": "bn128",
            "mode": self.cfg.mode,
            "uptime_seconds": round(time.time() - self.started, 1),
            "predicates": len(PREDICATES),
            "stateful": False,
            "warning": "состояние в памяти: перезапуск обнуляет выданные "
                       "nonce и счётчики. Не годится для продакшна без "
                       "постоянного хранилища.",
        }

    def predicates(self) -> tuple[int, dict]:
        return 200, {"predicates": [
            {"name": k, "threshold": v["threshold"], "bits": v["bits"],
             "label": v["label"]}
            for k, v in sorted(PREDICATES.items())
        ]}

    def issue_nonce(self, body: dict) -> tuple[int, dict]:
        predicate = body.get("predicate")
        if predicate not in PREDICATES:
            raise ServiceError(f"предикат {predicate!r} неизвестен; доступен: "
                               f"{', '.join(sorted(PREDICATES))}")
        nonce = self.nonces.issue()
        self.counts["nonce"] += 1
        return 200, {"nonce": nonce, "predicate": predicate,
                     "ttl_seconds": self.nonces._ttl}

    def verify(self, body: dict, resource_url: str) -> tuple[int, dict]:
        predicate = body.get("predicate")
        proof = body.get("proof")
        public = body.get("public_signals", [])
        nonce = body.get("nonce")

        if predicate not in PREDICATES:
            raise ServiceError(f"предикат {predicate!r} неизвестен")
        if not isinstance(proof, dict):
            raise ServiceError("proof должен быть объектом")
        if not isinstance(public, list):
            raise ServiceError("public_signals должен быть массивом")

        # Одноразовость проверяется ДО дорогой проверки: иначе повторное
        # предъявление оплачивалось бы заново на каждой попытке.
        status = self.nonces.status(nonce) if nonce else "unknown"
        if status != "issued":
            self.counts["rejected"] += 1
            return 409, {"ok": False,
                         "error": f"nonce недействителен ({status}); каждое "
                                  f"доказательство проверяется один раз"}

        # Ключ — по предикату. Раньше здесь стоял один build/vk.json на всех,
        # а он является копией tx_count_50_vk.json: четыре схемы из пяти
        # сверялись с чужим ключом и отвергали валидные доказательства.
        ok, why = verify_proof(predicate, proof, public,
                               str(verifying_key_path(predicate)))
        self.counts["verify"] += 1
        if ok:
            self.nonces.consume(nonce)
            self.counts["accepted"] += 1
            return 200, {"ok": True, "predicate": predicate,
                         "verdict": why,
                         "disclosed": "ничего: публичные сигналы пусты"}
        self.counts["rejected"] += 1
        return 200, {"ok": False, "predicate": predicate, "verdict": why,
                     "disclosed": "проверка не прошла; секрет не раскрыт"}

    def nonce_problem(self, nonce) -> str | None:
        """Одноразовость. None — можно проверять дальше.

        Вынесено отдельно от verify, потому что проверка обязана стоять
        ДО расчёта у фасилитатора. Раньше она жила внутри verify, а маршрут
        шёл settle → verify, и на повторном платеже сервер сначала
        обращался к фасилитатору, и лишь потом отказывал. Ловил его
        фасилитатор, и ловил верно, но это лишний сетевой вызов на
        заведомо отвергаемый запрос.

        Дёшево, локально и до сети: повтор должен отсекаться у нас.
        """
        status = self.nonces.status(nonce) if nonce else "unknown"
        if status != "issued":
            return (f"nonce недействителен ({status}); каждое доказательство "
                    f"проверяется один раз")
        return None

    def verify_paid(self, body: dict, resource_url: str,
                    receipt: dict) -> tuple[int, dict, dict]:
        """Проверить доказательство уже оплаченного запроса.

        Отдельный метод, а не флаг у verify: платёж и проверка доказательства
        — разные решения с разными последствиями. Здесь важно, чтобы квитанция
        о расчёте уехала к клиенту вместе с вердиктом: без неё агент-покупатель
        не сможет предъявить, что оплатил.
        """
        status, payload = self.verify(body, resource_url)
        payload["payment"] = {"settled": True,
                              "transaction": receipt.get("transaction"),
                              "network": receipt.get("network"),
                              "amount_atoms": receipt.get("amount_atoms"),
                              "pay_to": receipt.get("pay_to")}
        import base64 as _b64
        import json as _json
        resp = _b64.b64encode(_json.dumps(
            {"success": True, "transaction": receipt.get("transaction"),
             "network": receipt.get("network"),
             "payer": receipt.get("payer")}).encode()).decode()
        return status, payload, {"X-Payment-Response": resp}

    def payment_required(self, resource_url: str) -> tuple[int, dict, dict]:
        """Настоящий челлендж x402. Формат — из проверенного кода attest."""
        e = economics(_ATTEST)
        # dataclasses.replace, а не перечисление полей: здесь раньше стоял
        # Config(...) с пятью полями, и сеть с facilitator молча терялись —
        # сервер, запущенный на Sepolia, выставлял счёт в mainnet.
        # Ошибка невидима: подпись сходилась бы, деньги ушли бы не туда.
        import dataclasses
        cfg = dataclasses.replace(
            self.cfg,
            mode="x402",
            price_atoms=max(self.cfg.price_atoms, e["min_price_atoms"]),
        )
        header, challenge = build_payment_challenge(
            cfg, resource_url, attestation_sys_path=_ATTEST)
        return 402, challenge, {"X-Payment": header,
                                "Content-Type": "application/json"}


class Handler(BaseHTTPRequestHandler):
    app: App = None       # проставляется в create_server
    server_version = f"rta/{VERSION}"

    def log_message(self, fmt, *args):      # тише в журнале
        if self.app.cfg.mode == "x402":
            super().log_message(fmt, *args)

    def _send(self, code: int, payload: dict,
              headers: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False,
                          indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ServiceError(f"тело запроса больше {MAX_BODY_BYTES} байт")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ServiceError(f"тело не разобрано как JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ServiceError("в теле ожидается объект")
        return data

    def _resource_url(self) -> str:
        """Адрес ресурса для челленджа — ровно тот, по которому пришёл клиент.

        Схему берём из X-Forwarded-Proto: за туннелем сервер всегда был бы
        http, даже когда клиент пришёл по HTTPS, и покупатель увидел бы в
        счёте не тот адрес, которым пользуется. Несоответствие адреса в
        челлендже и в фактическом запросе — это расхождение, которое
        клиент не обязан прощать.

        Заголовок подделывает кто угодно, поэтому при отсутствии
        X-Forwarded-Proto считаем соединение https: сервис наружу
        выставляется только через туннель с TLS.
        """
        host = self.headers.get("Host", "localhost:8080")
        proto = (self.headers.get("X-Forwarded-Proto") or "https").strip().lower()
        if proto not in ("http", "https"):
            proto = "https"
        return f"{proto}://{host}/v1/verify"

    def do_GET(self) -> None:                # noqa: N802
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("/", ""):
            self._send(200, {
                "service": "ṚTA — zero-knowledge proof of a threshold",
                "endpoints": ["/healthz", "/v1/predicates",
                              "POST /v1/nonce", "POST /v1/verify"],
                "mode": self.app.cfg.mode,
            })
        elif path == "/healthz":
            self._send(*self.app.healthz())
        elif path == "/v1/predicates":
            self._send(*self.app.predicates())
        else:
            self._send(404, {"ok": False, "error": f"нет маршрута {path}"})

    def do_POST(self) -> None:               # noqa: N802
        path = self.path.split("?")[0].rstrip("/")
        if not self.app.limiter.allow():
            self._send(429, {"ok": False,
                             "error": "превышен лимит частоты",
                             "remaining_per_minute":
                                 self.app.limiter.remaining()})
            return
        try:
            body = self._read_json()
            if path == "/v1/nonce":
                self._send(*self.app.issue_nonce(body))
            elif path == "/v1/verify":
                if self.app.cfg.mode == "x402":
                    # Оплата. Раньше здесь стояло безусловное «вернуть 402
                    # и выйти»: счёт выставлялся на ЛЮБОЙ запрос, и оплатить
                    # его через сам сервис было невозможно — заколдованный
                    # круг. Теперь: нет заголовка — счёт; есть — расчёт.
                    # Заголовок оплаты называется по-разному в версиях
                    # спецификации: v2 — PAYMENT-SIGNATURE, v1 — X-PAYMENT.
                    # Мы выставляем x402Version 2, поэтому клиент по v2
                    # пришлёт первый, и читать только второй — значит не
                    # слышать настоящего плательщика вовсе.
                    header = (self.headers.get("PAYMENT-SIGNATURE")
                              or self.headers.get("X-PAYMENT")
                              or self.headers.get("X-Payment"))
                    if not header:
                        self._send(*self.app.payment_required(
                            self._resource_url()))
                        return
                    # Повтор отсекаем здесь, до фасилитатора: сеть на
                    # заведомо отвергаемый запрос не тратится.
                    stale = self.app.nonce_problem(body.get("nonce"))
                    if stale is not None:
                        self.app.counts["rejected"] += 1
                        self._send(409, {"ok": False, "error": stale,
                                         "paid": False})
                        return
                    try:
                        receipt = settle_payment(
                            self.app.cfg, header, attestation_sys_path=_ATTEST)
                    except ServiceError as exc:
                        # Платы не состоялось — доказательство не выдаём,
                        # но и не требуем оплату повторно вслепую: клиенту
                        # нужна причина, а не второй счёт.
                        self._send(402, {"ok": False, "error": str(exc),
                                         "paid": False})
                        return
                    self._send(*self.app.verify_paid(body,
                                                     self._resource_url(),
                                                     receipt))
                    return
                self._send(*self.app.verify(body, self._resource_url()))
            else:
                self._send(404, {"ok": False, "error": f"нет маршрута {path}"})
        except ServiceError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
        except Exception as exc:              # noqa: BLE001
            self._send(500, {"ok": False,
                             "error": f"внутренняя ошибка: {type(exc).__name__}"})


def create_server(app: App | None = None, host: str = "127.0.0.1",
                  port: int = 8080) -> ThreadingHTTPServer:
    """Сервер на localhost. Наружу не выставляется: нет TLS и аутентификации."""
    Handler.app = app or App()
    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:  # pragma: no cover
    srv = create_server(host=host, port=port)
    print(f"ṚTA слушает http://{host}:{port}  (режим {Handler.app.cfg.mode})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")
    finally:
        srv.server_close()


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    """Точка входа `python -m rta.http_api`.

    Её не было 09.10.2026, и это была худшая из возможных ошибок: модуль
    без `if __name__ == "__main__"` при запуске выходил с кодом 0 и не
    печатал ничего. Скрипт развёртывания видел успех, а порт не слушался
    никто — сервис «поднимался» за секунду и сразу умирал, и найти это
    можно было только попыткой обратиться к API.
    """
    import argparse
    p = argparse.ArgumentParser(prog="python -m rta.http_api",
                                description="ṚTA — HTTP-сервис ZK-доказательств")
    p.add_argument("--host", default=os.getenv("RTA_HOST", "127.0.0.1"),
                   help="адрес прослушивания (по умолчанию только localhost)")
    p.add_argument("--port", type=int, default=int(os.getenv("RTA_PORT", "8080")),
                   help="порт (по умолчанию 8080)")
    a = p.parse_args(argv)

    # Проверяем конфигурацию ДО старта: в режиме x402 без адреса получателя
    # и цены сервис поднялся бы и на каждый запрос отвечал бы 500.
    try:
        cfg = Config.from_env()
    except ServiceError as exc:
        print(f"конфигурация не проходит проверку: {exc}", file=sys.stderr)
        return 2
    if cfg.mode == "x402":
        print(f"режим x402: цена {cfg.price_atoms} атомов, получатель {cfg.pay_to}")

    serve(host=a.host, port=a.port)
    return 0


if __name__ == "__main__":       # noqa: RUF100
    raise SystemExit(main())
