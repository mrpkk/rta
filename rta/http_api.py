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
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .service import (Config, NonceStore, PREDICATES, RateLimiter,
                      ServiceError, build_payment_challenge, economics,
                      verify_proof)

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

        ok, why = verify_proof(predicate, proof, public,
                               str(Path(__file__).resolve().parents[1]
                                    / "build" / "vk.json"))
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

    def payment_required(self, resource_url: str) -> tuple[int, dict, dict]:
        """Настоящий челлендж x402. Формат — из проверенного кода attest."""
        e = economics(_ATTEST)
        cfg = Config(mode="x402",
                     price_atoms=max(self.cfg.price_atoms, e["min_price_atoms"]),
                     pay_to=self.cfg.pay_to,
                     max_timeout_seconds=self.cfg.max_timeout_seconds)
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
        host = self.headers.get("Host", "localhost:8080")
        return f"http://{host}/v1/verify"

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
                    self._send(*self.app.payment_required(self._resource_url()))
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
