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
# Ключ IndexNow: публикуется файлом /<ключ>.txt на хосте — это и есть
# доказательство владения. Секретом не является; тот же ключ уже отдаёт
# attest.rta.lat, здесь он нужен для корня rta.lat.
_INDEXNOW_KEY = "79b5d8b3abc6edc97859cc7c3f6d85de"


_PRIVACY_HTML = """<!doctype html><html lang="en"><head><meta charset=utf-8>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ṚTA — privacy</title>
<meta name="description" content="What ṚTA stores and what it does not.">
<style>
 body{background:#0b0d12;color:#e8ecf4;font:16px/1.65 system-ui,sans-serif;max-width:700px;margin:0 auto;padding:44px 22px 80px}
 h1{font-size:26px;margin:0 0 16px} h2{font-size:18px;margin:26px 0 8px}
 p,li{color:#c3cad4} code{background:#171b21;padding:2px 6px;border-radius:4px}
</style></head><body>
<h1>Privacy</h1>
<p>ṚTA verifies zero-knowledge proofs that a hidden value reached a threshold.</p>
<h2>What we store</h2>
<ul>
<li><strong>Call counters</strong> — how many requests a caller made, per day, so the
free tier can be enforced. No artifacts, no prompts, no results.</li>
<li><strong>Nonces</strong> — one-time tokens that stop the same request from being
replayed. They expire and are not linked to a person.</li>
</ul>
<h2>What we do not store</h2>
<ul>
<li>the artifacts or proofs you check, and the verdicts;</li>
<li>your prompts, model outputs, or anything you paste into the demo;</li>
<li>your IP address — the server sees the tunnel's address, not yours.</li>
</ul>
<h2>Payments</h2>
<p>Payments settle on-chain via x402 (USDC on Base). The receipt is signed and
verifiable offline. The paying wallet is visible on the public blockchain, as
any blockchain payment is — that is a property of the network, not of this
service.</p>
<h2>Deletion</h2>
<p>Write to the address in the footer of any page and we will delete what you
name. Counter aggregates can be reset on request.</p>
</body></html>"""


class App:
    """Состояние сервиса. Один объект на процесс — состояние в памяти."""

    STATE_SAVE_THROTTLE_SEC = 1.0

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or Config.from_env()
        # Состояние на диске. Раньше всё жило в памяти, и перезапуск
        # возвращал потраченные nonce к жизни: доказательство можно было
        # предъявить второй раз по той же оплате. Счётчики при этом
        # обнулялись, и /metrics врал о нулевой нагрузке.
        state_dir = Path(self.cfg.state_dir) if self.cfg.state_dir else None
        self._state_path = (state_dir / "api.json") if state_dir else None
        self.nonces = NonceStore(
            state_path=(state_dir / "nonces.json") if state_dir else None)
        self.limiter = RateLimiter(self.cfg.rate_limit_per_minute)
        self.started = time.time()
        self.counts = {"nonce": 0, "verify": 0, "accepted": 0, "rejected": 0}
        # Nonce'ы уже предъявленных платежей. EIP-3009 отверг бы повтор и
        # на цепи, но без этой проверки каждый повтор сначала уходит в сеть
        # и тратит время фасилитатора. Параметр был, а никто его не передавал.
        self.seen_payment_nonces: set[str] = set()
        self._last_save = 0.0
        self._load_state()

    # ---------------------------------------------------------- состояние

    def _load_state(self) -> None:
        if not self._state_path:
            return
        from .service import _read_json
        data = _read_json(self._state_path)
        seen = data.get("seen_payment_nonces") or []
        if isinstance(seen, list):
            self.seen_payment_nonces = {str(n) for n in seen}
        counts = data.get("counts") or {}
        if isinstance(counts, dict):
            for key in self.counts:
                if isinstance(counts.get(key), int):
                    self.counts[key] = counts[key]

    def save_state(self, force: bool = False) -> None:
        """Сохранить состояние. Троттлинг, потому что вызов частый."""
        if not self._state_path:
            return
        now = time.time()
        if not force and now - self._last_save < self.STATE_SAVE_THROTTLE_SEC:
            return
        self._last_save = now
        from .service import _atomic_write
        try:
            _atomic_write(self._state_path, {
                "seen_payment_nonces": sorted(self.seen_payment_nonces),
                "counts": self.counts,
            })
        except OSError as exc:
            print(f"rta: состояние не сохранено: {exc}")

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
            "stateful": bool(self.cfg.state_dir),
            "state_dir": self.cfg.state_dir or None,
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
            raise ServiceError(f"unknown predicate {predicate!r}; available: "
                               f"{', '.join(sorted(PREDICATES))}")
        nonce = self.nonces.issue()
        self.counts["nonce"] += 1
        self.save_state()
        return 200, {"nonce": nonce, "predicate": predicate,
                     "ttl_seconds": self.nonces._ttl}

    def verify(self, body: dict, resource_url: str) -> tuple[int, dict]:
        predicate = body.get("predicate")
        proof = body.get("proof")
        public = body.get("public_signals", [])
        nonce = body.get("nonce")

        if predicate not in PREDICATES:
            raise ServiceError(f"unknown predicate {predicate!r}")
        if not isinstance(proof, dict):
            raise ServiceError("proof должен быть объектом")
        if not isinstance(public, list):
            raise ServiceError("public_signals должен быть массивом")

        # Одноразовость проверяется ДО дорогой проверки: иначе повторное
        # предъявление оплачивалось бы заново на каждой попытке.
        status = self.nonces.status(nonce) if nonce else "unknown"
        if status != "issued":
            self.counts["rejected"] += 1
            self.save_state()
            return 409, {"ok": False,
                         "error": f"nonce недействителен ({status}); каждое "
                                  f"the proof can be verified only once"}

        # Ключ — по предикату. Раньше здесь стоял один build/vk.json на всех,
        # а он является копией tx_count_50_vk.json: четыре схемы из пяти
        # сверялись с чужим ключом и отвергали валидные доказательства.
        ok, why = verify_proof(predicate, proof, public,
                               str(verifying_key_path(predicate)))
        self.counts["verify"] += 1
        if ok:
            self.nonces.consume(nonce)
            self.counts["accepted"] += 1
            self.save_state()
            return 200, {"ok": True, "predicate": predicate,
                         "verdict": why,
                         "disclosed": "nothing: the public signals are empty"}
        self.counts["rejected"] += 1
        self.save_state()
        return 200, {"ok": False, "predicate": predicate, "verdict": why,
                     "disclosed": "verification failed; the secret is not disclosed"}

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
                    f"can be verified only once")
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
        # Потраченный nonce платежа появился в множестве внутри
        # settle_payment — записываем немедленно: если сервис упадёт до
        # следующего запроса, оплата снова станет предъявляемой.
        self.save_state(force=True)
        payload["payment"] = {"settled": True,
                              "transaction": receipt.get("transaction"),
                              "network": receipt.get("network"),
                              "amount_atoms": receipt.get("amount_atoms"),
                              "pay_to": receipt.get("pay_to"),
                              # Для возврата нужно знать, кто платил и чем,
                              # прямо в теле ответа, а не в заголовке.
                              "payer": receipt.get("payer"),
                              "nonce": receipt.get("nonce"),
                              "confirmed_on_chain":
                                  receipt.get("confirmed_on_chain")}
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


def _base_url() -> str:
    """Публичный адрес: в sitemap обязаны быть абсолютные URL."""
    import os
    return os.environ.get("RTA_BASE_URL", "https://rta.lat").rstrip("/")


def _robots() -> str:
    """Краулеров пускаем: индексация витрины — это трафик."""
    return ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /mcp\n"
            f"Sitemap: {_base_url()}/sitemap.xml\n")


def _sitemap() -> str:
    """Карта сайта: документы, а не endpoints.

    `/challenge` и `/verify` — машиночитаемые адреса, их индексация
    бессмысленна.
    """
    base = _base_url()
    urls = "".join(
        f"<url><loc>{base}{page}</loc></url>" for page in ("", "/health"))
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{urls}</urlset>")


def _schema_block() -> str:
    """Разметка товара для поиска: тип, имя, цена, где найти."""
    data = {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "\u1e5aTA",
        "alternateName": "RTA",
        "applicationCategory": "DeveloperApplication",
        "operatingSystem": "Any",
        "description": ("Zero-knowledge proof over HTTP: prove a fact "
                        "without revealing it. Returns a verifiable proof "
                        "with no SDK, no ceremony and no key rotation."),
        "url": "https://rta.lat/",
        "offers": {"@type": "Offer", "price": "1",
                   "priceCurrency": "USDC"},
    }
    return ('<script type="application/ld+json">'
            + json.dumps(data, ensure_ascii=False) + "</script>")


def _with_schema(html: str) -> str:
    """Вставить разметку в HTML. Идемпотентно: повтор не дублирует."""
    if not isinstance(html, str) or "application/ld+json" in html:
        return html
    block = _schema_block()
    lowered = html.lower()
    for marker in ("</head>", "<body", "</title>"):
        pos = lowered.find(marker)
        if pos != -1:
            return html[:pos] + block + html[pos:]
    import re
    m = re.search(r"<meta[^>]+charset[^>]*>", html, re.IGNORECASE)
    if m:
        return html[:m.end()] + block + html[m.end():]
    return block + html


def _send_raw(handler, body: bytes, content_type: str) -> None:
    """Отдать не-JSON. `_send` умеет только словарь с json.dumps."""
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError):
        pass

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
            raise ServiceError(f"request body larger than {MAX_BODY_BYTES} bytes")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ServiceError(f"request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ServiceError("a JSON object is expected in the body")
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
        if path == "/robots.txt":
            return _send_raw(self, _robots().encode("utf-8"),
                              "text/plain; charset=utf-8")
        if path == "/sitemap.xml":
            return _send_raw(self, _sitemap().encode("utf-8"),
                              "application/xml; charset=utf-8")
        if path == "/.well-known/glama.json":
            # Верификация владения доменом для Glama: один файл покрывает все
            # коннекторы под rta.lat. Токен не секрет и должен жить постоянно —
            # при его удалении Glama снимает подтверждённое владение.
            body = json.dumps({
                "$schema": "https://glama.ai/mcp/schemas/connector.json",
                "claim": "glama_claim_N9Ld3qGF9Tz7UfnYjR18x4BvXzaTk664",
            }).encode("utf-8")
            return _send_raw(self, body, "application/json; charset=utf-8")
        if path == f"/{_INDEXNOW_KEY}.txt":
            # Доказательство владения хостом для IndexNow (Bing, Яндекс):
            # без этого файла поисковики не принимают заявку на обход.
            return _send_raw(self, _INDEXNOW_KEY.encode("utf-8"),
                             "text/plain; charset=utf-8")
        if path == "/privacy":
            return _send_raw(self, _PRIVACY_HTML.encode("utf-8"),
                             "text/html; charset=utf-8")
        if path in ("/", ""):
            # Витрина. Машинное описание переехало на /api: корень домена
            # — первое, что видит покупатель, и список маршрутов ему ничего
            # не объясняет. Старый корень не исчез, а переехал.
            from .landing import landing_html
            atoms = self.app.cfg.price_atoms
            price = f"{atoms / 1_000_000:g}" if atoms else "0"
            body = landing_html(
                predicates=PREDICATES,
                price_usdc=price,
                network=("Base Sepolia"
                         if self.app.cfg.network.endswith("84532")
                         else "Base mainnet"),
                mode=self.app.cfg.mode,
            )
            body = _with_schema(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api":
            self._send(200, {
                "service": "ṚTA — zero-knowledge proof of a threshold",
                "endpoints": ["/healthz", "/v1/predicates",
                              "POST /v1/nonce", "POST /v1/verify",
                              "POST /mcp (MCP server)"],
                "mode": self.app.cfg.mode,
                "network": self.app.cfg.network,
            })
        elif path == "/healthz":
            self._send(*self.app.healthz())
        elif path == "/v1/predicates":
            self._send(*self.app.predicates())
        else:
            self._send(404, {"ok": False, "error": f"no route for {path}"})

    def do_POST(self) -> None:               # noqa: N802
        path = self.path.split("?")[0].rstrip("/")
        if not self.app.limiter.allow():
            self._send(429, {"ok": False,
                             "error": "превышен лимит частоты",
                             "remaining_per_minute":
                                 self.app.limiter.remaining()})
            return
        # MCP читает тело сам: там важен сырой байтовый JSON-RPC, а
        # _read_json() уже съел бы его. Поэтому ветка выше разбора.
        if path == "/mcp":
            return self._handle_mcp()
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
                            self.app.cfg, header,
                            attestation_sys_path=_ATTEST,
                            seen_nonces=self.app.seen_payment_nonces)
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
                self._send(404, {"ok": False, "error": f"no route for {path}"})
        except ServiceError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
        except Exception as exc:              # noqa: BLE001
            self._send(500, {"ok": False,
                             "error": f"внутренняя ошибка: {type(exc).__name__}"})


    def _handle_mcp(self) -> None:
        """MCP-эндпоинт: каталоги агентов принимают только MCP.

        Оплата устроена как у /v1/verify, но решение «платный ли вызов»
        принимается ПОСЛЕ разбора запроса: у сервиса два инструмента, и
        список предикатов должен остаться бесплатным. Поэтому метод
        читается здесь, а не по «любой tools/call».
        """
        from . import mcp as mcp_module

        if not self.app.limiter.allow():
            self._send(429, {"ok": False,
                             "error": "превышен лимит частоты",
                             "remaining_per_minute":
                                 self.app.limiter.remaining()})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send(400, {"ok": False,
                             "error": "Content-Length is not a number"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(400, {"ok": False,
                             "error": f"body must be 1..{MAX_BODY_BYTES} bytes"})
            return
        raw = self.rfile.read(length)

        tool_name = None
        try:
            message = json.loads(raw or b"{}")
            if isinstance(message, dict):
                params = message.get("params") or {}
                if isinstance(params, dict):
                    tool_name = params.get("name")
        except ValueError:
            message = {}

        receipt = None
        if tool_name in mcp_module.PAID_TOOLS and self.app.cfg.mode == "x402":
            header = (self.headers.get("PAYMENT-SIGNATURE")
                      or self.headers.get("X-PAYMENT")
                      or self.headers.get("X-Payment"))
            if not header:
                self._send(*self.app.payment_required(self._resource_url()))
                return
            try:
                receipt = settle_payment(
                    self.app.cfg, header,
                    attestation_sys_path=_ATTEST,
                    seen_nonces=self.app.seen_payment_nonces)
            except ServiceError as exc:
                self._send(402, {"ok": False, "error": str(exc), "paid": False})
                return

        def verify_fn(body: dict):
            if receipt is not None:
                return self.app.verify_paid(body, self._resource_url(), receipt)
            return self.app.verify(body, self._resource_url())

        answer = mcp_module.respond(raw, verify_fn, self.app.predicates)
        if answer is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = answer
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
