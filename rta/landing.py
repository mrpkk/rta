"""Витрина ṚTA: корневой адрес как торговая страница.

Почему отдельный файл: `http_api.py` занимается маршрутизацией, а текст
для человека и разметка — другой слой. Смешивать их в одном месте
невозможно читаемо, а править потом придётся именно эту строку.

Что здесь обязательно и почему:

* Правда о сети. Сервис может работать на тестнете, и страница обязана
  это писать. Тихая продажа несуществующего — обман.
* Риск подделки. Церемония односторонняя: доказательства может
  подделать оператор. Это риск №1, и на витрине он не прячется.
* Ноль публичных сигналов — главное свойство. Оно показывается явно,
  потому что именно за него платят.

Всё остальное — оформление, и оно меняется без опасений.
"""

from __future__ import annotations

import html
import json

_STYLE = """
:root{--bg:#0b0d12;--card:#141821;--line:#232a38;--ink:#e8ecf4;--dim:#8d97ad;
--accent:#6ea8fe;--warn:#f0a35e;--ok:#5fd08a;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:48px 24px 96px}
h1{font-size:34px;line-height:1.2;margin:0 0 6px}
h2{font-size:21px;margin:44px 0 12px;padding-top:20px;border-top:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
.lede{color:var(--dim);font-size:18px;margin:0 0 28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:14px 0}
.warn{border-left:3px solid var(--warn);background:#1d1710}
.warn b{color:var(--warn)}
.ok{border-left:3px solid var(--ok)}
.ok b{color:var(--ok)}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500}
code,pre{font-family:var(--mono);font-size:13px}
code{background:#0e1219;padding:1px 5px;border-radius:4px}
pre{background:#0e1219;border:1px solid var(--line);border-radius:8px;padding:14px 16px;
overflow-x:auto;line-height:1.55}
pre .c{color:var(--dim)}
a{color:var(--accent)}
.price{font-size:28px;font-weight:600;margin:6px 0}
.muted{color:var(--dim);font-size:14px}
.steps{counter-reset:s}
.steps li{margin:10px 0}
"""


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def landing_html(predicates: dict | None = None,
                 price_usdc: str = "1",
                 network: str = "Base Sepolia",
                 mode: str = "x402") -> str:
    """Собрать витрину.

    `predicates` приходит из PREDICATES, чтобы страница не расходилась с
    кодом: пять схем в тексте и пять в сервисе — одна правда.
    """
    preds = predicates or {}
    rows = "".join(
        f"<tr><td><code>{_esc(name)}</code></td><td>{_esc(meta['label'])}</td>"
        f"<td class='muted'>{meta['bits']} бит</td></tr>"
        for name, meta in sorted(preds.items())
    )

    testnet = "sepolia" in network.lower()

    banner = ""
    if testnet:
        banner = """
<div class="card warn">
<b>Сервис работает в тестовой сети Base Sepolia.</b> Деньги настоящие не
принимаются: оплата идёт тестовыми USDC, которые ничего не стоят. Переход
на mainnet не объявлен. Проверяйте платёжный путь, но не пишите это
в договор.
</div>"""
    elif mode == "free":
        banner = """
<div class="card warn">
<b>Режим free: доказательства не тарифицируются.</b>
</div>"""

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ṚTA — доказать факт, не раскрыв его</title>
<style>{_STYLE}</style></head><body><div class="wrap">

<h1>ṚTA</h1>
<p class="lede">Доказать, что условие выполнено, не раскрывая самого значения.
Проверяющий узнаёт, что порог пройден, и не узнаёт ничего больше.</p>

{banner}

<div class="card warn">
<b>Риск, о котором нужно знать до покупки: доказательства можно подделать.</b><br>
Церемония параметров односторонняя — участник один, значит «мусор», из
которого восстанавливается секрет, известен этому же человеку. Он способен
выпустить доказательство для несуществующего секрета.<br>
До участия трёх независимых сторон ключ нельзя считать доверенным. Это
ограничение продукта, а не недоработка документации.
</div>

<h2>Что доказывается</h2>
<table>
<tr><th>Схема</th><th>Что подтверждает</th><th>Разрядность</th></tr>
{rows}
</table>

<div class="card ok">
<b>Что узнаёт проверяющий:</b> только факт «порог пройден».<br>
<b>Что он не узнаёт:</b> сумму, залог, возраст аккаунта, число операций.<br>
Публичные сигналы доказательства пусты — это измерено на живых
доказательствах, а не заявлено.
</div>

<h2>Сколько и как</h2>
<div class="card">
<div class="price">{_esc(price_usdc)} USDC <span class="muted">за одну проверку</span></div>
<div class="muted">Сеть: {_esc(network)} · протокол: x402 (v2) · без подписки и аккаунта</div>
</div>
<p class="muted">Оплата приходит вместе с запросом: сервис отвечает счётом,
клиент подписывает платёж своим кошельком и повторяет запрос с оплатой.
Регистрация не нужна — нужен кошелёк с небольшим количеством USDC.</p>

<h2>Как использовать</h2>
<pre><code><span class="c"># 1. взять одноразовый токен под одно доказательство</span>
curl -s -X POST /v1/nonce \\
  -H 'Content-Type: application/json' \\
  -d '{{"predicate": "balance_1000"}}'

<span class="c"># 2. получить счёт: сумма, сеть, адрес получателя</span>
curl -si -X POST /v1/verify \\
  -H 'Content-Type: application/json' \\
  -d '{{"predicate": "balance_1000"}}'
<span class="c"># → HTTP 402 и заголовок x402 с параметрами оплаты</span>

<span class="c"># 3. подписать оплату EIP-3009 своим кошельком</span>
<span class="c">#    и положить подпись в заголовок PAYMENT-SIGNATURE</span>

<span class="c"># 4. отправить доказательство вместе с оплатой</span>
curl -s -X POST /v1/verify \\
  -H 'Content-Type: application/json' \\
  -H "PAYMENT-SIGNATURE: $PAYMENT" \\
  -d '{{"predicate":"balance_1000","proof":<proof>,
      "public_signals":[], "nonce":"<nonce>"}}'</code></pre>

<p class="muted">Ответ приходит с вердиктом <code>VERIFIED</code>, хешем
транзакции в блокчейне и заголовком <code>X-Payment-Response</code>.
Повторное предъявление того же nonce отклоняется: одна оплата — одна
проверка.</p>

<h2>Маршруты</h2>
<table>
<tr><th>Маршрут</th><th>Что делает</th></tr>
<tr><td><code>GET /healthz</code></td><td>живо ли сервис; сам сообщает свои ограничения</td></tr>
<tr><td><code>GET /v1/predicates</code></td><td>список схем с порогами</td></tr>
<tr><td><code>POST /v1/nonce</code></td><td>одноразовый токен под одно доказательство</td></tr>
<tr><td><code>POST /v1/verify</code></td><td>проверка; без оплаты отвечает счётом 402</td></tr>
<tr><td><code>GET /api</code></td><td>машинное описание сервиса (бывший корень)</td></tr>
</table>

<h2>Ограничения, честно</h2>
<ul class="muted">
<li>Состояние в памяти: перезапуск обнуляет выданные токены и счётчики.</li>
<li>Внешнего аудита схемы нет — она написана нами и нами же проверена.</li>
<li>Параметры ceremony сгенерированы локально, покупатель пересобрать их не сможет.</li>
<li>Доказательства подделываемы — см. предупреждение выше.</li>
</ul>

<p class="muted" style="margin-top:40px">
Имя — из ведической космологии: Ṛta — порядок, истина и правильное
соответствие между действием и следствием. Ровно то, что делает
доказательство: следствие следует из действия по правилу, и никакого иного
варианта нет.
</p>
</div></body></html>"""
