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
        f"<tr><td><code>{_esc(name)}</code></td><td>{_esc(meta.get('label_en') or meta['label'])}</td>"
        f"<td class='muted'>{meta['bits']} bits</td></tr>"
        for name, meta in sorted(preds.items())
    )

    testnet = "sepolia" in network.lower()

    banner = ""
    if testnet:
        banner = """
<div class="card warn">
<b>This service runs on Base Sepolia, a test network.</b> No real money is
accepted — payments are in test USDC, which is worth nothing. Mainnet has
not been announced. Use it to test the payment path; do not put it in a
contract.
</div>"""
    elif mode == "free":
        banner = """
<div class="card warn">
<b>Режим free: доказательства не тарифицируются.</b>
</div>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ṚTA — prove a fact without revealing it</title>
<style>{_STYLE}</style></head><body><div class="wrap">

<h1>ṚTA</h1>
<p class="lede">Show that a condition holds without revealing the value behind it.
The verifier learns that the threshold was met, and nothing else.</p>

{banner}

<div class="card warn">
<b>Read this before you buy: proofs can be forged.</b><br>
The ceremony is single-party. With one participant, the trapdoor material
that would reveal a secret is known to that same person — who can therefore
mint a proof for a secret that does not exist.<br>
Until three independent parties take part, the key cannot be considered
trusted. This is a limitation of the product, not a documentation gap.
</div>

<h2>What you can prove</h2>
<table>
<tr><th>Circuit</th><th>What it proves</th><th>Width</th></tr>
{rows}
</table>

<div class="card ok">
<b>What the verifier learns:</b> only that the threshold was met.<br>
<b>What they never learn:</b> the balance, the stake, the account age, the
transaction count.<br>
The proof publishes zero public signals — measured on live proofs, not
claimed.
</div>

<h2>Price and payment</h2>
<div class="card">
<div class="price">{_esc(price_usdc)} USDC <span class="muted">per verification</span></div>
<div class="muted">Network: {_esc(network)} · Protocol: x402 (v2) · no account, no subscription</div>
</div>
<p class="muted">Payment rides along with the request: the service answers with
an invoice, the client signs the payment with its own wallet and repeats the
request carrying it. No signup — just a wallet holding a little USDC.</p>

<h2>How to use it</h2>
<pre><code><span class="c"># 1. take a single-use token, one per proof</span>
curl -s -X POST /v1/nonce \\
  -H 'Content-Type: application/json' \\
  -d '{{"predicate": "balance_1000"}}'

<span class="c"># 2. get the invoice: amount, network, payee address</span>
curl -si -X POST /v1/verify \\
  -H 'Content-Type: application/json' \\
  -d '{{"predicate": "balance_1000"}}'
<span class="c"># → HTTP 402 plus an x402 header with the payment terms</span>

<span class="c"># 3. sign the EIP-3009 payment with your wallet and put it</span>
<span class="c">#    in the PAYMENT-SIGNATURE header</span>

<span class="c"># 4. send the proof together with the payment</span>
curl -s -X POST /v1/verify \\
  -H 'Content-Type: application/json' \\
  -H "PAYMENT-SIGNATURE: $PAYMENT" \\
  -d '{{"predicate":"balance_1000","proof":<proof>,
      "public_signals":[], "nonce":"<nonce>"}}'</code></pre>

<p class="muted">The reply carries a <code>VERIFIED</code> verdict, the
transaction hash on chain, and an <code>X-Payment-Response</code> header.
Replaying the same nonce is rejected: one payment, one verification.</p>

<h2>Endpoints</h2>
<table>
<tr><th>Endpoint</th><th>What it does</th></tr>
<tr><td><code>GET /healthz</code></td><td>liveness, and the service states its own limits</td></tr>
<tr><td><code>GET /v1/predicates</code></td><td>circuits with their thresholds</td></tr>
<tr><td><code>POST /v1/nonce</code></td><td>single-use token, one per proof</td></tr>
<tr><td><code>POST /v1/verify</code></td><td>verify; answers 402 with an invoice when unpaid</td></tr>
<tr><td><code>GET /api</code></td><td>machine-readable service description</td></tr>
</table>

<h2>Limitations, stated plainly</h2>
<ul class="muted">
<li>State is in memory: a restart clears issued tokens and counters.</li>
<li>No external audit of the circuits — we wrote them and we verified them.</li>
<li>Ceremony parameters were generated locally; a buyer cannot rebuild the chain.</li>
<li>Proofs are forgeable — see the warning above.</li>
</ul>

<p class="muted" style="margin-top:40px">
The name comes from Vedic cosmology: Ṛta is order, truth, and the right
correspondence between action and consequence — which is precisely what a
proof does. The consequence follows from the action by rule, and no other
outcome is possible.
</p>
</div></body></html>"""
