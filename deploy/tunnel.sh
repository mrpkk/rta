#!/usr/bin/env bash
# Публичный HTTPS-адрес через Cloudflare Tunnel.
#
# Почему туннель, а не Cloudflare Workers: сервис на Python, а Workers
# исполняет только JS. Переписывать проверку доказательств на JS ради
# бесплатного хостинга — значит заменить проверенный snarkjs на
# непроверенный код. Туннель оставляет ровно то, что уже работает.
#
# Нужно один раз: залогиниться в cloudflared и создать именованный туннель.
# Дальше адрес постоянный, в отличие от trycloudflare.
set -euo pipefail

DOMAIN="${RTA_DOMAIN:?укажите свой домен: RTA_DOMAIN=example.com}"
HOST="${RTA_HOST:-127.0.0.1}"
PORT="${RTA_PORT:-8080}"

if ! command -v cloudflared >/dev/null; then
  echo "cloudflared не установлен. Установка:" >&2
  echo "  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" >&2
  exit 1
fi

echo "Проверяю, что сервис отвечает локально..."
curl -fsS "http://${HOST}:${PORT}/healthz" >/dev/null || {
  echo "сервис не отвечает на ${HOST}:${PORT} — сначала запусти его" >&2
  exit 1
}

echo "Поднимаю туннель: ${HOST}:${PORT} -> https://${DOMAIN}"
exec cloudflared tunnel run --url "http://${HOST}:${PORT}"
