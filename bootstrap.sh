#!/usr/bin/env bash
# Ідемпотентний підйом бекенду ZortilWatch одним стеком.
# Використання:  DOMAIN=zortil.example.com ./bootstrap.sh
set -euo pipefail

cd "$(dirname "$0")"

# 1. Секрети генеруються ОДИН раз. Якщо .env є — не чіпаємо (ідемпотентно).
if [ ! -f .env ]; then
  : "${DOMAIN:?Спершу задайте DOMAIN, напр.: DOMAIN=zortil.example.com ./bootstrap.sh}"
  umask 077  # .env лише для власника
  {
    echo "DOMAIN=${DOMAIN}"
    echo "POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')"
    echo "JWT_SECRET=$(openssl rand -hex 32)"
    echo "TURN_STATIC_AUTH_SECRET=$(openssl rand -hex 32)"
    echo "SERVER_ED25519_SEED=$(openssl rand -hex 32)"  # ідентичність сервера (rendezvous)
  } > .env
  echo "[bootstrap] .env створено."
else
  echo "[bootstrap] .env уже є — використовую наявний (без перезапису)."
fi

# shellcheck disable=SC1091
set -a; . ./.env; set +a

# 2. Рендеримо coturn-конфіг із шаблону (щоразу — щоб тримати синхрон із .env).
sed -e "s|__DOMAIN__|${DOMAIN}|g" \
    -e "s|__TURN_STATIC_AUTH_SECRET__|${TURN_STATIC_AUTH_SECRET}|g" \
    coturn/turnserver.conf.template > coturn/turnserver.conf
echo "[bootstrap] coturn/turnserver.conf згенеровано."

# 3. Підіймаємо стек. Postgres healthcheck притримує бекенд до готовності БД.
docker compose up -d --build

# 4. Чекаємо, доки API за TLS відповість (або падаємо з підказкою).
echo "[bootstrap] чекаю на https://${DOMAIN}/health ..."
for _ in $(seq 1 30); do
  if curl -fsS "https://${DOMAIN}/health" >/dev/null 2>&1; then
    echo "[bootstrap] ZortilWatch піднято: https://${DOMAIN}"
    exit 0
  fi
  sleep 5
done
echo "[bootstrap] API не відповів вчасно. Дивіться: docker compose logs backend caddy" >&2
exit 1
