#!/usr/bin/env sh
set -e

# Міграції застосовуються на старті (після того, як Postgres став healthy через
# depends_on у compose). `migrate deploy` лише накатує наявні міграції — без
# shadow-БД і без інтерактиву (production-коректно).
echo "[entrypoint] prisma migrate deploy..."
npx prisma migrate deploy

echo "[entrypoint] starting ZortilWatch server..."
exec npx tsx src/index.ts
