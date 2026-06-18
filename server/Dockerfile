# Бекенд ZortilWatch. glibc-база (НЕ Alpine) — надійніше для Prisma на ARM (Oracle A1).
FROM node:24-bookworm-slim

WORKDIR /app

# Залежності окремим шаром для кешу.
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Prisma-схема + генерація клієнта (бінарники рушія під цільову платформу зі schema).
COPY prisma ./prisma
RUN npx prisma generate

# Код і запуск (через tsx — рантайм-залежність).
COPY tsconfig.json ./
COPY src ./src
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["./docker-entrypoint.sh"]
