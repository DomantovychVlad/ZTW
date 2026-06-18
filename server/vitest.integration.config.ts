import { defineConfig } from "vitest/config";

// Інтеграційні тести проти СПРАВЖНЬОГО Postgres (embedded-postgres, без Docker).
// global-setup піднімає сервер на 54329 і накатує схему (prisma db push).
const DATABASE_URL =
  "postgresql://postgres:postgres@localhost:54329/zortilwatch_test?schema=public";

export default defineConfig({
  test: {
    include: ["src/**/*.integration.test.ts"],
    globalSetup: ["./test/global-setup.ts"],
    setupFiles: ["./test/reset-each.ts"],
    env: { DATABASE_URL, NODE_ENV: "test" },
    testTimeout: 60_000,
    hookTimeout: 120_000,
    pool: "forks",
    poolOptions: { forks: { singleFork: true } },
  },
});
