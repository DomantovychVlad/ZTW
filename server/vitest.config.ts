import { defineConfig } from "vitest/config";

// Юніт-тести (без БД) — швидко, завжди зелено. Інтеграційні виключені.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    exclude: ["src/**/*.integration.test.ts", "node_modules/**"],
  },
});
