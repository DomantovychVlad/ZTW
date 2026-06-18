import { afterAll, beforeEach } from "vitest";
import { prisma } from "../src/db/client";

// Чиста БД перед кожним тестом: усікаємо всі таблиці public-схеми.
beforeEach(async () => {
  const rows = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public'`;
  const list = rows.map((r) => `"public"."${r.tablename}"`).join(", ");
  if (!list) return;
  // Ретрай на 40P01: фонові записи (напр. fire-and-forget аудит сигналінгу) можуть
  // перетнутися з TRUNCATE і дати дедлок — повторна спроба проходить.
  for (let attempt = 0; ; attempt++) {
    try {
      await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE;`);
      return;
    } catch (e) {
      if (attempt >= 3) throw e;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
});

afterAll(async () => {
  await prisma.$disconnect();
});
