// Дев-утиліта: завести РЕАЛЬНИЙ логін на акаунт, що володіє пристроєм-host'ом,
// щоб зайти у веб-пульт і побачити цей пристрій в адресній книзі.
// Запуск з server/: $env:DATABASE_URL='...'; npx tsx scripts/set-login.ts
// НЕ для прод — лише локальна дев-БД.

import { prisma } from "../src/db/client";
import { hashPassword } from "../src/auth/passwords";

const HOST_PUBLIC_ID = "592596134";
const EMAIL = "demo@local.test";
const PASSWORD = "demo-password-123";

async function main() {
  const dev = await prisma.device.findUnique({ where: { publicId: HOST_PUBLIC_ID } });
  if (!dev) throw new Error(`пристрій ${HOST_PUBLIC_ID} не знайдено`);
  await prisma.account.update({
    where: { id: dev.accountId },
    data: { email: EMAIL, passwordHash: await hashPassword(PASSWORD) },
  });
  console.log(`LOGIN SET email=${EMAIL} password=${PASSWORD} account=${dev.accountId}`);
  await prisma.$disconnect();
}

main().catch(async (e) => {
  console.error("FAIL", e);
  try {
    await prisma.$disconnect();
  } catch {
    /* ignore */
  }
  process.exit(1);
});
