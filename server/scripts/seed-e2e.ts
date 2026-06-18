// Дев-провіжен для живого тесту: створює акаунт + 2 пристрої (host, controller)
// і пише .scratch/e2e-creds.json. Запуск з каталогу server/:
//   $env:DATABASE_URL='...'; npx tsx scripts/seed-e2e.ts
// НЕ для прод — лише локальна БД розробника.

import { writeFileSync } from "node:fs";
import { prisma } from "../src/db/client";
import { createAccount } from "../src/db/accounts";
import { registerDevice } from "../src/db/devices";
import { generateClientSecret, hashClientSecret } from "../src/auth/secrets";

async function main() {
  const email = `e2e-${process.pid}-${Math.floor(Math.random() * 1e6)}@local.test`;
  const acc = await createAccount(email, "dev-password-hash-not-used");

  const hostSecret = generateClientSecret();
  const ctrlSecret = generateClientSecret();
  const host = await registerDevice(acc.id, {
    alias: "e2e-host",
    clientSecretHash: hashClientSecret(hostSecret),
  });
  const ctrl = await registerDevice(acc.id, {
    alias: "e2e-controller",
    clientSecretHash: hashClientSecret(ctrlSecret),
  });

  const creds = {
    base: "http://127.0.0.1:8787",
    host: { id: host.publicId, secret: hostSecret },
    controller: { id: ctrl.publicId, secret: ctrlSecret },
  };
  // cwd = server/, тож піднімаємось на корінь у .scratch
  writeFileSync("../.scratch/e2e-creds.json", JSON.stringify(creds, null, 2));
  console.log(
    `SEED OK account=${acc.id} host=${host.publicId} controller=${ctrl.publicId}`,
  );
  await prisma.$disconnect();
}

main().catch(async (e) => {
  console.error("SEED FAIL", e);
  try {
    await prisma.$disconnect();
  } catch {
    /* ignore */
  }
  process.exit(1);
});
