import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import EmbeddedPostgres from "embedded-postgres";

const PORT = 54329;
const USER = "postgres";
const PASSWORD = "postgres";
const DB = "zortilwatch_test";
const DATABASE_URL = `postgresql://${USER}:${PASSWORD}@localhost:${PORT}/${DB}?schema=public`;

// Піднімаємо РЕАЛЬНИЙ Postgres у %TEMP% (НЕ в теці проєкту — уникаємо OneDrive/локів),
// накатуємо схему й віддаємо teardown. Дані-каталог щоразу свіжий і викидається.
export default async function setup() {
  const dataDir = mkdtempSync(join(tmpdir(), "zw-pgtest-"));
  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: USER,
    password: PASSWORD,
    port: PORT,
    persistent: false,
  });

  await pg.initialise();
  await pg.start();
  await pg.createDatabase(DB);

  execFileSync("npx", ["prisma", "db", "push", "--skip-generate", "--accept-data-loss"], {
    stdio: "inherit",
    env: { ...process.env, DATABASE_URL },
    shell: process.platform === "win32",
  });

  return async () => {
    await pg.stop();
    rmSync(dataDir, { recursive: true, force: true });
  };
}
