import "dotenv/config";
import { cleanEnv, num, port, str } from "envalid";

// Валідація середовища на старті. Дев-значення за замовчуванням дозволяють підняти
// сервер локально без .env; у проді все перевизначається реальними секретами.
export const env = cleanEnv(process.env, {
  NODE_ENV: str({
    choices: ["development", "test", "production"],
    default: "development",
  }),
  PORT: port({ default: 8787 }),
  DATABASE_URL: str({
    default: "postgresql://zortil:zortil@localhost:5432/zortilwatch?schema=public",
  }),
  JWT_SECRET: str({ default: "dev-insecure-change-me" }),
  TURN_STATIC_AUTH_SECRET: str({ default: "dev-insecure-turn-secret" }),
  TURN_REALM: str({ default: "zortilwatch.local" }),
  TURN_HOST: str({ default: "localhost" }),
  TURN_TTL_SECONDS: num({ default: 12 * 3600 }),
});
