import "dotenv/config";
import { cleanEnv, num, port, str } from "envalid";

// Дев-дефолти секретів — небезпечні; у проді мають бути перевизначені реальними значеннями.
const DEV_JWT_SECRET = "dev-insecure-change-me";
const DEV_TURN_SECRET = "dev-insecure-turn-secret";

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
  JWT_SECRET: str({ default: DEV_JWT_SECRET }),
  TURN_STATIC_AUTH_SECRET: str({ default: DEV_TURN_SECRET }),
  TURN_REALM: str({ default: "zortilwatch.local" }),
  TURN_HOST: str({ default: "localhost" }),
  TURN_TTL_SECONDS: num({ default: 12 * 3600 }),
});

// Fail-fast у проді: дев-дефолти секретів = підробні токени/TURN-обліковки для всіх.
// Краще НЕ стартувати, ніж тихо працювати з відомими всім секретами.
if (env.isProduction) {
  const insecure: string[] = [];
  if (env.JWT_SECRET === DEV_JWT_SECRET) insecure.push("JWT_SECRET");
  if (env.TURN_STATIC_AUTH_SECRET === DEV_TURN_SECRET) insecure.push("TURN_STATIC_AUTH_SECRET");
  if (insecure.length > 0) {
    throw new Error(
      `Небезпечні дефолтні секрети у production: ${insecure.join(", ")}. ` +
        `Задайте реальні значення в середовищі.`,
    );
  }
}
