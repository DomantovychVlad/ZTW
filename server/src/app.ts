import Fastify, { type FastifyInstance } from "fastify";
import fastifyWebsocket from "@fastify/websocket";
import cors from "@fastify/cors";
import { ZodError } from "zod";
import { env } from "./config";
import { AuthError } from "./auth/guard";
import { registerRoutes } from "./http/routes";
import { registerSignaling } from "./ws/signaling";

/** Зібрати застосунок (HTTP + WS), БЕЗ listen — зручно для тестів через inject/прямий запуск. */
export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({ logger: env.NODE_ENV !== "test" });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({ error: "bad_request", details: err.issues });
    }
    if (err instanceof AuthError) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    // Клієнтські помилки Fastify (битий JSON, порожнє тіло з content-type тощо) — не "internal".
    const status = (err as { statusCode?: unknown }).statusCode;
    if (typeof status === "number" && status >= 400 && status < 500) {
      return reply.code(status).send({ error: "bad_request" });
    }
    app.log.error(err);
    return reply.code(500).send({ error: "internal" });
  });

  // CORS для браузерних/webview-клієнтів (API на Bearer-токенах, без кук). У проді — обмежити origin.
  // methods явно: дефолт @fastify/cors (GET,HEAD,POST) ріже префлайт PATCH/DELETE адресної книги.
  await app.register(cors, { origin: true, methods: ["GET", "HEAD", "POST", "PATCH", "DELETE"] });

  app.get("/health", async () => ({ status: "ok", service: "zortilwatch-server" }));

  await app.register(fastifyWebsocket);
  const registry = registerSignaling(app);
  registerRoutes(app, registry);

  return app;
}
