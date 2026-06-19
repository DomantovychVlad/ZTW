import { env } from "./config";
import { buildServer } from "./app";
import { disconnect } from "./db/client";

const app = await buildServer();

app
  .listen({ port: env.PORT, host: "0.0.0.0" })
  .then((addr) => app.log.info(`ZortilWatch server listening on ${addr}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });

// Коректне завершення: закрити сокети/heartbeat (onClose-хуки) і відпустити пул БД,
// щоб не лишати підвислих з'єднань і дати клієнтам session_close (повторний сигнал — форс).
let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    if (shuttingDown) process.exit(1);
    shuttingDown = true;
    app.log.info(`${signal} отримано — коректне завершення`);
    app
      .close()
      .then(() => disconnect())
      .then(() => process.exit(0))
      .catch((err) => {
        app.log.error(err);
        process.exit(1);
      });
  });
}
