import { env } from "./config";
import { buildServer } from "./app";

const app = await buildServer();

app
  .listen({ port: env.PORT, host: "0.0.0.0" })
  .then((addr) => app.log.info(`ZortilWatch server listening on ${addr}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
