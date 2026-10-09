import "dotenv/config";
import Fastify from "fastify";
import { analyzeRoutes } from "./routes/analyze.js";
import { reportRoutes } from "./routes/reports.js";

const app = Fastify({ logger: { level: "info" } });

app.get("/api/health", async () => ({ ok: true }));
app.register(analyzeRoutes);
app.register(reportRoutes);

const port = Number(process.env.PORT) || 4000;

app.listen({ port, host: "127.0.0.1" }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});