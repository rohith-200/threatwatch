import "dotenv/config";
import Fastify from "fastify";
import { analyzeRoutes } from "./routes/analyze.js";
import { reportRoutes } from "./routes/reports.js";
import { ensureSchema, isConfigured } from "./store/clickhouse.js";

const app = Fastify({ logger: { level: "info" } });

app.get("/api/health", async () => ({ ok: true }));
app.register(analyzeRoutes);
app.register(reportRoutes);

const port = Number(process.env.PORT) || 4000;

// Create the ClickHouse tables if needed. If ClickHouse is down, the server still starts
// and reports are kept in memory only.
if (isConfigured()) {
  ensureSchema()
    .then(() => app.log.info("ClickHouse ready"))
    .catch((err) => app.log.warn({ err: err instanceof Error ? err.message : String(err) }, "ClickHouse unavailable; reports kept in memory only"));
} else {
  app.log.warn("CLICKHOUSE_URL not set; reports kept in memory only");
}

app.listen({ port, host: "127.0.0.1" }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});