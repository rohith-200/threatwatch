// GET /api/analyses/:id
// GET /api/analyses/:id  -> memory, then ClickHouse, then the fixture report
// GET /api/repos/:owner/:repo/history -> past analyses of a repo from ClickHouse, newest first

import type { FastifyInstance } from "fastify";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Report } from "../../../shared/types.js";
import { recallReport } from "../analysis/memoryStore.js";
import { loadHistory, loadReport } from "../store/clickhouse.js";

const FIXTURE_PATH = path.resolve(process.cwd(), "../fixtures/report.json");

export async function reportRoutes(app: FastifyInstance) {
  app.get<{ Params: { id: string } }>("/api/analyses/:id", async (request, reply) => {
    const { id } = request.params;

    // Real reports from this server run (in memory until ClickHouse storage lands)
    const live = recallReport(id);
    if (live) return live;

    // Reports from earlier server runs, stored in ClickHouse
    try {
      const stored = await loadReport(id);
      if (stored) return stored;
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "ClickHouse read failed");
    }

    // Fixture report for UI development and the offline demo page
    const report = JSON.parse(await readFile(FIXTURE_PATH, "utf8")) as Report;

    if (id !== report.analysisId && id !== "demo") {
      return reply.code(404).send({ error: "Analysis not found" });
    }
    return report;
  });

  app.get<{ Params: { owner: string; repo: string } }>("/api/repos/:owner/:repo/history", async (request, reply) => {
    const { owner, repo } = request.params;
    try {
      return { repo: `${owner}/${repo}`, analyses: await loadHistory(`${owner}/${repo}`) };
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "ClickHouse history failed");
      return reply.code(503).send({ error: "History is unavailable right now." });
    }
  });
}