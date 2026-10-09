// GET /api/analyses/:id
// Serves reports from this server run (in memory), falling back to fixtures/report.json.
// Person B replaces the in-memory lookup with ClickHouse.

import type { FastifyInstance } from "fastify";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Report } from "../../../shared/types.js";
import { recallReport } from "../analysis/memoryStore.js";

const FIXTURE_PATH = path.resolve(process.cwd(), "../fixtures/report.json");

export async function reportRoutes(app: FastifyInstance) {
  app.get<{ Params: { id: string } }>("/api/analyses/:id", async (request, reply) => {
    const { id } = request.params;

    // Real reports from this server run (in memory until ClickHouse storage lands)
    const live = recallReport(id);
    if (live) return live;

    // Fixture report for UI development and the offline demo page
    const report = JSON.parse(await readFile(FIXTURE_PATH, "utf8")) as Report;

    if (id !== report.analysisId && id !== "demo") {
      return reply.code(404).send({ error: "Analysis not found" });
    }
    return report;
  });
}