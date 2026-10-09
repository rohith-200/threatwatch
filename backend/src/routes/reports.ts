// GET /api/analyses/:id
// TEMPORARY: serves fixtures/report.json so the report page works end to end.
// Replace with the ClickHouse lookup once storage is built.

import type { FastifyInstance } from "fastify";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Report } from "../../../shared/types.js";

const FIXTURE_PATH = path.resolve(process.cwd(), "../fixtures/report.json");

export async function reportRoutes(app: FastifyInstance) {
  app.get<{ Params: { id: string } }>("/api/analyses/:id", async (request, reply) => {
    const report = JSON.parse(await readFile(FIXTURE_PATH, "utf8")) as Report;
    const { id } = request.params;

    if (id !== report.analysisId && id !== "demo") {
      return reply.code(404).send({ error: "Analysis not found" });
    }
    return report;
  });
}