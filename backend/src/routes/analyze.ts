// POST /api/analyze
// Ingest (A3) is real. The other steps are still fake and get replaced one by one.

import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import type { AnalyzeRequest, ProgressEvent, StepName } from "../../../shared/types.js";
import { IngestError, ingestRepo, removeClone, type IngestResult } from "../ingest/index.js";

const REPO_URL = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/?$/;
const LOOKBACKS = [7, 30, 90];
const STEP_DELAY_MS = 700;

// Steps not built yet. Each one is removed from this list when its real version lands.
const FAKE_STEPS: { step: StepName; running: string; done: (days: number) => string; count?: number }[] = [
  { step: "osv", running: "Querying OSV", done: () => "OSV: 11 advisories match your packages", count: 11 },
  { step: "ghsa", running: "Checking GitHub advisories", done: (d) => `GitHub: 1,240 npm advisories from the last ${d} days checked`, count: 1240 },
  { step: "kev", running: "Checking CISA KEV", done: () => "CISA KEV: 19 newly exploited vulnerabilities checked", count: 19 },
  { step: "semgrep", running: "Semgrep: scanning src/", done: () => "Semgrep: 2 code matches", count: 2 },
  { step: "score", running: "Scoring and prioritizing", done: () => "Scored 4 alerts", count: 4 },
  { step: "advice", running: "Writing advice with AkashML", done: () => "Advice written for 4 alerts", count: 4 },
  { step: "save", running: "Saving analysis", done: () => "Analysis saved" },
];

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let busy = false; // one analysis at a time

export async function analyzeRoutes(app: FastifyInstance) {
  app.post<{ Body: AnalyzeRequest }>("/api/analyze", async (request, reply) => {
    const body = (request.body ?? {}) as Partial<AnalyzeRequest>;

    if (typeof body.repoUrl !== "string" || !REPO_URL.test(body.repoUrl.trim())) {
      return reply.code(400).send({ error: "Enter a GitHub repo URL like https://github.com/owner/repo" });
    }
    if (typeof body.lookbackDays !== "number" || !LOOKBACKS.includes(body.lookbackDays)) {
      return reply.code(400).send({ error: "lookbackDays must be 7, 30 or 90" });
    }
    if (busy) {
      return reply.code(409).send({ error: "Another analysis is running. Try again in a minute." });
    }
    busy = true;

    const repoUrl = body.repoUrl.trim();
    const lookbackDays = body.lookbackDays;
    const analysisId = `an_${randomUUID().slice(0, 8)}`;

    reply.hijack();
    const res = reply.raw;
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    let closed = false;
    res.on("close", () => {
      closed = true;
    });
    const send = (event: ProgressEvent) => {
      if (!closed) res.write(`data: ${JSON.stringify(event)}\n\n`);
    };

    let ingest: IngestResult | null = null;

    try {
      // A3: real ingest
      send({ type: "progress", step: "ingest", status: "running", message: "Reading package.json and package-lock.json" });
      ingest = await ingestRepo(repoUrl, analysisId);
      const lockNote = ingest.hasLockfile ? "" : ", no lockfile so versions are estimated";
      send({
        type: "progress",
        step: "ingest",
        status: "done",
        message: `Read ${ingest.dependencies.length} dependencies (${ingest.directCount} direct${lockNote})`,
        count: ingest.dependencies.length,
      });
      request.log.info({ analysisId, repo: `${ingest.owner}/${ingest.repo}`, commit: ingest.commit, deps: ingest.dependencies.length }, "ingest done");

      // Remaining steps: still fake
      for (const s of FAKE_STEPS) {
        if (closed) return;
        send({ type: "progress", step: s.step, status: "running", message: s.running });
        await sleep(STEP_DELAY_MS);
        send({ type: "progress", step: s.step, status: "done", message: s.done(lookbackDays), count: s.count });
      }

      // Until saveReport is real, point the UI at the fixture report.
      send({ type: "result", analysisId: "an_fixture_001" });
    } catch (err) {
      request.log.error({ analysisId, err: err instanceof Error ? err.message : String(err) }, "analysis failed");
      const message = err instanceof IngestError ? err.userMessage : "The analysis failed. Try again.";
      send({ type: "error", message });
    } finally {
      await removeClone(ingest?.cloneDir ?? null);
      busy = false;
      if (!closed) res.end();
    }
  });
}