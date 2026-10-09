// POST /api/analyze
// STUB VERSION: streams fake progress events so Person B can build the input screen.
// Each fake step will be replaced by the real pipeline step (ingest, OSV, Semgrep, ...).

import type { FastifyInstance } from "fastify";
import type { AnalyzeRequest, ProgressEvent, StepName } from "../../../shared/types.js";

const REPO_URL = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/?$/;
const LOOKBACKS = [7, 30, 90];
const STEP_DELAY_MS = 700;

const FAKE_STEPS: { step: StepName; running: string; done: (days: number) => string; count?: number }[] = [
  { step: "ingest", running: "Reading package-lock.json", done: () => "Read 186 dependencies (9 direct)", count: 186 },
  { step: "osv", running: "Querying OSV", done: () => "OSV: 11 advisories match your packages", count: 11 },
  { step: "ghsa", running: "Checking GitHub advisories", done: (d) => `GitHub: 1,240 npm advisories from the last ${d} days checked`, count: 1240 },
  { step: "kev", running: "Checking CISA KEV", done: () => "CISA KEV: 19 newly exploited vulnerabilities checked", count: 19 },
  { step: "semgrep", running: "Semgrep: scanning src/", done: () => "Semgrep: 2 code matches", count: 2 },
  { step: "score", running: "Scoring and prioritizing", done: () => "Scored 4 alerts", count: 4 },
  { step: "advice", running: "Writing advice with AkashML", done: () => "Advice written for 4 alerts", count: 4 },
  { step: "save", running: "Saving analysis", done: () => "Analysis saved" },
];

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function analyzeRoutes(app: FastifyInstance) {
  app.post<{ Body: AnalyzeRequest }>("/api/analyze", async (request, reply) => {
    const body = (request.body ?? {}) as Partial<AnalyzeRequest>;

    // Validate before streaming, so bad input gets a normal 400 response.
    if (typeof body.repoUrl !== "string" || !REPO_URL.test(body.repoUrl.trim())) {
      return reply.code(400).send({ error: "Enter a GitHub repo URL like https://github.com/owner/repo" });
    }
    if (typeof body.lookbackDays !== "number" || !LOOKBACKS.includes(body.lookbackDays)) {
      return reply.code(400).send({ error: "lookbackDays must be 7, 30 or 90" });
    }
    const lookbackDays = body.lookbackDays;

    // Take over the raw response so Fastify doesn't send its own reply.
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

    try {
      for (const s of FAKE_STEPS) {
        if (closed) return;
        send({ type: "progress", step: s.step, status: "running", message: s.running });
        await sleep(STEP_DELAY_MS);
        send({ type: "progress", step: s.step, status: "done", message: s.done(lookbackDays), count: s.count });
      }
      send({ type: "result", analysisId: "an_fixture_001" });
    } catch (err) {
      request.log.error(err);
      send({ type: "error", message: "The analysis failed. Try again." });
    } finally {
      if (!closed) res.end();
    }
  });
}