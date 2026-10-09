// POST /api/analyze
// Ingest (A3) and threat search (A4: OSV, GitHub count, KEV, EPSS) are real.
// The remaining steps are still fake and get replaced one by one.

import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import type { AnalyzeRequest, ProgressEvent, StepName } from "../../../shared/types.js";
import { IngestError, ingestRepo, removeClone, type IngestResult } from "../ingest/index.js";
import { addExploitSignals, countRecentNpmAdvisories, searchOsv, type RawAdvisory } from "../threats/index.js";

const REPO_URL = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/?$/;
const LOOKBACKS = [7, 30, 90];
const STEP_DELAY_MS = 700;

// Steps not built yet. Each one is removed from this list when its real version lands.
const FAKE_STEPS: { step: StepName; running: string; done: (days: number) => string; count?: number }[] = [
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

      // A4: OSV (vulnerabilities and malicious packages affecting the installed versions)
      send({ type: "progress", step: "osv", status: "running", message: `Querying OSV for ${ingest.dependencies.length} packages` });
      const osv = await searchOsv(ingest.dependencies);
      const advisories: RawAdvisory[] = osv.advisories;
      const affectedPackages = new Set(advisories.map((a) => a.package)).size;
      send({
        type: "progress",
        step: "osv",
        status: "done",
        message: `OSV: ${advisories.length} advisories match ${affectedPackages} of your packages${osv.fromCache ? " (cached data)" : ""}`,
        count: advisories.length,
      });

      // A4: GitHub advisory count for the coverage line (not used for matching)
      send({ type: "progress", step: "ghsa", status: "running", message: "Checking recent GitHub advisories" });
      const ghsa = await countRecentNpmAdvisories(lookbackDays);
      send({
        type: "progress",
        step: "ghsa",
        status: "done",
        message:
          ghsa.count === null
            ? "GitHub advisory count unavailable right now"
            : `GitHub: ${ghsa.count.toLocaleString("en-US")}${ghsa.capped ? "+" : ""} npm advisories from the last ${lookbackDays} days checked`,
        count: ghsa.count ?? undefined,
      });

      // A4: CISA KEV (exploited in the wild) and EPSS (exploit probability)
      send({ type: "progress", step: "kev", status: "running", message: "Checking CISA KEV and EPSS" });
      const signals = await addExploitSignals(advisories, lookbackDays);
      const inKev = advisories.filter((a) => a.inKev).length;
      send({
        type: "progress",
        step: "kev",
        status: "done",
        message: signals.kev.available
          ? `CISA KEV: ${signals.kev.addedInWindow} added in the last ${lookbackDays} days; ${inKev} of your matches listed`
          : "CISA KEV unavailable right now; continuing without it",
        count: signals.kev.addedInWindow,
      });
      request.log.info(
        { analysisId, advisories: advisories.length, inKev, epss: signals.epssCount, ghsa: ghsa.count },
        "threat search done",
      );

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