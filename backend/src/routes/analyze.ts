// POST /api/analyze
// Full pipeline: ingest (A3), threat search (A4), Semgrep (A6), classify and score (A5 + A7),
// AI advice (Person B, via contracts.ts) and save. Every step is real.

import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import type { AnalyzeRequest, ProgressEvent, Report } from "../../../shared/types.js";
import { IngestError, ingestRepo, removeClone, type IngestResult } from "../ingest/index.js";
import { addExploitSignals, countRecentNpmAdvisories, searchOsv, type RawAdvisory } from "../threats/index.js";
import { evidenceFor, runSemgrep } from "../analysis/semgrep.js";
import { classify } from "../analysis/classify.js";
import { previousReportFor, rememberReport } from "../analysis/memoryStore.js";
import { explainFindings, saveReport } from "../contracts.js";
import { previousAlertIds } from "../store/clickhouse.js";

const REPO_URL = /^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/?$/;
const LOOKBACKS = [7, 30, 90];
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

      // A6: Semgrep code evidence on the shallow clone
      send({ type: "progress", step: "semgrep", status: "running", message: "Semgrep: scanning the code for vulnerable usage" });
      const semgrep = await runSemgrep(ingest.cloneDir);
      const withEvidence = advisories.filter((a) => evidenceFor(a.package, [a.id, ...a.aliases], semgrep.hits).length > 0);
      send({
        type: "progress",
        step: "semgrep",
        status: "done",
        message: semgrep.available
          ? `Semgrep: ${semgrep.hits.length} code ${semgrep.hits.length === 1 ? "match" : "matches"}, linked to ${withEvidence.length} ${withEvidence.length === 1 ? "advisory" : "advisories"}`
          : "Semgrep unavailable; continuing without code evidence",
        count: semgrep.hits.length,
      });
      request.log.info(
        { analysisId, semgrepHits: semgrep.hits.map((h) => `${h.ruleId} ${h.file}:${h.line}`), linked: withEvidence.map((a) => a.id), semgrepError: semgrep.error },
        "semgrep done",
      );

      // A5 + A7: dedupe, classify, score
      send({ type: "progress", step: "score", status: "running", message: "Scoring and prioritizing" });
      let findings = classify(advisories, semgrep.hits, lookbackDays);
      const likely = findings.filter((f) => f.status === "likely_affected").length;
      send({
        type: "progress",
        step: "score",
        status: "done",
        message: `${findings.length} ${findings.length === 1 ? "alert" : "alerts"}: ${likely} likely affected, ${findings.length - likely} potentially affected`,
        count: findings.length,
      });

      // AI advice (Person B's code; falls back to template advice on any failure)
      if (closed) return;
      send({ type: "progress", step: "advice", status: "running", message: "Writing advice with AkashML" });
      findings = await explainFindings(findings, { id: null });
      const passed = findings.filter((f) => f.evidenceCheck === "passed").length;
      const advised = findings.filter((f) => f.advice !== null).length;
      send({
        type: "progress",
        step: "advice",
        status: "done",
        message: `Advice written for ${advised} ${advised === 1 ? "alert" : "alerts"} (${passed} passed evidence checks)`,
        count: advised,
      });

      // Build and save the report
      send({ type: "progress", step: "save", status: "running", message: "Saving analysis" });
      const repo = `${ingest.owner}/${ingest.repo}`;
      // Alerts from this repo's previous analysis: ClickHouse first, memory as fallback.
      let previousIds: Set<string> | null = null;
      try {
        previousIds = await previousAlertIds(repo);
      } catch (err) {
        request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "ClickHouse lookup failed");
      }
      if (!previousIds) {
        const prev = previousReportFor(repo);
        previousIds = prev ? new Set(prev.alerts.map((f) => f.canonicalId)) : null;
      }
      const newCount = findings.filter((f) => f.isNew).length;
      const report: Report = {
        analysisId,
        repo,
        commit: ingest.commit,
        analyzedAt: new Date().toISOString(),
        lookbackDays: lookbackDays as Report["lookbackDays"],
        traceId: null,
        coverage: {
          dependencies: ingest.dependencies.length,
          directDependencies: ingest.directCount,
          recentAdvisoriesChecked: ghsa.count ?? 0,
          kevChecked: signals.kev.addedInWindow,
          threatDataFetchedAt: new Date().toISOString(),
          newestAdvisoryPublished: ghsa.newestPublished,
          fromCache: osv.fromCache || signals.kev.fromCache,
        },
        summary: {
          newAffecting: newCount,
          knownAffecting: findings.length - newCount,
          notAffecting: Math.max(0, (ghsa.count ?? 0) - newCount),
          sinceLastAnalysis: previousIds ? findings.filter((f) => !previousIds!.has(f.canonicalId)).length : null,
        },
        alerts: findings,
      };
      rememberReport(report); // in-memory copy: the UI can load it even if ClickHouse is down
      let savedTo = "ClickHouse";
      try {
        await saveReport(report);
      } catch (err) {
        savedTo = "memory only";
        request.log.warn({ analysisId, err: err instanceof Error ? err.message : String(err) }, "ClickHouse save failed");
      }
      send({ type: "progress", step: "save", status: "done", message: `Analysis saved (${savedTo})` });
      request.log.info({ analysisId, alerts: findings.length, likely, adviceChecksPassed: passed }, "analysis done");

      send({ type: "result", analysisId });
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