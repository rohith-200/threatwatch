// ClickHouse storage for analyses and findings.
// Creates its own schema at startup, so there is no manual setup step.

import { createClient, type ClickHouseClient } from "@clickhouse/client";
import type { Report } from "../../../shared/types.js";

const DB = "threatwatch";

const SCHEMA = [
  `CREATE DATABASE IF NOT EXISTS ${DB}`,
  `CREATE TABLE IF NOT EXISTS ${DB}.analyses
   (
     analysis_id String, repo String, commit String, analyzed_at DateTime64(3, 'UTC'),
     lookback_days UInt16, dependencies UInt32, direct_dependencies UInt32,
     advisories_checked UInt32, kev_checked UInt32, alerts UInt16, likely UInt16,
     new_affecting UInt16, total_risk UInt32, from_cache Bool, report_json String
   )
   ENGINE = MergeTree ORDER BY (repo, analyzed_at)`,
  `CREATE TABLE IF NOT EXISTS ${DB}.findings
   (
     analysis_id String, repo String, analyzed_at DateTime64(3, 'UTC'), canonical_id String,
     aliases Array(String), package LowCardinality(String), installed_version String,
     fixed_version Nullable(String), severity LowCardinality(String), status LowCardinality(String),
     risk_score UInt8, is_new Bool, in_kev Bool, epss Nullable(Float32), evidence_count UInt16,
     simulated Bool, evidence_check LowCardinality(String)
   )
   ENGINE = MergeTree ORDER BY (repo, analyzed_at, canonical_id)`,
];

let client: ClickHouseClient | null = null;

// Reads CLICKHOUSE_URL, e.g. http://tw:tw@localhost:8123. Returns null if it isn't set.
function getClient(): ClickHouseClient | null {
  if (client) return client;
  const raw = process.env.CLICKHOUSE_URL;
  if (!raw) return null;
  const u = new URL(raw);
  client = createClient({
    url: `${u.protocol}//${u.host}`,
    username: decodeURIComponent(u.username) || "default",
    password: decodeURIComponent(u.password),
    request_timeout: 10_000,
    clickhouse_settings: { date_time_input_format: "best_effort" },
  });
  return client;
}

export function isConfigured(): boolean {
  return getClient() !== null;
}

// Creates the database and tables if they don't exist. Called once at server startup.
export async function ensureSchema(): Promise<void> {
  const ch = getClient();
  if (!ch) throw new Error("CLICKHOUSE_URL is not set");
  for (const query of SCHEMA) await ch.command({ query });
}

export async function storeReport(report: Report): Promise<void> {
  const ch = getClient();
  if (!ch) throw new Error("CLICKHOUSE_URL is not set");

  const likely = report.alerts.filter((a) => a.status === "likely_affected").length;
  await ch.insert({
    table: `${DB}.analyses`,
    format: "JSONEachRow",
    values: [{
      analysis_id: report.analysisId,
      repo: report.repo,
      commit: report.commit,
      analyzed_at: report.analyzedAt,
      lookback_days: report.lookbackDays,
      dependencies: report.coverage.dependencies,
      direct_dependencies: report.coverage.directDependencies,
      advisories_checked: report.coverage.recentAdvisoriesChecked,
      kev_checked: report.coverage.kevChecked,
      alerts: report.alerts.length,
      likely,
      new_affecting: report.summary.newAffecting,
      total_risk: report.alerts.reduce((sum, a) => sum + a.riskScore, 0),
      from_cache: report.coverage.fromCache,
      report_json: JSON.stringify(report),
    }],
  });

  if (report.alerts.length === 0) return;
  await ch.insert({
    table: `${DB}.findings`,
    format: "JSONEachRow",
    values: report.alerts.map((a) => ({
      analysis_id: report.analysisId,
      repo: report.repo,
      analyzed_at: report.analyzedAt,
      canonical_id: a.canonicalId,
      aliases: a.aliases,
      package: a.package,
      installed_version: a.installedVersion,
      fixed_version: a.fixedVersion,
      severity: a.severity,
      status: a.status,
      risk_score: a.riskScore,
      is_new: a.isNew,
      in_kev: a.inKev,
      epss: a.epss,
      evidence_count: a.evidence.length,
      simulated: a.simulated,
      evidence_check: a.evidenceCheck,
    })),
  });
}

export async function loadReport(analysisId: string): Promise<Report | null> {
  const ch = getClient();
  if (!ch) return null;
  const rs = await ch.query({
    query: `SELECT report_json FROM ${DB}.analyses WHERE analysis_id = {id:String} LIMIT 1`,
    query_params: { id: analysisId },
    format: "JSONEachRow",
  });
  const rows = (await rs.json()) as { report_json: string }[];
  return rows.length ? (JSON.parse(rows[0].report_json) as Report) : null;
}

export interface HistoryEntry {
  analysisId: string;
  analyzedAt: string;
  commit: string;
  alerts: number;
  likely: number;
  newAffecting: number;
  totalRisk: number;
}

export async function loadHistory(repo: string, limit = 20): Promise<HistoryEntry[]> {
  const ch = getClient();
  if (!ch) return [];
  const rs = await ch.query({
    query: `SELECT analysis_id, concat(replaceOne(toString(analyzed_at), ' ', 'T'), 'Z') AS analyzed_iso,
                   commit, alerts, likely, new_affecting, total_risk
            FROM ${DB}.analyses
            WHERE repo = {repo:String}
            ORDER BY analyzed_at DESC
            LIMIT {limit:UInt32}`,
    query_params: { repo, limit },
    format: "JSONEachRow",
  });
  const rows = (await rs.json()) as {
    analysis_id: string; analyzed_iso: string; commit: string;
    alerts: number; likely: number; new_affecting: number; total_risk: number | string;
  }[];
  return rows.map((r) => ({
    analysisId: r.analysis_id,
    analyzedAt: r.analyzed_iso,
    commit: r.commit,
    alerts: Number(r.alerts),
    likely: Number(r.likely),
    newAffecting: Number(r.new_affecting),
    totalRisk: Number(r.total_risk),
  }));
}

// Alert IDs from the repo's most recent stored analysis, or null if there is none.
export async function previousAlertIds(repo: string): Promise<Set<string> | null> {
  const ch = getClient();
  if (!ch) return null;
  const last = await ch.query({
    query: `SELECT analysis_id FROM ${DB}.analyses WHERE repo = {repo:String} ORDER BY analyzed_at DESC LIMIT 1`,
    query_params: { repo },
    format: "JSONEachRow",
  });
  const lastRows = (await last.json()) as { analysis_id: string }[];
  if (!lastRows.length) return null;
  const ids = await ch.query({
    query: `SELECT canonical_id FROM ${DB}.findings WHERE analysis_id = {id:String}`,
    query_params: { id: lastRows[0].analysis_id },
    format: "JSONEachRow",
  });
  const idRows = (await ids.json()) as { canonical_id: string }[];
  return new Set(idRows.map((r) => r.canonical_id));
}