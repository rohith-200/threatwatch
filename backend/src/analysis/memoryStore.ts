// TEMPORARY in-memory report store, so real reports show in the UI before ClickHouse storage lands.
// Reports are lost when the server restarts. Replaced by the ClickHouse store.

import type { Report } from "../../../shared/types.js";

const reports = new Map<string, Report>();

export function rememberReport(report: Report): void {
  reports.set(report.analysisId, report);
}

export function recallReport(id: string): Report | undefined {
  return reports.get(id);
}

// The most recent earlier report for the same repo, if any.
export function previousReportFor(repo: string): Report | undefined {
  return [...reports.values()]
    .filter((r) => r.repo === repo)
    .sort((a, b) => Date.parse(b.analyzedAt) - Date.parse(a.analyzedAt))[0];
}