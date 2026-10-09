// EPSS: daily probability (0..1) that a CVE will be exploited. Optional signal.

import { fetchJson } from "./http.js";

const EPSS_URL = "https://api.first.org/data/v1/epss";
const BATCH = 100;

interface EpssResponse { data: { cve: string; epss: string }[] }

export async function loadEpss(cves: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  const unique = [...new Set(cves)];
  for (let i = 0; i < unique.length; i += BATCH) {
    const chunk = unique.slice(i, i + BATCH);
    try {
      const res = await fetchJson<EpssResponse>(`${EPSS_URL}?cve=${chunk.join(",")}`);
      for (const row of res.data) scores.set(row.cve, Number(row.epss));
    } catch {
      // Missing EPSS just means no EPSS points in the score.
    }
  }
  return scores;
}