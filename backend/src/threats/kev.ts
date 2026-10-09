// CISA Known Exploited Vulnerabilities: CVEs attackers are using in the wild.

import { fetchJson, withCache } from "./http.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevFeed { vulnerabilities: { cveID: string; dateAdded: string }[] }

export interface KevData {
  dateAddedByCve: Map<string, string>;
  addedInWindow: number;
  fromCache: boolean;
  available: boolean;
}

export async function loadKev(lookbackDays: number): Promise<KevData> {
  try {
    const { data, fromCache } = await withCache("kev", () => fetchJson<KevFeed>(KEV_URL));
    const since = Date.now() - lookbackDays * 864e5;
    const dateAddedByCve = new Map(data.vulnerabilities.map((v) => [v.cveID, v.dateAdded]));
    const addedInWindow = data.vulnerabilities.filter((v) => Date.parse(v.dateAdded) >= since).length;
    return { dateAddedByCve, addedInWindow, fromCache, available: true };
  } catch {
    // KEV is an extra signal: carry on without it rather than fail the analysis.
    return { dateAddedByCve: new Map(), addedInWindow: 0, fromCache: false, available: false };
  }
}