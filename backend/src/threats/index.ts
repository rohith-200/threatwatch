// A4: threat search. Dependencies in, matched advisories + coverage numbers out.

import type { Dependency } from "../ingest/index.js";
import { loadEpss } from "./epss.js";
import { countRecentNpmAdvisories, type GhsaCoverage } from "./ghsa.js";
import { loadKev, type KevData } from "./kev.js";
import { queryOsv } from "./osv.js";
import type { RawAdvisory } from "./types.js";

export type { RawAdvisory } from "./types.js";
export { countRecentNpmAdvisories } from "./ghsa.js";

const cvesOf = (a: RawAdvisory) => [a.id, ...a.aliases].filter((x) => x.startsWith("CVE-"));

export async function searchOsv(deps: Dependency[]) {
  return queryOsv(deps);
}

// Adds KEV and EPSS signals to the matched advisories (mutates and returns them).
export async function addExploitSignals(advisories: RawAdvisory[], lookbackDays: number): Promise<{ kev: KevData; epssCount: number }> {
  const [kev, epss] = await Promise.all([loadKev(lookbackDays), loadEpss(advisories.flatMap(cvesOf))]);
  for (const a of advisories) {
    const cves = cvesOf(a);
    const kevCve = cves.find((c) => kev.dateAddedByCve.has(c));
    a.inKev = !!kevCve;
    a.kevDateAdded = kevCve ? kev.dateAddedByCve.get(kevCve)! : null;
    const scores = cves.map((c) => epss.get(c)).filter((s): s is number => s !== undefined);
    a.epss = scores.length ? Math.max(...scores) : null;
  }
  return { kev, epssCount: epss.size };
}

export type { GhsaCoverage, KevData };