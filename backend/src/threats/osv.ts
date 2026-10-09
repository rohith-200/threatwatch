// OSV: which known vulnerabilities affect the exact installed versions.
// Also covers malicious npm packages (OSV "MAL-" entries).

import semver from "semver";
import type { Severity } from "../../../shared/types.js";
import type { Dependency } from "../ingest/index.js";
import { cacheKey, fetchJson, mapLimit, withCache } from "./http.js";
import type { RawAdvisory } from "./types.js";

const OSV = "https://api.osv.dev/v1";
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 5;

interface OsvEvent { introduced?: string; fixed?: string; last_affected?: string }
interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: { type: string; events: OsvEvent[] }[];
  versions?: string[];
}
export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  affected?: OsvAffected[];
  database_specific?: { severity?: string };
}
interface BatchResponse { results: { vulns?: { id: string }[] }[] }

const SEVERITY: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

// Turns OSV range events into semver range pieces, e.g. ["<4.17.19", ">=5.0.0 <5.0.2"].
export function rangePieces(affected: OsvAffected): { range: string; fixed: string | null }[] {
  const pieces: { range: string; fixed: string | null }[] = [];
  for (const r of affected.ranges ?? []) {
    if (r.type !== "SEMVER" && r.type !== "ECOSYSTEM") continue;
    let start: string | null = null;
    for (const e of r.events) {
      if (e.introduced !== undefined) start = e.introduced;
      else if (e.fixed !== undefined && start !== null) {
        pieces.push({ range: start === "0" ? `<${e.fixed}` : `>=${start} <${e.fixed}`, fixed: e.fixed });
        start = null;
      } else if (e.last_affected !== undefined && start !== null) {
        pieces.push({ range: start === "0" ? `<=${e.last_affected}` : `>=${start} <=${e.last_affected}`, fixed: null });
        start = null;
      }
    }
    if (start !== null) pieces.push({ range: start === "0" ? "*" : `>=${start}`, fixed: null });
  }
  if (pieces.length === 0 && affected.versions?.length) {
    pieces.push({ range: affected.versions.join(" || "), fixed: null });
  }
  return pieces;
}

export function toAdvisory(vuln: OsvVuln, dep: Dependency): RawAdvisory {
  const mine = (vuln.affected ?? []).filter((a) => a.package?.ecosystem === "npm" && a.package?.name === dep.name);
  const pieces = mine.flatMap(rangePieces);

  // Fixed version: the one closing the range that contains the installed version,
  // otherwise the lowest fixed version above it.
  const containing = pieces.find((p) => p.fixed && semver.satisfies(dep.version, p.range));
  const above = pieces
    .map((p) => p.fixed)
    .filter((f): f is string => !!f && !!semver.valid(f) && semver.gt(f, dep.version))
    .sort(semver.compare);
  const fixedVersion = containing?.fixed ?? above[0] ?? null;

  const isMalware = vuln.id.startsWith("MAL-");
  const severity: Severity = isMalware ? "critical" : SEVERITY[(vuln.database_specific?.severity ?? "").toUpperCase()] ?? "medium";
  const summary = vuln.summary || (isMalware ? "Malicious package" : (vuln.details ?? "").split("\n")[0].slice(0, 160)) || vuln.id;

  return {
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary,
    published: vuln.published ?? vuln.modified ?? "",
    modified: vuln.modified ?? "",
    severity,
    package: dep.name,
    installedVersion: dep.version,
    isDirect: dep.isDirect,
    isDev: dep.isDev,
    estimated: dep.estimated,
    vulnerableRange: pieces.map((p) => p.range).join(" || ") || "unknown",
    fixedVersion,
    isMalware,
    inKev: false,
    kevDateAdded: null,
    epss: null,
  };
}

export async function queryOsv(deps: Dependency[]): Promise<{ advisories: RawAdvisory[]; fromCache: boolean }> {
  let fromCache = false;

  // 1. Which vulnerability IDs affect each package@version
  const idsPerDep: string[][] = [];
  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    const chunk = deps.slice(i, i + BATCH_SIZE);
    const queries = chunk.map((d) => ({ package: { ecosystem: "npm", name: d.name }, version: d.version }));
    const key = `osv-batch-${cacheKey(JSON.stringify(queries))}`;
    const res = await withCache(key, () =>
      fetchJson<BatchResponse>(`${OSV}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
      }),
    );
    fromCache ||= res.fromCache;
    for (const r of res.data.results) idsPerDep.push((r.vulns ?? []).map((v) => v.id));
  }

  // 2. Full details for each unique ID
  const uniqueIds = [...new Set(idsPerDep.flat())];
  const details = new Map<string, OsvVuln>();
  await mapLimit(uniqueIds, DETAIL_CONCURRENCY, async (id) => {
    const res = await withCache(`osv-${id}`, () => fetchJson<OsvVuln>(`${OSV}/vulns/${encodeURIComponent(id)}`));
    fromCache ||= res.fromCache;
    details.set(id, res.data);
  });

  // 3. One advisory per (vulnerability, installed package)
  const advisories: RawAdvisory[] = [];
  deps.forEach((dep, i) => {
    for (const id of idsPerDep[i] ?? []) {
      const vuln = details.get(id);
      if (vuln) advisories.push(toAdvisory(vuln, dep));
    }
  });
  return { advisories, fromCache };
}