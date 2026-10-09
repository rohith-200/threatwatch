// A5 + A7: dedupe raw advisories, double-check versions, attach evidence, classify and score.

import semver from "semver";
import type { Finding, ScoreBreakdown, Severity, Source } from "../../../shared/types.js";
import type { RawAdvisory } from "../threats/index.js";
import { evidenceFor, type SemgrepHit } from "./semgrep.js";

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY_POINTS: Record<Severity, number> = { critical: 40, high: 30, medium: 15, low: 5 };

// ---- A5: dedupe ----

// Groups advisories for the same installed package that share any ID (directly or via aliases).
export function dedupe(raw: RawAdvisory[]): RawAdvisory[][] {
  const groups: RawAdvisory[][] = [];
  const byPackage = new Map<string, RawAdvisory[]>();
  for (const a of raw) {
    const key = `${a.package}@${a.installedVersion}`;
    byPackage.set(key, [...(byPackage.get(key) ?? []), a]);
  }
  for (const list of byPackage.values()) {
    const parent = list.map((_, i) => i);
    const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const owner = new Map<string, number>();
    list.forEach((a, i) => {
      for (const id of [a.id, ...a.aliases]) {
        const j = owner.get(id);
        if (j === undefined) owner.set(id, i);
        else parent[find(i)] = find(j);
      }
    });
    const merged = new Map<number, RawAdvisory[]>();
    list.forEach((a, i) => merged.set(find(i), [...(merged.get(find(i)) ?? []), a]));
    groups.push(...merged.values());
  }
  return groups;
}

// ---- A7: score ----

export function score(f: Pick<Finding, "severity" | "inKev" | "epss" | "evidence" | "isDirect" | "isNew" | "fixedVersion">): { riskScore: number; scoreBreakdown: ScoreBreakdown } {
  const b: ScoreBreakdown = { severity: SEVERITY_POINTS[f.severity] };
  if (f.inKev) b.kev = 25;
  if (f.epss !== null) {
    const pts = Math.min(15, Math.round(f.epss * 30));
    if (pts > 0) b.epss = pts;
  }
  if (f.evidence.length > 0) b.semgrep = 15;
  if (f.isDirect) b.direct = 10;
  if (f.isNew) b.recent = 10;
  if (f.fixedVersion) b.fixAvailable = 5;
  const total = Object.values(b).reduce((sum, n) => sum + (n ?? 0), 0);
  return { riskScore: Math.min(100, total), scoreBreakdown: b };
}

// ---- Merge one group into a Finding ----

function toFinding(group: RawAdvisory[], hits: SemgrepHit[], lookbackDays: number, now: number): Finding | null {
  const first = [...group].sort((a, b) => Date.parse(a.published) - Date.parse(b.published))[0];
  const allIds = [...new Set(group.flatMap((a) => [a.id, ...a.aliases]))];
  const cves = allIds.filter((id) => id.startsWith("CVE-")).sort();
  const ghsas = allIds.filter((id) => id.startsWith("GHSA-")).sort();
  const canonicalId = cves[0] ?? ghsas[0] ?? first.id;

  // Double-check the installed version really is inside a vulnerable range.
  const ranges = [...new Set(group.map((a) => a.vulnerableRange).filter((r) => r !== "unknown"))];
  if (ranges.length && !ranges.some((r) => semver.validRange(r) && semver.satisfies(first.installedVersion, r, { includePrerelease: true }))) {
    return null; // not affected
  }

  const fixes = group.map((a) => a.fixedVersion).filter((v): v is string => !!v && !!semver.valid(v));
  const fixedVersion = fixes.length ? fixes.sort(semver.rcompare)[0] : null; // highest fix covers every merged advisory
  const severity = group.reduce<Severity>((s, a) => (SEVERITY_RANK[a.severity] > SEVERITY_RANK[s] ? a.severity : s), "low");
  const epssValues = group.map((a) => a.epss).filter((e): e is number => e !== null);
  const inKev = group.some((a) => a.inKev);
  const published = first.published;
  const isNew = Date.parse(published) >= now - lookbackDays * 864e5;
  const evidence = evidenceFor(first.package, allIds, hits);

  const sources: Source[] = ["osv"];
  if (ghsas.length) sources.push("ghsa");
  if (inKev) sources.push("kev");

  const base = {
    severity,
    inKev,
    epss: epssValues.length ? Math.max(...epssValues) : null,
    evidence,
    isDirect: group.some((a) => a.isDirect),
    isNew,
    fixedVersion,
  };

  return {
    canonicalId,
    aliases: allIds.filter((id) => id !== canonicalId),
    title: first.summary,
    package: first.package,
    installedVersion: first.installedVersion,
    fixedVersion,
    isDirect: base.isDirect,
    severity,
    published,
    isNew,
    inKev,
    epss: base.epss,
    // Code evidence makes it "likely". Estimated versions (no lockfile) stay "potentially".
    status: evidence.length > 0 && !group.some((a) => a.estimated) ? "likely_affected" : "potentially_affected",
    ...score(base),
    evidence,
    sources,
    simulated: false,
    advice: null,
    evidenceCheck: "not_run",
  };
}

export function classify(raw: RawAdvisory[], hits: SemgrepHit[], lookbackDays: number, now = Date.now()): Finding[] {
  return dedupe(raw)
    .map((g) => toFinding(g, hits, lookbackDays, now))
    .filter((f): f is Finding => f !== null)
    .sort((a, b) => Number(b.isNew) - Number(a.isNew) || b.riskScore - a.riskScore);
}