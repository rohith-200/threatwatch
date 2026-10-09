import type { Severity } from "../../../shared/types.js";

// One advisory matched to one installed package, before dedupe and scoring (A5/A7).
export interface RawAdvisory {
  id: string;                    // OSV ID, usually GHSA-... (MAL-... for malicious packages)
  aliases: string[];             // other IDs, e.g. CVE-...
  summary: string;
  published: string;             // ISO 8601
  modified: string;
  severity: Severity;
  package: string;
  installedVersion: string;
  isDirect: boolean;
  isDev: boolean;
  estimated: boolean;            // version estimated from package.json (no lockfile)
  vulnerableRange: string;       // semver range, e.g. "<4.17.19 || >=5.0.0 <5.0.2"
  fixedVersion: string | null;   // lowest fixed version above the installed one
  isMalware: boolean;
  inKev: boolean;
  kevDateAdded: string | null;
  epss: number | null;           // 0..1
}