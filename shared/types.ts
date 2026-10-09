// ThreatWatch shared contract.
// Both the backend and the frontend import from this file.
// Change it only after both of us agree, then commit and tell the other person.

export type Severity = "critical" | "high" | "medium" | "low";
export type Status = "likely_affected" | "potentially_affected" | "not_affected";
export type Source = "osv" | "ghsa" | "kev";
export type EvidenceCheck = "passed" | "fallback" | "not_run";

// What the input screen sends to POST /api/analyze
export interface AnalyzeRequest {
  repoUrl: string;              // https://github.com/<owner>/<repo>
  lookbackDays: 7 | 30 | 90;
  simulate?: boolean;           // inject the labeled simulated advisory (demo only)
}

// One Semgrep match. Never contains source code, only its location.
export interface Evidence {
  ruleId: string;
  file: string;                 // path relative to the repo root
  line: number;
}

// Points per scoring factor. Only factors that applied are present.
export interface ScoreBreakdown {
  severity?: number;
  kev?: number;
  epss?: number;
  semgrep?: number;
  direct?: number;
  recent?: number;
  fixAvailable?: number;
}

// AI-written explanation for one alert (AkashML), after verification
export interface Advice {
  summary: string;
  attackPath: {
    entryPoint: string;         // e.g. "POST /login"
    howItReachesYou: string;
    impact: string;
  };
  exploitedInWild: string;      // e.g. "Not in CISA KEV; EPSS 40%"
  fix: {
    action: string;
    targetVersion: string | null;
    verified: boolean;          // true only if targetVersion >= fixedVersion
  };
  confidenceNote: string;
}

// One alert: a vulnerability that matches an installed dependency
export interface Finding {
  canonicalId: string;          // CVE if present, else GHSA, else OSV ID
  aliases: string[];            // all other IDs for the same vulnerability
  title: string;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  isDirect: boolean;            // listed in package.json, not only transitive
  severity: Severity;
  published: string;            // ISO 8601
  isNew: boolean;               // published inside the lookback window
  inKev: boolean;               // in CISA Known Exploited Vulnerabilities
  epss: number | null;          // exploit probability 0..1, null if unknown
  status: Status;
  riskScore: number;            // 0..100
  scoreBreakdown: ScoreBreakdown;
  evidence: Evidence[];         // empty when no usage was found
  sources: Source[];
  simulated: boolean;           // true only for the injected demo advisory
  advice: Advice | null;        // null until the AI step has run
  evidenceCheck: EvidenceCheck;
}

export interface Coverage {
  dependencies: number;
  directDependencies: number;
  recentAdvisoriesChecked: number;   // npm advisories published in the window
  kevChecked: number;                // KEV entries added in the window
  threatDataFetchedAt: string;       // ISO 8601
  newestAdvisoryPublished: string | null;
  fromCache: boolean;                // true if a source failed and cache was used
}

export interface Summary {
  newAffecting: number;
  knownAffecting: number;
  notAffecting: number;              // recent threats checked that don't affect the repo
  sinceLastAnalysis: number | null;  // null when there is no previous analysis
}

// The full output of one analysis
export interface Report {
  analysisId: string;
  repo: string;                      // "<owner>/<repo>"
  commit: string;                    // short SHA
  analyzedAt: string;                // ISO 8601
  lookbackDays: 7 | 30 | 90;
  traceId: string | null;            // observability trace, if any
  coverage: Coverage;
  summary: Summary;
  alerts: Finding[];                 // likely and potentially affected only,
                                     // sorted: isNew first, then riskScore desc
}

// Pipeline steps, in order, as shown on the progress list
export type StepName =
  | "ingest"
  | "osv"
  | "ghsa"
  | "kev"
  | "semgrep"
  | "score"
  | "advice"
  | "save";

// Events streamed by POST /api/analyze (server-sent events)
export type ProgressEvent =
  | { type: "progress"; step: StepName; status: "running" | "done"; message: string; count?: number }
  | { type: "result"; analysisId: string }
  | { type: "error"; message: string };
