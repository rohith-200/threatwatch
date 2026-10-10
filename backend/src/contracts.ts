// The four functions where Person A's pipeline calls Person B's code.
// Person A imports from this file from day one and never waits.
// Person B later replaces each stub body with a call to the real module
// (ai/, store/, observability/). The signatures must not change without agreement.

import type { Finding, Report } from "../../shared/types.js";
import { explainFindings as runAdvice } from "./ai/advice.js";
import { storeReport } from "./store/clickhouse.js";

export interface TraceMeta {
  analysisId: string;
  repo: string;
  commit: string;
  lookbackDays: number;
}

export interface Trace {
  id: string | null; // null when tracing is off
}

// Opens one trace for the whole analysis. Must never receive tokens or source code.
export type StartTrace = (meta: TraceMeta) => Promise<Trace>;

// Times one pipeline step. Must return fn's result unchanged and rethrow its errors.
export type WithSpan = <T>(trace: Trace, name: string, fn: () => Promise<T>) => Promise<T>;

// Adds verified AI advice to the top alerts (at most 5).
// Must return every finding it received, in the same order, changing only
// `advice` and `evidenceCheck`. Must not throw: on any failure, use template advice.
export type ExplainFindings = (findings: Finding[], trace: Trace) => Promise<Finding[]>;

// Stores the finished report so GET /api/analyses/:id can return it.
export type SaveReport = (report: Report) => Promise<void>;

// ---- Stubs (Person A uses these until Person B's versions are ready) ----

export const startTrace: StartTrace = async () => ({ id: null });

export const withSpan: WithSpan = async (_trace, _name, fn) => fn();

export const explainFindings: ExplainFindings = async (findings, _trace) =>
  runAdvice(findings);

export const saveReport: SaveReport = async (report) => storeReport(report);