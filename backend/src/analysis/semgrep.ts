// A6: runs our custom Semgrep rules on the shallow clone and returns code evidence.
// Static analysis only: nothing from the repo is executed. Only rule ID, file and line
// are kept; the matched source code is dropped so it never reaches logs or the AI model.

import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import type { Evidence } from "../../../shared/types.js";

const execFileAsync = promisify(execFile);

const RULES_DIR = path.resolve(process.cwd(), "rules");
const SEMGREP_BIN = process.env.SEMGREP_BIN || "semgrep";
const SCAN_TIMEOUT_MS = 90_000;
const EXCLUDES = ["node_modules", ".git", "dist", "build", "coverage", "vendor", "*.min.js", "test", "tests", "__tests__"];

export interface SemgrepHit extends Evidence {
  package: string;        // from the rule's metadata.package
  advisories: string[];   // advisory IDs this hit is evidence for
}

export interface SemgrepResult {
  hits: SemgrepHit[];
  available: boolean;     // false if Semgrep isn't installed or the scan failed
  error?: string;
}

interface SemgrepJson {
  results: {
    check_id: string;
    path: string;
    start: { line: number };
    extra: { metadata?: { package?: string; advisories?: string[] } };
  }[];
  errors: { message?: string }[];
}

export async function runSemgrep(cloneDir: string): Promise<SemgrepResult> {
  const args = [
    "scan",
    "--config", RULES_DIR,
    "--json",
    "--metrics=off",
    "--disable-version-check",
    "--quiet",
    "--timeout", "30",
    ...EXCLUDES.flatMap((e) => ["--exclude", e]),
    cloneDir,
  ];

  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(SEMGREP_BIN, args, {
      timeout: SCAN_TIMEOUT_MS,
      maxBuffer: 20 * 1024 * 1024,
      env: { ...process.env, SEMGREP_SEND_METRICS: "off" },
    }));
  } catch (err) {
    // Semgrep can exit non-zero yet still print valid results; use them if present.
    const out = (err as { stdout?: string }).stdout;
    if (!out) {
      const code = (err as { code?: string }).code;
      const reason = code === "ENOENT" ? "Semgrep is not installed or not on PATH" : String(err);
      return { hits: [], available: false, error: reason };
    }
    stdout = out;
  }

  let parsed: SemgrepJson;
  try {
    parsed = JSON.parse(stdout) as SemgrepJson;
  } catch {
    return { hits: [], available: false, error: "Semgrep returned output that isn't JSON" };
  }

  const seen = new Set<string>();
  const hits: SemgrepHit[] = [];
  for (const r of parsed.results) {
    const ruleId = r.check_id.split(".").pop() ?? r.check_id; // Semgrep prefixes IDs with the config path
    const file = path.relative(cloneDir, path.resolve(cloneDir, r.path)).split(path.sep).join("/");
    const meta = r.extra.metadata ?? {};
    if (!meta.package || !meta.advisories?.length) continue; // rules without a mapping aren't evidence
    const key = `${ruleId}|${file}|${r.start.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({ ruleId, file, line: r.start.line, package: meta.package, advisories: meta.advisories });
  }
  hits.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  const errorCount = parsed.errors.length;
  return { hits, available: true, error: errorCount ? `${errorCount} Semgrep warnings` : undefined };
}

// The evidence for one advisory: hits for the same package whose rule lists this
// advisory's ID or one of its aliases. Used by classification (A5/A7).
export function evidenceFor(pkg: string, ids: string[], hits: SemgrepHit[]): Evidence[] {
  const wanted = new Set(ids);
  return hits
    .filter((h) => h.package === pkg && h.advisories.some((a) => wanted.has(a)))
    .map(({ ruleId, file, line }) => ({ ruleId, file, line }));
}