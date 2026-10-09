import type { Advice, Finding } from "../../../shared/types.js";

const unsafeText = /```|\b(payload|exploit code|step[- ]by[- ]step attack|breached|compromised)\b/i;
const idPattern = /\b(?:CVE|GHSA|OSV)[-_A-Z0-9]+\b/gi;
const locationPattern = /([^\s:]+\.(?:js|jsx|ts|tsx|mjs|cjs)):(\d+)/g;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function versionParts(version: string): number[] | null {
  const match = version.trim().replace(/^[v=]/i, "").match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  return match ? [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)] : null;
}

function isAtLeast(version: string, minimum: string): boolean {
  const actual = versionParts(version);
  const required = versionParts(minimum);
  if (!actual || !required) return version === minimum;
  for (let index = 0; index < 3; index += 1) {
    if (actual[index] !== required[index]) return actual[index] > required[index];
  }
  return true;
}

function collectStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(collectStrings);
  if (isRecord(value)) return Object.values(value).flatMap(collectStrings);
  return [];
}

function isAdvice(value: unknown): value is Advice {
  if (!isRecord(value) || !isRecord(value.attackPath) || !isRecord(value.fix)) return false;
  return ["summary", "exploitedInWild", "confidenceNote"].every((key) => typeof value[key] === "string")
    && ["entryPoint", "howItReachesYou", "impact"].every((key) => typeof value.attackPath[key] === "string")
    && typeof value.fix.action === "string"
    && (value.fix.targetVersion === null || typeof value.fix.targetVersion === "string")
    && typeof value.fix.verified === "boolean";
}

export function verifyAdvice(finding: Finding, advice: unknown): Advice | null {
  if (!isAdvice(advice)) return null;

  const strings = collectStrings(advice);
  if (strings.some((text) => unsafeText.test(text))) return null;

  const allowedIds = new Set([finding.canonicalId, ...finding.aliases].map((id) => id.toUpperCase()));
  for (const text of strings) {
    for (const id of text.match(idPattern) ?? []) {
      if (!allowedIds.has(id.toUpperCase())) return null;
    }
  }

  const allText = strings.join(" ");
  if (allText.toLowerCase().includes(finding.package.toLowerCase()) === false) return null;
  if (allText.includes(finding.installedVersion) === false) return null;

  for (const match of allText.matchAll(locationPattern)) {
    const evidenceMatch = finding.evidence.some(
      (item) => item.file === match[1] && item.line === Number(match[2]),
    );
    if (!evidenceMatch) return null;
  }

  if (finding.fixedVersion && advice.fix.targetVersion && !isAtLeast(advice.fix.targetVersion, finding.fixedVersion)) {
    return null;
  }

  if (finding.fixedVersion && advice.fix.targetVersion === null) return null;

  return advice;
}
