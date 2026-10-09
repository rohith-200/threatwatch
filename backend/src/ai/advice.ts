import type { Advice, Finding } from "../../../shared/types.js";
import { explainFinding } from "./akashml.js";
import { verifyAdvice } from "./verify.js";

function templateAdvice(finding: Finding): Advice {
  const location = finding.evidence[0]
    ? ` Review ${finding.evidence[0].file}:${finding.evidence[0].line}.`
    : " No specific code usage was identified.";

  return {
    summary: `Review the ${finding.package} dependency and its reported advisory.${location}`,
    attackPath: {
      entryPoint: finding.evidence[0]
        ? `${finding.evidence[0].file}:${finding.evidence[0].line}`
        : "Not identified",
      howItReachesYou: `The repository contains ${finding.package}@${finding.installedVersion}, which matches the reported affected version range based on current evidence.`,
      impact: "Potential impact depends on whether the affected functionality is reached by the application.",
    },
    exploitedInWild: finding.inKev ? "Listed in CISA KEV." : "Not listed in CISA KEV based on current evidence.",
    fix: {
      action: finding.fixedVersion
        ? `Upgrade ${finding.package} to ${finding.fixedVersion} or later.`
        : `Review and remediate the ${finding.package} advisory according to the upstream guidance.`,
      targetVersion: finding.fixedVersion,
      verified: Boolean(finding.fixedVersion),
    },
    confidenceNote: `${finding.status === "likely_affected" ? "Likely" : "Potentially"} affected based on current evidence.`,
  };
}

function parseAdvice(raw: string): unknown {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  return JSON.parse(cleaned);
}

export async function explainFindings(findings: Finding[]): Promise<Finding[]> {
  const selected = new Set(
    [...findings]
      .sort((left, right) => right.riskScore - left.riskScore)
      .slice(0, 5),
  );

  return Promise.all(
    findings.map(async (finding) => {
      if (!selected.has(finding)) return finding;

      try {
        const raw = await explainFinding(finding);
        const verified = verifyAdvice(finding, parseAdvice(raw));
        return verified
          ? { ...finding, advice: verified, evidenceCheck: "passed" as const }
          : { ...finding, advice: templateAdvice(finding), evidenceCheck: "fallback" as const };
      } catch {
        return { ...finding, advice: templateAdvice(finding), evidenceCheck: "fallback" as const };
      }
    }),
  );
}
