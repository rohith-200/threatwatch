import "dotenv/config";
import OpenAI from "openai";
import type { Finding } from "../../../shared/types.js";

const apiKey = process.env.AKASHML_API_KEY;
const baseURL = process.env.AKASHML_BASE_URL;
const model = process.env.AKASHML_MODEL;

if (!apiKey) {
  throw new Error("AKASHML_API_KEY is not configured");
}

if (!baseURL) {
  throw new Error("AKASHML_BASE_URL is not configured");
}

if (!model) {
  throw new Error("AKASHML_MODEL is not configured");
}

export const akashml = new OpenAI({
  apiKey,
  baseURL,
  timeout: 20_000,
});

export async function explainFinding(finding: Finding): Promise<string> {
  const evidence = {
    canonicalId: finding.canonicalId,
    aliases: finding.aliases,
    title: finding.title,
    package: finding.package,
    installedVersion: finding.installedVersion,
    fixedVersion: finding.fixedVersion,
    severity: finding.severity,
    inKev: finding.inKev,
    epss: finding.epss,
    evidence: finding.evidence,
    status: finding.status,
  };

  const response = await akashml.chat.completions.create({
    model,
    temperature: 0.2,
    messages: [
      {
        role: "system",
        content:
          "Explain security findings using only the supplied structured evidence. Do not invent IDs, versions, files, lines, impacts, or exploit claims. Do not provide exploit code or payloads.",
      },
      {
        role: "user",
        content: JSON.stringify(evidence),
      },
    ],
  });

  return response.choices[0]?.message?.content ?? "";
}
