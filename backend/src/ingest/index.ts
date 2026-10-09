// A3: repo ingest. Repo URL in, dependency list + shallow clone out.

import { fetchFile, fetchRepoMeta, IngestError, parseRepoUrl, shallowClone } from "./github.js";
import { parseDependencies, type Dependency } from "./lockfile.js";

export { IngestError, removeClone } from "./github.js";
export type { Dependency } from "./lockfile.js";

export interface IngestResult {
  owner: string;
  repo: string;
  commit: string;          // short SHA for display
  commitSha: string;       // full SHA
  dependencies: Dependency[];
  directCount: number;
  hasLockfile: boolean;
  cloneDir: string;        // delete with removeClone() when the analysis ends
}

export async function ingestRepo(repoUrl: string, analysisId: string): Promise<IngestResult> {
  const ref = parseRepoUrl(repoUrl);
  const meta = await fetchRepoMeta(ref);

  const [packageJson, lockfile] = await Promise.all([
    fetchFile(ref, "package.json", meta.commitSha),
    fetchFile(ref, "package-lock.json", meta.commitSha),
  ]);
  if (!packageJson) {
    throw new IngestError("No package.json found at the repo root. ThreatWatch supports npm projects only.");
  }

  let dependencies: Dependency[];
  try {
    dependencies = parseDependencies(packageJson, lockfile);
  } catch (err) {
    throw new IngestError("Couldn't read the repo's package.json.", String(err));
  }

  const cloneDir = await shallowClone(ref, meta.defaultBranch, analysisId);

  return {
    owner: ref.owner,
    repo: ref.repo,
    commit: meta.commitSha.slice(0, 7),
    commitSha: meta.commitSha,
    dependencies,
    directCount: dependencies.filter((d) => d.isDirect).length,
    hasLockfile: lockfile !== null,
    cloneDir,
  };
}