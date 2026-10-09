// GitHub access for repo ingest: URL validation, file fetching, shallow clone.
// Never runs anything from the analyzed repo. Clone uses execFile (no shell).

import { execFile } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const REPO_URL = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;
const API = "https://api.github.com";
const CLONE_TIMEOUT_MS = 60_000;
const FETCH_TIMEOUT_MS = 15_000;

// An error whose message is safe to show to the user.
export class IngestError extends Error {
  constructor(public userMessage: string, detail?: string) {
    super(detail ?? userMessage);
  }
}

export interface RepoRef {
  owner: string;
  repo: string;
}

export function parseRepoUrl(url: string): RepoRef {
  const match = REPO_URL.exec(url.trim());
  if (!match || match[2] === "." || match[2] === "..") {
    throw new IngestError("Enter a GitHub repo URL like https://github.com/owner/repo");
  }
  return { owner: match[1], repo: match[2] };
}

function headers(accept: string): Record<string, string> {
  const h: Record<string, string> = {
    Accept: accept,
    "User-Agent": "threatwatch",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

async function githubFetch(url: string, accept: string): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(url, { headers: headers(accept), signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new IngestError("Couldn't reach GitHub. Check your connection and try again.", String(err));
  }
  if (res.status === 403 || res.status === 429) {
    throw new IngestError("GitHub rate limit reached. Try again in a few minutes.", `GitHub ${res.status} for ${url}`);
  }
  if (res.status === 401) {
    throw new IngestError("The server's GitHub token is invalid or expired.", `GitHub 401 for ${url}`);
  }
  return res;
}

export interface RepoMeta {
  defaultBranch: string;
  commitSha: string;
}

export async function fetchRepoMeta({ owner, repo }: RepoRef): Promise<RepoMeta> {
  const repoRes = await githubFetch(`${API}/repos/${owner}/${repo}`, "application/vnd.github+json");
  if (repoRes.status === 404) {
    throw new IngestError("Couldn't find that repo. Check the URL and that the repo is public.");
  }
  if (!repoRes.ok) throw new IngestError("GitHub returned an error. Try again.", `GitHub ${repoRes.status}`);
  const repoJson = (await repoRes.json()) as { default_branch: string; private: boolean };
  if (repoJson.private) throw new IngestError("ThreatWatch only analyzes public repos.");

  const branch = repoJson.default_branch;
  const commitRes = await githubFetch(
    `${API}/repos/${owner}/${repo}/commits/${encodeURIComponent(branch)}`,
    "application/vnd.github+json",
  );
  if (!commitRes.ok) throw new IngestError("Couldn't read the repo's latest commit.", `GitHub ${commitRes.status}`);
  const commitJson = (await commitRes.json()) as { sha: string };
  return { defaultBranch: branch, commitSha: commitJson.sha };
}

// Returns the file's text, or null if it doesn't exist. Works for files over 1 MB.
export async function fetchFile({ owner, repo }: RepoRef, filePath: string, ref: string): Promise<string | null> {
  const url = `${API}/repos/${owner}/${repo}/contents/${filePath}?ref=${encodeURIComponent(ref)}`;
  const res = await githubFetch(url, "application/vnd.github.raw+json");
  if (res.status === 404) return null;
  if (!res.ok) throw new IngestError(`Couldn't read ${filePath} from the repo.`, `GitHub ${res.status}`);
  return res.text();
}

// Shallow clone into backend/tmp/<analysisId>/ for static scanning only.
export async function shallowClone({ owner, repo }: RepoRef, branch: string, analysisId: string): Promise<string> {
  const tmpRoot = path.resolve(process.cwd(), "tmp");
  const dest = path.join(tmpRoot, analysisId);
  await mkdir(tmpRoot, { recursive: true });
  await rm(dest, { recursive: true, force: true });

  try {
    await execFileAsync(
      "git",
      [
        "-c", "core.symlinks=false",
        "clone", "--depth", "1", "--single-branch", "--branch", branch,
        `https://github.com/${owner}/${repo}.git`, dest,
      ],
      {
        timeout: CLONE_TIMEOUT_MS,
        env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_LFS_SKIP_SMUDGE: "1" },
      },
    );
  } catch (err) {
    await rm(dest, { recursive: true, force: true });
    throw new IngestError("Couldn't download the repo's code. Try again.", String(err));
  }
  return dest;
}

export async function removeClone(dir: string | null): Promise<void> {
  if (dir) await rm(dir, { recursive: true, force: true });
}