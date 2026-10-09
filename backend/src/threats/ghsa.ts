// GitHub Advisory Database: how many npm advisories were published in the window.
// Used for the coverage line ("1,240 recent advisories checked"), not for matching.

const API = "https://api.github.com/advisories";
const MAX_PAGES = 10; // 1,000 advisories is plenty for a coverage number

export interface GhsaCoverage {
  count: number | null;           // null if GitHub couldn't be reached
  capped: boolean;                // true if there were more than MAX_PAGES * 100
  newestPublished: string | null;
}

export async function countRecentNpmAdvisories(lookbackDays: number): Promise<GhsaCoverage> {
  const since = new Date(Date.now() - lookbackDays * 864e5).toISOString().slice(0, 10);
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "threatwatch",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  let url: string | null =
    `${API}?ecosystem=npm&published=${encodeURIComponent(`>=${since}`)}&sort=published&direction=desc&per_page=100`;
  let count = 0;
  let newestPublished: string | null = null;

  try {
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res: Response = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`GitHub ${res.status}`);
      const items = (await res.json()) as { published_at: string }[];
      if (page === 0) newestPublished = items[0]?.published_at ?? null;
      count += items.length;
      const next: RegExpMatchArray | null = (res.headers.get("link") ?? "").match(/<([^>]+)>;\s*rel="next"/);
      url = next ? next[1] : null;
    }
    return { count, capped: url !== null, newestPublished };
  } catch {
    return { count: null, capped: false, newestPublished: null };
  }
}