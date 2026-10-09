// Small helpers for threat-feed requests: JSON fetch with timeout, disk cache, concurrency limit.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";

const TIMEOUT_MS = 10_000;
const CACHE_DIR = path.resolve(process.cwd(), "../fixtures/cache");

export async function fetchJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { "User-Agent": "threatwatch", Accept: "application/json", ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`${res.status} from ${url}`);
  return (await res.json()) as T;
}

export function cacheKey(...parts: string[]): string {
  return createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 16);
}

// Tries the network first and saves the result. If the network fails, falls back to the
// last saved copy. Throws only if both fail.
export async function withCache<T>(name: string, load: () => Promise<T>): Promise<{ data: T; fromCache: boolean }> {
  const file = path.join(CACHE_DIR, `${name}.json`);
  try {
    const data = await load();
    await mkdir(CACHE_DIR, { recursive: true });
    await writeFile(file, JSON.stringify(data));
    return { data, fromCache: false };
  } catch (err) {
    try {
      return { data: JSON.parse(await readFile(file, "utf8")) as T, fromCache: true };
    } catch {
      throw err;
    }
  }
}

// Runs fn over items with at most `limit` running at once, keeping order.
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}