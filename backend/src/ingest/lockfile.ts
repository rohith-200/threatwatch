// Turns package.json + package-lock.json into a flat list of installed packages.
// Supports lockfile v1, v2 and v3. Without a lockfile, estimates versions from package.json.

import semver from "semver";

export interface Dependency {
  name: string;
  version: string;
  isDirect: boolean;       // listed in package.json and installed at the top level
  isDev: boolean;          // only needed for development
  estimated: boolean;      // true when the version came from a package.json range, not a lockfile
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface LockEntry {
  name?: string;
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, LockEntry>; // v1 only
}

interface LockFile {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, LockEntry>;
}

const NODE_MODULES = "node_modules/";

export function parsePackageJson(text: string): PackageJson {
  try {
    return JSON.parse(text) as PackageJson;
  } catch {
    throw new Error("package.json is not valid JSON");
  }
}

function directNames(pkg: PackageJson): Set<string> {
  return new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
  ]);
}

// Collapse duplicates of the same name@version, keeping the strongest flags.
function addDep(map: Map<string, Dependency>, dep: Dependency) {
  const key = `${dep.name}@${dep.version}`;
  const existing = map.get(key);
  if (!existing) {
    map.set(key, dep);
    return;
  }
  existing.isDirect ||= dep.isDirect;
  existing.isDev &&= dep.isDev; // prod if any copy is prod
}

function fromPackagesSection(lock: LockFile, direct: Set<string>): Dependency[] {
  const map = new Map<string, Dependency>();
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (key === "" || entry.link || !entry.version) continue;
    const idx = key.lastIndexOf(NODE_MODULES);
    if (idx === -1) continue; // workspace folders, not installed packages
    const name = entry.name ?? key.slice(idx + NODE_MODULES.length);
    if (!semver.valid(entry.version)) continue; // skip git/file/alias versions
    const topLevel = key === `${NODE_MODULES}${name}`;
    addDep(map, { name, version: entry.version, isDirect: topLevel && direct.has(name), isDev: entry.dev === true, estimated: false });
  }
  return [...map.values()];
}

function fromV1Section(lock: LockFile, direct: Set<string>): Dependency[] {
  const map = new Map<string, Dependency>();
  const walk = (deps: Record<string, LockEntry> | undefined, depth: number) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      if (entry.version && semver.valid(entry.version)) {
        addDep(map, { name, version: entry.version, isDirect: depth === 0 && direct.has(name), isDev: entry.dev === true, estimated: false });
      }
      walk(entry.dependencies, depth + 1);
    }
  };
  walk(lock.dependencies, 0);
  return [...map.values()];
}

function fromPackageJsonOnly(pkg: PackageJson): Dependency[] {
  const deps: Dependency[] = [];
  const add = (ranges: Record<string, string> | undefined, isDev: boolean) => {
    for (const [name, range] of Object.entries(ranges ?? {})) {
      const min = semver.validRange(range) ? semver.minVersion(range) : null;
      if (min) deps.push({ name, version: min.version, isDirect: true, isDev, estimated: true });
    }
  };
  add(pkg.dependencies, false);
  add(pkg.optionalDependencies, false);
  add(pkg.devDependencies, true);
  return deps;
}

export function parseDependencies(packageJsonText: string, lockText: string | null): Dependency[] {
  const pkg = parsePackageJson(packageJsonText);
  if (!lockText) return fromPackageJsonOnly(pkg);

  let lock: LockFile;
  try {
    lock = JSON.parse(lockText) as LockFile;
  } catch {
    return fromPackageJsonOnly(pkg); // broken lockfile: fall back rather than fail
  }

  const direct = directNames(pkg);
  const deps = lock.packages ? fromPackagesSection(lock, direct) : fromV1Section(lock, direct);
  return deps.sort((a, b) => Number(b.isDirect) - Number(a.isDirect) || a.name.localeCompare(b.name));
}