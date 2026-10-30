/**
 * Package check. Answers four questions about each dependency by READING the public registries:
 *   made_up     the name does not exist on npm / PyPI (AI assistants invent names; attackers register them)  → fix_now
 *   brand_new   first published less than 14 days ago                                                      → fix_week
 *   lookalike   one or two letters away from a popular package and not established itself                  → fix_week
 *   vulnerable  the pinned version has a known advisory in OSV (critical/high → fix_now, else fix_week)
 * A registry that does not answer (timeout, 5xx, network) gives "unknown", never an alarm. Download counts are only
 * supporting evidence (they can clear a lookalike; they never raise anything on their own).
 *
 * SAFE BY CONSTRUCTION: manifests are parsed as text (JSON.parse / line reading), never executed; the fetcher can only
 * reach FOUR fixed public hosts (registry.npmjs.org, api.npmjs.org, pypi.org, api.osv.dev), so nothing in a manifest
 * can steer a request anywhere else; GET everywhere except OSV's read-only query endpoint; 3 s per request; at most 4
 * at once; one answer per URL per run. Only package names and pinned versions are sent, never your code.
 */
import { POPULAR_NPM, POPULAR_PYPI } from "./popular-packages";

export type Ecosystem = "npm" | "pypi";
export interface Dependency { name: string; ecosystem: Ecosystem; /** As written in the manifest (a range or a pin). */ spec?: string }
export type PackageSeverity = "fix_now" | "fix_week";
export type PackageIssue = "made_up" | "brand_new" | "lookalike" | "vulnerable";

export interface PackageFinding {
  name: string; ecosystem: Ecosystem; issue: PackageIssue; severity: PackageSeverity;
  /** lookalike: the popular package it resembles. */ similarTo?: string;
  /** brand_new: when it was first published (ISO). */ firstPublished?: string;
  /** vulnerable: the pinned version, the advisory and the first fixed version (when OSV lists one). */
  version?: string; advisory?: string; fixedIn?: string | null;
}
export interface PackageCheckResult {
  findings: PackageFinding[];
  /** Names the registries could not answer for: nothing is claimed about them. */
  unknown: { name: string; ecosystem: Ecosystem }[];
  checked: number;
}

// ── Words (English) ───────────────────────────────────────────────────────────────────────────────────────────────
const COPY: Record<PackageIssue, string> & { noFix: string; fixedIn: string } = {
  made_up: "This package doesn't exist on {registry}. AI assistants sometimes invent package names, and attackers register those names with malware. Check the spelling or remove it.",
  brand_new: "This package was published in the last 14 days. Check who made it before you install it.",
  lookalike: "This name is one or two letters away from the popular package {similar}. Make sure you meant this one and not {similar}.",
  vulnerable: "This version has a known security problem ({id}). Update it.",
  noFix: "No fixed version is listed yet.",
  fixedIn: "Fixed in {fixed}.",
};

/** The plain-English sentence for one finding. */
export function packageMessage(f: PackageFinding): string {
  const registry = f.ecosystem === "npm" ? "npm" : "PyPI";
  let text = COPY[f.issue].replace(/\{registry\}/g, registry).replace(/\{similar\}/g, f.similarTo ?? "").replace(/\{id\}/g, f.advisory ?? "");
  if (f.issue === "vulnerable") text += ` ${f.fixedIn ? COPY.fixedIn.replace("{fixed}", f.fixedIn) : COPY.noFix}`;
  return text;
}

// ── Fetching: four fixed hosts only ──────────────────────────────────────────────────────────────────────────────
export const PACKAGE_HOSTS = ["registry.npmjs.org", "api.npmjs.org", "pypi.org", "api.osv.dev"] as const;
export const PACKAGE_UA = "yof-cli (+https://yof.io)";
export const PACKAGE_TIMEOUT_MS = 3000;
export const PACKAGE_CONCURRENCY = 4;
export const BRAND_NEW_DAYS = 14;
/** Weekly npm downloads at or above this mark a package as established (it clears a lookalike, nothing more). */
export const ESTABLISHED_WEEKLY_DOWNLOADS = 10_000;
/** OSV advisory details fetched per run at most (each is one GET). */
export const MAX_ADVISORY_LOOKUPS = 10;

export interface PackageResponse { status: number; json?: unknown }
/** status 0 = no answer (timeout or network). Tests pass a mock; the CLI uses packageFetcher(). */
export type PackageFetcher = (url: string, init?: { method?: "GET" | "POST"; body?: string }) => Promise<PackageResponse>;

/** The real fetcher: refuses any host outside PACKAGE_HOSTS, https only, 3 s timeout, no redirects, no cookies. */
export function packageFetcher(f: typeof fetch = fetch, timeoutMs = PACKAGE_TIMEOUT_MS): PackageFetcher {
  return async (url, init) => {
    let u: URL;
    try { u = new URL(url); } catch { return { status: 0 }; }
    if (u.protocol !== "https:" || !(PACKAGE_HOSTS as readonly string[]).includes(u.hostname)) return { status: 0 };
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const r = await f(u.toString(), {
        method: init?.method ?? "GET", body: init?.body, signal: ctl.signal, redirect: "error", credentials: "omit",
        headers: { "User-Agent": PACKAGE_UA, Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
      });
      let json: unknown;
      if (r.ok) { try { json = await r.json(); } catch { json = undefined; } }
      return { status: r.status, json };
    } catch { return { status: 0 }; } finally { clearTimeout(t); }
  };
}

// ── Parsing manifests (text only, never executed) ────────────────────────────────────────────────────────────────
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

/** package.json → dependencies + devDependencies that come from the npm registry (file:, git, http, workspace: skipped). */
export function parsePackageJson(text: string): Dependency[] {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return []; }
  if (!j || typeof j !== "object") return [];
  const out: Dependency[] = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = (j as Record<string, unknown>)[field];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
    for (const [rawName, rawSpec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof rawSpec !== "string") continue;
      let name = rawName.trim().toLowerCase(), spec = rawSpec.trim();
      // "npm:real-name@^1" aliases install the real name.
      const alias = /^npm:((?:@[^@/]+\/)?[^@]+)(?:@(.*))?$/.exec(spec);
      if (alias) { name = alias[1]!.toLowerCase(); spec = alias[2] ?? ""; }
      else if (/^(?:file:|link:|workspace:|portal:|git\+|git:|github:|https?:|[\w.-]+\/[\w.-]+(?:#.*)?$)/.test(spec)) continue;
      if (!NPM_NAME.test(name)) continue;
      if (!out.some((d) => d.name === name)) out.push({ name, ecosystem: "npm", spec });
    }
  }
  return out;
}

/** PEP 503 normalised name. */
export const normalizePypi = (name: string) => name.trim().toLowerCase().replace(/[-_.]+/g, "-");
const PYPI_REQ = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/;

function pypiRequirement(line: string): Dependency | null {
  const clean = line.replace(/\s+#.*$/, "").replace(/;.*$/, "").trim();   // comments and environment markers
  if (!clean || clean.startsWith("#") || clean.startsWith("-") || /^(?:git\+|https?:|file:|\.|\/)/.test(clean) || clean.includes(" @ ")) return null;
  const m = PYPI_REQ.exec(clean);
  if (!m) return null;
  return { name: normalizePypi(m[1]!), ecosystem: "pypi", spec: m[2]!.trim() };
}

/** requirements.txt → names (options like -r / -e, URLs, VCS and local paths skipped; extras and markers dropped). */
export function parseRequirements(text: string): Dependency[] {
  const out: Dependency[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const d = pypiRequirement(raw);
    if (d && !out.some((x) => x.name === d.name)) out.push(d);
  }
  return out;
}

/** pyproject.toml → [project] dependencies (PEP 621) and [tool.poetry.dependencies] / dev groups (python itself skipped). */
export function parsePyproject(text: string): Dependency[] {
  const out: Dependency[] = [];
  const add = (d: Dependency | null) => { if (d && d.name !== "python" && !out.some((x) => x.name === d.name)) out.push(d); };
  let section = "";
  let inArray = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) { section = sec[1]!.trim(); inArray = false; continue; }
    if (section === "project") {
      if (/^dependencies\s*=\s*\[/.test(line)) inArray = !line.includes("]");
      if (/^dependencies\s*=\s*\[/.test(line) || inArray) {
        for (const q of line.matchAll(/["']([^"']+)["']/g)) add(pypiRequirement(q[1]!));
        if (inArray && line.includes("]")) inArray = false;
      }
    } else if (/^tool\.poetry\.(?:dev-)?dependencies$|^tool\.poetry\.group\.[^.]+\.dependencies$/.test(section)) {
      const kv = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.*)$/.exec(line);
      if (kv) add({ name: normalizePypi(kv[1]!), ecosystem: "pypi", spec: kv[2]!.replace(/^["']|["']$/g, "") });
    }
  }
  return out;
}

const MANIFEST = /(?:^|\/)(?:package\.json|requirements(?:[-.][\w-]+)?\.txt|pyproject\.toml)$/;
/** True for package.json, requirements*.txt and pyproject.toml. */
export const isManifest = (path: string) => MANIFEST.test(path);

/** Parse whichever manifest this path is. */
export function parseManifest(path: string, text: string): Dependency[] {
  if (/(?:^|\/)package\.json$/.test(path)) return parsePackageJson(text);
  if (/(?:^|\/)pyproject\.toml$/.test(path)) return parsePyproject(text);
  if (isManifest(path)) return parseRequirements(text);
  return [];
}

/** An exact pin ("1.2.3", "==1.2.3"), or null: OSV is asked only about versions we KNOW are installed (no false alarms on ranges). */
export function pinnedVersion(spec: string | undefined, ecosystem: Ecosystem): string | null {
  const s = (spec ?? "").trim();
  const m = ecosystem === "pypi" ? /^===?\s*([0-9][0-9A-Za-z.+!-]*)$/.exec(s) : /^v?=?\s*([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$/.exec(s);
  return m ? m[1]! : null;
}

// ── Lookalikes (bundled list, no network) ────────────────────────────────────────────────────────────────────────
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
      rowMin = Math.min(rowMin, cur[j]!);
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length]!;
}

const NPM_SET = new Set(POPULAR_NPM.map((n) => n.toLowerCase()));
const PYPI_SET = new Set(POPULAR_PYPI.map(normalizePypi));

/** The popular package this name imitates, or null. Short names need distance 1; scoped npm names are compared whole. */
export function lookalikeOf(name: string, ecosystem: Ecosystem): string | null {
  const set = ecosystem === "npm" ? NPM_SET : PYPI_SET;
  const n = ecosystem === "npm" ? name.toLowerCase() : normalizePypi(name);
  if (set.has(n) || n.length < 5) return null;
  const limit = n.length < 8 ? 1 : 2;
  let best: string | null = null, bestD = limit + 1;
  for (const p of set) {
    if (Math.abs(p.length - n.length) > limit) continue;
    const d = editDistance(n, p, limit);
    if (d >= 1 && d < bestD) { best = p; bestD = d; }
  }
  return best;
}

// ── The check ────────────────────────────────────────────────────────────────────────────────────────────────────
async function pool<T>(items: T[], limit: number, fn: (t: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; await fn(items[i]!); }
  }));
}

const enc = (name: string) => name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
const npmUrl = (name: string) => `https://registry.npmjs.org/${enc(name)}`;
const pypiUrl = (name: string) => `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
const downloadsUrl = (name: string) => `https://api.npmjs.org/downloads/point/last-week/${enc(name)}`;

interface RegistryFacts { exists: boolean; firstPublished: string | null; releases: number }

function npmFacts(json: unknown): RegistryFacts {
  const j = (json ?? {}) as { time?: Record<string, string>; versions?: Record<string, unknown> };
  const created = j.time?.created ?? null;
  return { exists: true, firstPublished: typeof created === "string" ? created : null, releases: j.versions ? Object.keys(j.versions).length : 0 };
}
function pypiFacts(json: unknown): RegistryFacts {
  const j = (json ?? {}) as { releases?: Record<string, { upload_time_iso_8601?: string; upload_time?: string }[]> };
  let first: string | null = null;
  for (const files of Object.values(j.releases ?? {})) for (const f of files ?? []) {
    const t = f.upload_time_iso_8601 ?? f.upload_time;
    if (typeof t === "string" && (!first || t < first)) first = t;
  }
  return { exists: true, firstPublished: first, releases: Object.keys(j.releases ?? {}).length };
}

/** An OSV advisory: the first fixed version for this package, and our severity. */
function readAdvisory(json: unknown, name: string): { fixed: string | null; severity: PackageSeverity } {
  const j = (json ?? {}) as {
    affected?: { package?: { name?: string }; ranges?: { events?: { fixed?: string }[] }[]; database_specific?: { severity?: string } }[];
    database_specific?: { severity?: string };
  };
  let fixed: string | null = null, sev = j.database_specific?.severity ?? "";
  for (const a of j.affected ?? []) {
    if (a.package?.name && a.package.name.toLowerCase() !== name.toLowerCase() && normalizePypi(a.package.name) !== normalizePypi(name)) continue;
    sev = sev || a.database_specific?.severity || "";
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed && !fixed) fixed = e.fixed;
  }
  return { fixed, severity: /^(?:critical|high)$/i.test(sev) ? "fix_now" : "fix_week" };
}

export interface PackageCheckOptions { fetcher?: PackageFetcher; now?: Date; concurrency?: number; checkDownloads?: boolean }

export async function checkPackages(deps: Dependency[], opts: PackageCheckOptions = {}): Promise<PackageCheckResult> {
  const fetchRaw = opts.fetcher ?? packageFetcher();
  const cache = new Map<string, Promise<PackageResponse>>();
  const get: PackageFetcher = (url, init) => {
    const key = `${init?.method ?? "GET"} ${url} ${init?.body ?? ""}`;
    if (!cache.has(key)) cache.set(key, fetchRaw(url, init).catch(() => ({ status: 0 })));
    return cache.get(key)!;
  };
  const now = (opts.now ?? new Date()).getTime();
  const findings: PackageFinding[] = [];
  const unknown: { name: string; ecosystem: Ecosystem }[] = [];
  const existing: { dep: Dependency; facts: RegistryFacts }[] = [];
  const limit = Math.max(1, Math.min(opts.concurrency ?? PACKAGE_CONCURRENCY, PACKAGE_CONCURRENCY));

  await pool(deps, limit, async (dep) => {
    const r = await get(dep.ecosystem === "npm" ? npmUrl(dep.name) : pypiUrl(dep.name));
    if (r.status === 404) {
      findings.push({ name: dep.name, ecosystem: dep.ecosystem, issue: "made_up", severity: "fix_now" });
      return;
    }
    if (r.status !== 200 || !r.json) { unknown.push({ name: dep.name, ecosystem: dep.ecosystem }); return; }
    const facts = dep.ecosystem === "npm" ? npmFacts(r.json) : pypiFacts(r.json);
    existing.push({ dep, facts });
    const ageDays = facts.firstPublished ? (now - Date.parse(facts.firstPublished)) / 86_400_000 : Infinity;
    if (ageDays >= 0 && ageDays < BRAND_NEW_DAYS) {
      findings.push({ name: dep.name, ecosystem: dep.ecosystem, issue: "brand_new", severity: "fix_week", firstPublished: facts.firstPublished ?? undefined });
    }
    const similar = lookalikeOf(dep.name, dep.ecosystem);
    if (similar) {
      // Established packages are not traps: an old package with many releases, or (npm) many weekly downloads.
      let established = ageDays > 365 && facts.releases >= 10;
      if (!established && dep.ecosystem === "npm" && opts.checkDownloads !== false) {
        const d = await get(downloadsUrl(dep.name));
        const n = (d.json as { downloads?: unknown } | undefined)?.downloads;
        established = typeof n === "number" && n >= ESTABLISHED_WEEKLY_DOWNLOADS;
      }
      if (!established) findings.push({ name: dep.name, ecosystem: dep.ecosystem, issue: "lookalike", severity: "fix_week", similarTo: similar });
    }
  });

  // Known vulnerabilities: only exact pins (a range could already resolve to a fixed version), one batch query.
  const pinned = existing.map(({ dep }) => ({ dep, version: pinnedVersion(dep.spec, dep.ecosystem) })).filter((x): x is { dep: Dependency; version: string } => !!x.version);
  if (pinned.length) {
    const body = JSON.stringify({ queries: pinned.map(({ dep, version }) => ({ package: { name: dep.name, ecosystem: dep.ecosystem === "npm" ? "npm" : "PyPI" }, version })) });
    const r = await get("https://api.osv.dev/v1/querybatch", { method: "POST", body });
    const results = (r.json as { results?: { vulns?: { id?: string }[] }[] } | undefined)?.results ?? [];
    let lookups = 0;
    for (let i = 0; i < pinned.length; i++) {
      const id = results[i]?.vulns?.find((v) => typeof v.id === "string")?.id;
      if (!id) continue;
      const { dep, version } = pinned[i]!;
      let detail = { fixed: null as string | null, severity: "fix_week" as PackageSeverity };
      if (lookups++ < MAX_ADVISORY_LOOKUPS) {
        const d = await get(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
        if (d.status === 200) detail = readAdvisory(d.json, dep.name);
      }
      findings.push({ name: dep.name, ecosystem: dep.ecosystem, issue: "vulnerable", severity: detail.severity, version, advisory: id, fixedIn: detail.fixed });
    }
  }

  const order: Record<PackageIssue, number> = { made_up: 0, vulnerable: 1, lookalike: 2, brand_new: 3 };
  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "fix_now" ? -1 : 1) || order[a.issue] - order[b.issue] || a.name.localeCompare(b.name));
  return { findings, unknown, checked: deps.length };
}
