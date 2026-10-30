/**
 * One check: read the files, find keys, check the dependencies, decide the exit code.
 *
 * Profiles (same names as yof Guard's .yof.yml):
 *   relaxed   shows "fix now" only; fails on "fix now"
 *   balanced  shows "fix now" and "fix this week"; fails on "fix now" (the default)
 *   strict    shows everything, including public keys that are fine; fails on "fix now" and "fix this week"
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseGitignore, parseYofYml, type Profile } from "./config";
import { gitTopLevel, runGit, stagedAddedText, stagedFiles, walkFiles, type GitRunner, type SourceFile } from "./files";
import { checkPackages, isManifest, packageMessage, parseManifest, type Dependency, type Ecosystem, type PackageFetcher, type PackageFinding, type PackageIssue } from "./packages";
import { KEY_RULES, scanText, type Severity } from "./secrets";

/** Most dependencies checked against the registries in one run. */
export const MAX_DEPENDENCIES = 500;

export interface KeyFinding { file: string; line: number; column: number; rule: string; name: string; severity: Severity; masked: string }
export interface DependencyFinding {
  file: string; name: string; ecosystem: Ecosystem; issue: PackageIssue; severity: "fix_now" | "fix_week"; message: string;
  similarTo?: string; firstPublished?: string; version?: string; advisory?: string; fixedIn?: string | null;
}
export interface CheckReport {
  root: string;
  mode: "full" | "staged";
  profile: Profile;
  offline: boolean;
  filesScanned: number;
  filesSkipped: number;
  truncated: boolean;
  keys: KeyFinding[];
  packages: DependencyFinding[];
  /** Dependencies checked against the registries (0 when offline). */
  dependenciesChecked: number;
  /** Dependencies the registries did not answer for: nothing is claimed about them. */
  unknown: { name: string; ecosystem: Ecosystem }[];
  counts: { fix_now: number; fix_week: number; info: number };
  /** True when something at or above the profile's threshold was found (exit code 1). */
  failed: boolean;
}

export interface CheckOptions {
  path?: string;
  cwd?: string;
  staged?: boolean;
  offline?: boolean;
  /** Overrides .yof.yml's profile. */
  profile?: Profile;
  fetcher?: PackageFetcher;
  git?: GitRunner;
  now?: Date;
}

export const visibleIn = (profile: Profile, severity: Severity) =>
  profile === "strict" ? true : profile === "balanced" ? severity !== "info" : severity === "fix_now";
export const failsIn = (profile: Profile, severity: Severity) =>
  severity === "fix_now" || (profile === "strict" && severity === "fix_week");

const readIf = (p: string) => { try { return existsSync(p) ? readFileSync(p, "utf8") : null; } catch { return null; } };

export class CheckError extends Error {}

export async function runCheck(opts: CheckOptions = {}): Promise<CheckReport> {
  const git = opts.git ?? runGit;
  const base = opts.cwd ?? process.cwd();
  const target = resolve(base, opts.path ?? ".");
  if (!existsSync(target) || !statSync(target).isDirectory()) throw new CheckError(`Not a folder: ${opts.path ?? "."}`);

  let root = target;
  if (opts.staged) {
    try { root = gitTopLevel(target, git); } catch { throw new CheckError("--staged needs a git repository (git rev-parse failed here)."); }
  }
  const cfg = parseYofYml(readIf(join(root, ".yof.yml")));
  const profile = opts.profile ?? cfg.profile;

  const set = opts.staged ? stagedFiles(root, cfg.ignore, git) : walkFiles(root, cfg.ignore, parseGitignore(readIf(join(root, ".gitignore"))));

  // Keys.
  const keys: KeyFinding[] = [];
  for (const f of set.files) {
    for (const m of scanText(f.content)) {
      const rule = KEY_RULES[m.ruleId] ?? { name: m.ruleId, severity: "fix_week" as Severity };
      keys.push({ file: f.path, line: m.line, column: m.column, rule: m.ruleId, name: rule.name, severity: rule.severity, masked: m.masked });
    }
  }

  // Dependencies (staged mode: only the ones on lines this commit adds).
  const deps: (Dependency & { file: string })[] = [];
  const manifests: SourceFile[] = set.files.filter((f) => isManifest(f.path));
  for (const m of manifests) {
    let parsed = parseManifest(m.path, m.content);
    if (opts.staged) {
      let added = "";
      try { added = stagedAddedText(root, m.path, git); } catch { added = m.content; }
      parsed = parsed.filter((d) => added.toLowerCase().includes(d.name) || added.toLowerCase().replace(/[-_.]+/g, "-").includes(d.name));
    }
    for (const d of parsed) if (!deps.some((x) => x.name === d.name && x.ecosystem === d.ecosystem)) deps.push({ ...d, file: m.path });
  }
  const toCheck = deps.slice(0, MAX_DEPENDENCIES);

  const packages: DependencyFinding[] = [];
  let unknown: { name: string; ecosystem: Ecosystem }[] = [];
  let dependenciesChecked = 0;
  if (!opts.offline && toCheck.length) {
    const result = await checkPackages(toCheck, { fetcher: opts.fetcher, now: opts.now });
    dependenciesChecked = result.checked;
    unknown = result.unknown;
    for (const f of result.findings as PackageFinding[]) {
      const file = toCheck.find((d) => d.name === f.name && d.ecosystem === f.ecosystem)?.file ?? "";
      packages.push({ file, ...f, message: packageMessage(f) });
    }
  }

  const counts = { fix_now: 0, fix_week: 0, info: 0 };
  for (const x of [...keys, ...packages]) counts[x.severity]++;
  const failed = [...keys, ...packages].some((x) => failsIn(profile, x.severity));

  return {
    root, mode: opts.staged ? "staged" : "full", profile, offline: !!opts.offline,
    filesScanned: set.files.length, filesSkipped: set.skipped, truncated: set.truncated,
    keys, packages, dependenciesChecked, unknown, counts, failed,
  };
}
