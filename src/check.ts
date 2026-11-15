/**
 * One check: read the files, find keys, check the dependencies, decide the exit code.
 *
 * Profiles (same names as yof Guard's .yof.yml):
 *   relaxed   shows "fix now" only; fails on "fix now"
 *   balanced  shows "fix now" and "fix this week"; fails on "fix now" (the default)
 *   strict    shows everything, including public keys that are fine; fails on "fix now" and "fix this week"
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseGitignore, parseYofYml, type Profile } from "./config";
import { gitTopLevel, runGit, stagedAddedText, stagedFiles, trackedPaths, walkFiles, type GitRunner, type SourceFile } from "./files";
import { checkPackages, isManifest, packageMessage, parseBunLock, parseManifest, privateNpmNames, type Dependency, type Ecosystem, type PackageFetcher, type PackageFinding, type PackageIssue } from "./packages";
import { KEY_RULES, isRepoFixture, scanText, type Severity } from "./secrets";
import { ACCEPTED_FILE, acceptFingerprint, acceptanceFor, parseAccepted, type Acceptance } from "./accepted";
import { patternFindings, type PatternFinding, type PatternRun } from "./patterns";
import type { Ts } from "./rules2/types";

/** Most dependencies checked against the registries in one run. */
export const MAX_DEPENDENCIES = 500;

export interface KeyFinding {
  file: string; line: number; column: number; rule: string; name: string; severity: Severity; masked: string;
  /** For .yof/accepted.json (./accepted.ts): changes when the line changes. */
  fingerprint: string;
  /** Set when .yof/accepted.json accepts this finding: it is still listed, but not counted as open. */
  accepted?: Acceptance;
  /** Other rules that caught the very same value in this file (one finding, not several). */
  alsoMatched?: string[];
}
/** `files`: every manifest that names this dependency (the first is `file`), when there is more than one. */
export interface DependencyFinding {
  file: string; name: string; ecosystem: Ecosystem; issue: PackageIssue; severity: "fix_now" | "fix_week"; message: string;
  similarTo?: string; firstPublished?: string; version?: string; advisory?: string; fixedIn?: string | null;
  /** made_up only: a scoped name that may be a private package (fix_week, needs validation). */
  unconfirmed?: true;
  fingerprint: string; accepted?: Acceptance; files?: string[];
}
export interface CheckReport {
  root: string;
  mode: "full" | "staged";
  profile: Profile;
  offline: boolean;
  filesScanned: number;
  filesSkipped: number;
  /** Paths (files and whole folders) left out by .yof.yml's ignore list; part of filesSkipped. */
  ignoredByConfig: number;
  /**
   * Where the settings that can weaken a check came from (.yof.yml and the accepted-risks file): this folder, or on a
   * pull request the base branch (`base`). "base_unavailable": a pull request whose base branch git could not read,
   * so NO ignore list and NO accepted risks were used.
   */
  settings: { from: "folder" | "base" | "base_unavailable"; base?: string };
  truncated: boolean;
  keys: KeyFinding[];
  packages: DependencyFinding[];
  /** Dependencies checked against the registries (0 when offline). */
  dependenciesChecked: number;
  /** Dependencies the registries did not answer for: nothing is claimed about them. */
  unknown: { name: string; ecosystem: Ecosystem }[];
  /**
   * Lockfiles next to a package.json that could not be read (15 Nov 2026: a binary bun.lockb, or a bun.lock that is not
   * readable text). Their installed versions are not known: never reported as "no packages". Left out when none.
   */
  unreadableLockfiles?: string[];
  /** Open findings by severity (accepted ones are not counted). */
  counts: { fix_now: number; fix_week: number; info: number };
  /** Findings .yof/accepted.json accepts (listed with their reason, never hidden). */
  acceptedCount: number;
  /** True when something at or above the profile's threshold was found (exit code 1). */
  failed: boolean;
  /**
   * Code and config patterns (./patterns.ts, the second rule set). Kept apart from `counts`: a pattern is not a
   * proven problem, and each one carries its own verdict. `patternRun` is null when the patterns were turned off.
   */
  patterns: PatternFinding[];
  patternRun: PatternRun | null;
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
  /** false: leave the code and config patterns out (yof check --no-patterns). */
  patterns?: boolean;
  /** The TypeScript compiler for the syntax rules: undefined = look for one, null = run without them. */
  ts?: Ts | null;
  /** The environment (default process.env): only read to see a pull-request run (GITHUB_EVENT_NAME, GITHUB_BASE_REF). */
  env?: Record<string, string | undefined>;
}

/** The base branch of a pull-request run in CI (GitHub Actions sets both variables), or null. Pure. */
export function pullRequestBase(env: Record<string, string | undefined>): string | null {
  const base = (env.GITHUB_BASE_REF ?? "").trim();
  if (!/^pull_request/.test(env.GITHUB_EVENT_NAME ?? "")) return null;
  return /^[A-Za-z0-9][\w./-]{0,199}$/.test(base) && !base.includes("..") ? base : null;
}

/**
 * The settings that can weaken a check, read from the BASE branch of a pull request (yof audit 3.10). Before, a pull
 * request could silence the check on itself: add its own folder to .yof.yml's ignore list, set `profile: relaxed`, or
 * "accept" its own leaked key in .yof/accepted.json, all in the same change that adds the key. Now those files are
 * read as they are on the base branch (git show origin/<base>:<file>), so a change to them counts once it is merged.
 * A file the base branch does not have is an empty file. A base branch git cannot read (a shallow checkout that
 * never fetched it) gives `null`: the caller then uses no ignore list and no accepted risks, and says so.
 */
export function baseSettings(root: string, base: string, git: GitRunner): { yml: string | null; accepted: string | null } | null {
  const ref = `origin/${base}`;
  let prefix = "";
  try {
    git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], root);
    prefix = git(["rev-parse", "--show-prefix"], root).toString("utf8").trim();
  } catch { return null; }
  const show = (file: string) => { try { return git(["show", `${ref}:${prefix}${file}`], root).toString("utf8"); } catch { return null; } };
  return { yml: show(".yof.yml"), accepted: show(ACCEPTED_FILE) };
}

export const visibleIn = (profile: Profile, severity: Severity) =>
  profile === "strict" ? true : profile === "balanced" ? severity !== "info" : severity === "fix_now";
export const failsIn = (profile: Profile, severity: Severity) =>
  severity === "fix_now" || (profile === "strict" && severity === "fix_week");
/** Patterns: strict shows everything, balanced leaves the hardening notes out, relaxed shows "fix now" only. */
export const patternVisibleIn = (profile: Profile, p: Pick<PatternFinding, "severity">) =>
  profile === "strict" ? true : profile === "balanced" ? p.severity !== "note" : p.severity === "fix_now";
/** A pattern fails the check only when it is confirmed and "fix now"; with profile strict, whenever it is not a note. */
export const patternFailsIn = (profile: Profile, p: Pick<PatternFinding, "severity" | "verdict">) =>
  (p.severity === "fix_now" && p.verdict === "confirmed") || (profile === "strict" && p.severity !== "note");

const RANK: Record<Severity, number> = { fix_now: 3, fix_week: 2, info: 1 };
/** Rules that recognise a value by its name or shape alone: a provider rule on the same value is the primary. */
const GENERIC = new Set(["secret.named_env", "secret.aws_key_id"]);
/** Which of two findings on the same value is the primary (negative = a first): urgency, then the specific rule, then the id. */
export const primaryOrder = (a: Pick<KeyFinding, "rule" | "severity">, b: Pick<KeyFinding, "rule" | "severity">) =>
  RANK[b.severity] - RANK[a.severity] || Number(GENERIC.has(a.rule)) - Number(GENERIC.has(b.rule)) || a.rule.localeCompare(b.rule);

/**
 * One finding per value per file (2026-11-07): when several rules catch the same value (a Stripe key in a VITE_..._SECRET
 * setting is both "Stripe live secret key" and "secret-sounding setting"), the primary stays and the others are listed
 * in `alsoMatched`, so counts and the exit code see one problem. Pure, deterministic.
 */
export function collapseKeys(found: readonly (KeyFinding & { hash: string })[]): KeyFinding[] {
  const by = new Map<string, (KeyFinding & { hash: string })[]>();
  for (const k of found) { const key = `${k.file}|${k.hash}`; by.set(key, [...(by.get(key) ?? []), k]); }
  return [...by.values()].map((g) => {
    const [p, ...rest] = [...g].sort(primaryOrder);
    const { hash: _h, ...primary } = p!;
    const also = [...new Set(rest.map((r) => r.rule))].filter((r) => r !== primary.rule).sort();
    // The primary keeps its own fingerprint. An entry in .yof/accepted.json made for one of the folded rules (same
    // value, same line) still applies to the one finding, so grouping never reopens an accepted risk.
    const accepted = primary.accepted ?? rest.find((r) => r.accepted)?.accepted;
    return { ...primary, ...(accepted ? { accepted } : {}), ...(also.length ? { alsoMatched: also } : {}) };
  });
}

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
  // The settings that can weaken the check. On a pull request in CI they come from the base branch, never from the
  // pull request's own files (baseSettings above); a staged check is a person's own commit and reads the folder.
  const prBase = opts.staged ? null : pullRequestBase(opts.env ?? process.env);
  const fromBase = prBase ? baseSettings(root, prBase, git) : null;
  const settings: CheckReport["settings"] = !prBase ? { from: "folder" } : fromBase ? { from: "base", base: prBase } : { from: "base_unavailable", base: prBase };
  const cfg = parseYofYml(!prBase ? readIf(join(root, ".yof.yml")) : fromBase?.yml ?? null);
  const profile = opts.profile ?? cfg.profile;

  // Committed files are scanned whatever .gitignore says (files.ts walkFiles).
  const set = opts.staged ? stagedFiles(root, cfg.ignore, git) : walkFiles(root, cfg.ignore, parseGitignore(readIf(join(root, ".gitignore"))), trackedPaths(root, git));

  // Accepted risks recorded in the repository (the working tree's file, so a staged check sees them too; on a pull
  // request the base branch's file, so a pull request cannot accept its own finding).
  const acceptedList = parseAccepted(!prBase ? readIf(join(root, ACCEPTED_FILE)) : fromBase?.accepted ?? null);

  // Keys.
  const found: (KeyFinding & { hash: string })[] = [];
  for (const f of set.files) {
    const lines = f.content.split(/\r?\n/);
    for (const m of scanText(f.content)) {
      const rule = KEY_RULES[m.ruleId] ?? { name: m.ruleId, severity: "fix_week" as Severity };
      const text = lines[m.line - 1] ?? "";
      if (isRepoFixture(m, f.path, text)) continue;   // the app's repository rule (0.3.1)
      const accepted = acceptanceFor(acceptedList, m.ruleId, f.path, text);
      found.push({ file: f.path, line: m.line, column: m.column, rule: m.ruleId, name: rule.name, severity: rule.severity, masked: m.masked, fingerprint: acceptFingerprint(m.ruleId, f.path, text), ...(accepted ? { accepted } : {}), hash: m.hash });
    }
  }
  const keys = collapseKeys(found);

  // Dependencies (staged mode: only the ones on lines this commit adds).
  const deps: (Dependency & { file: string; files: string[] })[] = [];
  const manifests: SourceFile[] = set.files.filter((f) => isManifest(f.path));
  for (const m of manifests) {
    let parsed = parseManifest(m.path, m.content);
    if (opts.staged) {
      let added = "";
      try { added = stagedAddedText(root, m.path, git); } catch { added = m.content; }
      parsed = parsed.filter((d) => added.toLowerCase().includes(d.name) || added.toLowerCase().replace(/[-_.]+/g, "-").includes(d.name));
    }
    // One dependency, however many workspace manifests name it: asked once, reported once, every manifest listed.
    for (const d of parsed) {
      const have = deps.find((x) => x.name === d.name && x.ecosystem === d.ecosystem);
      if (!have) deps.push({ ...d, file: m.path, files: [m.path] });
      else if (!have.files.includes(m.path)) have.files.push(m.path);
    }
  }
  // bun.lock beside a package.json (15 Nov 2026): the exact installed version of each npm dependency, asked of OSV as
  // a pin. bun.lockb (binary) cannot be read: named as unreadable, never treated as "no packages".
  const unreadableLockfiles: string[] = [];
  for (const m of manifests.filter((x) => /(?:^|\/)package\.json$/.test(x.path))) {
    const dir = dirname(m.path) === "." ? "" : `${dirname(m.path)}/`;
    const text = readIf(join(root, `${dir}bun.lock`));
    const versions = text != null ? parseBunLock(text) : null;
    if (text != null && !versions) unreadableLockfiles.push(`${dir}bun.lock`);
    else if (text == null && existsSync(join(root, `${dir}bun.lockb`))) unreadableLockfiles.push(`${dir}bun.lockb`);
    if (!versions) continue;
    for (const d of deps) if (d.ecosystem === "npm" && !d.installed && d.files.includes(m.path) && versions.has(d.name)) d.installed = versions.get(d.name)!;
  }
  // The yof app's rule (0.4.0): names the repository publishes itself, and npm names served by a private registry
  // (.npmrc: a scope's own registry, or another default registry) are never asked of the public registry.
  const priv = privateNpmNames(set.files);
  const toCheck = deps.filter((d) => d.ecosystem !== "npm" || !priv.skip(d.name)).slice(0, MAX_DEPENDENCIES);

  const packages: DependencyFinding[] = [];
  let unknown: { name: string; ecosystem: Ecosystem }[] = [];
  let dependenciesChecked = 0;
  if (!opts.offline && toCheck.length) {
    const result = await checkPackages(toCheck, { fetcher: opts.fetcher, now: opts.now });
    dependenciesChecked = result.checked;
    unknown = result.unknown;
    for (const f of result.findings as PackageFinding[]) {
      const dep = toCheck.find((d) => d.name === f.name && d.ecosystem === f.ecosystem);
      const file = dep?.file ?? "";
      const rule = `package.${f.issue}`, content = `${f.ecosystem}:${f.name}`;
      const accepted = acceptanceFor(acceptedList, rule, file, content);
      packages.push({ file, ...f, message: packageMessage(f), fingerprint: acceptFingerprint(rule, file, content), ...(accepted ? { accepted } : {}), ...((dep?.files.length ?? 0) > 1 ? { files: dep!.files } : {}) });
    }
  }

  // Code and config patterns: offline, the same rules the hosted check runs.
  const pat = opts.patterns === false ? null : await patternFindings(set.files, acceptedList, { ts: opts.ts });

  const counts = { fix_now: 0, fix_week: 0, info: 0 };
  const open = [...keys, ...packages].filter((x) => !x.accepted);
  for (const x of open) counts[x.severity]++;
  const failed = open.some((x) => failsIn(profile, x.severity)) || (pat?.findings ?? []).some((p) => !p.accepted && patternFailsIn(profile, p));
  const acceptedCount = keys.length + packages.length - open.length;

  return {
    root, mode: opts.staged ? "staged" : "full", profile, offline: !!opts.offline,
    filesScanned: set.files.length, filesSkipped: set.skipped, ignoredByConfig: set.ignored ?? 0, settings, truncated: set.truncated,
    keys, packages, dependenciesChecked, unknown, ...(unreadableLockfiles.length ? { unreadableLockfiles } : {}), counts, acceptedCount, failed,
    patterns: pat?.findings ?? [], patternRun: pat?.run ?? null,
  };
}
