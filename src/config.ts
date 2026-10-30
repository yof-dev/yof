/**
 * .yof.yml: the same two settings yof Guard reads on GitHub, so one file works for both.
 *
 *   profile: balanced        # relaxed | balanced | strict
 *   ignore:
 *     - fixtures/            # a folder
 *     - "**\/*.snap"          # a glob (* = within one folder, ** = any depth)
 *
 * Anything else in the file is ignored. Parsed as plain lines, never as code.
 */
export type Profile = "relaxed" | "balanced" | "strict";
export const PROFILES: readonly Profile[] = ["relaxed", "balanced", "strict"];

export interface YofConfig { profile: Profile; ignore: string[] }

/** The two settings read from .yof.yml: `profile:` and an `ignore:` list (at most 50 entries). */
export function parseYofYml(text: string | null | undefined): YofConfig {
  const out: YofConfig = { profile: "balanced", ignore: [] };
  if (!text) return out;
  let inIgnore = false;
  for (const raw of text.split("\n").slice(0, 200)) {
    const line = raw.replace(/\s+#.*$/, "");
    const prof = /^profile:\s*["']?(relaxed|balanced|strict)["']?\s*$/.exec(line.trim());
    if (prof) { out.profile = prof[1] as Profile; inIgnore = false; continue; }
    if (/^ignore:\s*$/.test(line.trim())) { inIgnore = true; continue; }
    const inline = /^ignore:\s*\[(.*)\]\s*$/.exec(line.trim());
    if (inline) { out.ignore.push(...inline[1]!.split(",").map((s) => s.trim().replace(/^["']|["']$/g, "")).filter(Boolean)); continue; }
    if (inIgnore) {
      const item = /^\s*-\s*["']?([^"']+?)["']?\s*$/.exec(line);
      if (item) { out.ignore.push(item[1]!); continue; }
      if (line.trim() && !/^\s/.test(line)) inIgnore = false;
    }
  }
  out.ignore = out.ignore.slice(0, 50);
  return out;
}

const globToRe = (glob: string) =>
  new RegExp(`^${glob.split("**").map((s) => s.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*")).join(".*")}$`);

/** A .yof.yml ignore entry: a path or folder prefix, or a glob matched against the whole path. Paths use "/". */
export function matchesIgnore(path: string, pattern: string): boolean {
  const p = pattern.trim().replace(/^\.\//, "");
  if (!p) return false;
  if (!p.includes("*")) return path === p || path.startsWith(p.endsWith("/") ? p : `${p}/`);
  return globToRe(p).test(path);
}

/**
 * A simple reading of a root .gitignore: plain names match at any depth ("node_modules", "*.log"), names with a slash
 * are anchored to the root ("/out", "docs/build"), a trailing slash means a folder. Negations ("!keep") are skipped,
 * so yof may skip a little less than git does, never more.
 */
export function parseGitignore(text: string | null | undefined): string[] {
  if (!text) return [];
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("!")).slice(0, 500);
}

export function matchesGitignore(path: string, pattern: string): boolean {
  let p = pattern.replace(/\\ /g, " ");
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith("/") || p.includes("/");
  p = p.replace(/^\//, "");
  if (!p) return false;
  const re = globToRe(p);
  const segs = path.split("/");
  if (anchored) {
    // The pattern matches the path itself or one of its parent folders.
    for (let i = 1; i <= segs.length; i++) {
      if (dirOnly && i === segs.length) break;
      if (re.test(segs.slice(0, i).join("/"))) return true;
    }
    return false;
  }
  // A plain name matches any one segment (the last one only when it is not folder-only).
  return segs.some((s, i) => (!dirOnly || i < segs.length - 1) && re.test(s));
}
