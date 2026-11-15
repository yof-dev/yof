/**
 * yof static rules, second set (owner decision 12 Nov 2026): code and config PATTERNS for injection, CSRF, unsafe
 * loaders, weak cryptography, passwords in code, upload handling, containers, Kubernetes and Terraform.
 *
 * THIS FOLDER IS MIRRORED BYTE FOR BYTE between the hosted check (packages/api/src/lib/yof/inside/rules2) and the
 * open-source CLI (oss/yof/src/rules2); a test pins that every file is the same in both, so the two can never
 * disagree. It imports nothing outside itself except Node's own modules and, as a TYPE only, the TypeScript compiler:
 * the caller hands the compiler in (Rules2Options.ts), and without it the syntax-tree rules do not run and say so.
 *
 * TRUTH: a static rule finds a pattern, never an exploit. Nothing here runs code, opens a connection or reads a
 * built image. What each rule covers, its guards and its known false-positive risks: ./catalog.ts.
 */
import type * as TS from "typescript";

export type Ts = typeof TS;
export interface R2File { path: string; content: string }

/** One pattern found. Never holds a secret: `masked` and `snippet` are already masked. */
export interface R2Finding {
  ruleId: string;
  file: string;
  /** 1-based. */
  line: number;
  /** A short stable text the finding is recognised by across runs (never a secret; defaults to the line's own text). */
  key: string;
  /** Facts for the report (short, never a secret). */
  meta: Record<string, string>;
  masked?: string;
  snippet?: string;
}

/** Tests, fixtures, examples, docs: their values are fake on purpose and their code never ships. */
export const NON_SHIPPING = /(?:^|\/)(?:__tests__|__mocks__|__fixtures__|__snapshots__|tests?|spec|specs|fixtures?|mocks?|examples?|samples?|demos?|docs?|testdata|e2e|cypress|playwright|stories|\.storybook)\/|\.(?:test|spec|stories|story|e2e)\.[cm]?[jt]sx?$|(?:^|\/)test_[^/]+\.py$|_test\.(?:go|py)$|(?:^|\/)conftest\.py$|\.(?:md|mdx|rst|txt|adoc)$|\.(?:example|sample|template|dist|tmpl)$|\.(?:example|sample|template)\.[\w.]+$/i;
/** Vendored, generated or built: never scanned by these rules. */
export const VENDORED = /(?:^|\/)(?:node_modules|vendor|vendors|third_party|third-party|bower_components|dist|build|out|target|coverage|\.next|\.nuxt|\.svelte-kit|\.vercel|\.turbo|\.terraform|\.serverless|\.venv|venv|site-packages|__pycache__|__generated__|generated|\.git)\/|\.min\.(?:js|css)$|\.(?:generated|gen)\.[\w.]+$|\.pb\.go$|_pb2(?:_grpc)?\.py$|\.d\.ts$|\.map$/i;

export const skipPath = (p: string): boolean => VENDORED.test(p) || NON_SHIPPING.test(p);

/** 1-based line of a character offset. */
export function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) n++;
  return n;
}
export const lineText = (text: string, line: number): string => (text.split("\n")[line - 1] ?? "").replace(/\r$/, "");

/** A value shown without giving it away: its first character (two when it is long) and dots. */
export function maskValue(v: string): string {
  const keep = v.length >= 12 ? 2 : v.length >= 6 ? 1 : 0;
  return `${v.slice(0, keep)}••••`;
}
/** A line with `value` masked, trimmed and cut for evidence. */
export function maskedLine(text: string, value: string): string {
  const t = (value ? text.split(value).join(maskValue(value)) : text).trim();
  return t.length > 140 ? `${t.slice(0, 139)}…` : t;
}
const cut = (s: string, n = 140) => { const t = s.replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
export const shortText = cut;

/** Values that are placeholders or references, never a real password or key. */
export const PLACEHOLDER = /^$|x{4,}|\*{3,}|\.{3,}|•|^(?:0+|1234\w*|abc\w*)$|example|sample|dummy|fake|placeholder|change[_-]?me|change[_-]?this|replace[_-]?(?:me|this)|your[_-]?|my[_-]?(?:secret|password|key)|^<.*>$|^\[.*\]$|^\{.*\}$|\$\{|\$\(|\{\{|%\(|<%|^\$[A-Za-z_]|^%[A-Z_]+%$|^(?:todo|tbd|none|null|nil|undefined|true|false|redacted|hidden|masked|secret|password|passwd|pass|pwd|token|key|value|string|text|test|testing|demo|default|required|optional|n\/a|na|empty|unset|not[_-]?set)$|[_-]here$|^insert|^enter[_ -]|^put[_ -]/i;
export const isPlaceholderValue = (v: string): boolean => PLACEHOLDER.test(v.trim());
/** A reference to the environment or a secret store, in the common languages and config formats. */
export const ENV_REF = /process\.env|import\.meta\.env|os\.environ|os\.getenv|getenv\(|ENV\[|System\.getenv|env\(|Deno\.env|\$\{\{?|\$[A-Z_][A-Z0-9_]*\b|var\.|local\.|data\.|secrets\.|vault|ssm:|arn:aws:secretsmanager/;

/** A name as lower-case words: "dbPassword", "DB_PASSWORD" and "db.password" all give ["db", "password"]. */
export const nameWords = (name: string): string[] =>
  name.split(/[_.\-\s/]+|(?<=[a-z0-9])(?=[A-Z])/).map((w) => w.toLowerCase().replace(/\d+$/, "")).filter(Boolean);
/** Words that make a name talk ABOUT a password (a label, a field, a rule, an address), not hold one. */
const ABOUT = new Set(["field", "label", "placeholder", "hint", "title", "text", "message", "msg", "error", "prompt", "regex", "regexp", "pattern", "policy", "min", "max", "length", "len", "strength", "rule", "rules", "validation", "validator", "input", "name", "names", "key", "keys", "param", "header", "type", "url", "uri", "link", "path", "route", "page", "file", "dir", "env", "var", "id", "ids", "column", "attr", "attribute", "selector", "ref", "schema", "prop", "props", "hash", "hashed", "digest", "salt", "rounds", "expiry", "expires", "ttl", "enabled", "required", "visible", "show", "toggle", "icon", "mask", "masked", "form", "view", "screen", "step", "reset", "forgot", "change", "changed", "update", "confirm", "confirmation", "repeat", "new", "old", "current", "no", "has", "is", "use", "with", "without", "invalid", "wrong", "missing", "weak", "strong"]);
/** Does the name say it HOLDS a password or secret? The last word decides, and the word before it may veto. */
export function isSecretName(name: string): boolean {
  const w = nameWords(name);
  const last = w[w.length - 1] ?? "";
  if (last === "key" && w[w.length - 2] === "secret") return true;   // secret_key, secretKey
  if (!(/(?:passw(?:or)?d|passwd|pwd|secret)$/.test(last) || last === "pass")) return false;
  return !(w.length >= 2 && ABOUT.has(w[w.length - 2]!));
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}
/** The existing entropy rule's own ground (inside.secret_entropy): a random-looking value of 20+ characters. */
export function looksRandom(v: string): boolean {
  if (v.length < 20 || /[()[\]{}\\|,;<>\s"'`]/.test(v)) return false;
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
  return kinds >= 2 && entropy(v) >= 3.5;
}

export function finding(ruleId: string, f: R2File, line: number, meta: Record<string, string> = {}, extra: { key?: string; masked?: string; snippet?: string } = {}): R2Finding {
  const text = lineText(f.content, line);
  const m: Record<string, string> = {};
  for (const [k, v] of Object.entries(meta)) if (v) m[k] = cut(String(v), 200);
  return {
    ruleId, file: f.path, line, key: extra.key ?? text.replace(/\s+/g, " ").trim(), meta: m,
    ...(extra.masked ? { masked: extra.masked } : {}),
    ...(extra.snippet ? { snippet: extra.snippet } : {}),
  };
}
