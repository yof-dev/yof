/**
 * yof check, code and config patterns: the second rule set (./rules2, the same bytes the hosted check runs) over the
 * files of a folder. Offline: nothing is sent anywhere and nothing is run.
 *
 * WORDING: a pattern is not a proven problem. Each finding carries its verdict:
 *   confirmed         the pattern alone is the defect and the file says it (ECB mode, a TLS check switched off, a
 *                     privileged container, a JWT accepted without a signature)
 *   needs_validation  yof found the pattern in the code; it did not run it
 *   note              a hardening note (good practice that is missing), never counted as a problem
 * A low-urgency pattern that still needs validation (an unencrypted volume in Terraform) is listed with the notes.
 * EXIT CODE: only a confirmed "fix now" pattern fails a balanced or relaxed check. With profile strict, every
 * pattern that is not a note fails it. Accepted risks (.yof/accepted.json) apply as for keys.
 *
 * THE TYPESCRIPT COMPILER: the JavaScript / TypeScript syntax rules need it. yof has no dependencies, so it uses the
 * `typescript` package when one is installed next to it (most TypeScript projects have one) and never runs a copy
 * from the folder being scanned unless that is where yof itself is installed. Without it those rules do not run, the
 * report says so, and the text rules (passwords, containers, Kubernetes, Terraform, Python, other languages) still do.
 */
import { acceptFingerprint, acceptanceFor, type AcceptedEntry, type Acceptance } from "./accepted";
import { R2_RULE_BY_ID, runRules2, type R2Family, type R2File } from "./rules2/index";
import type { Ts } from "./rules2/types";
import { R2_WORDS } from "./rules2/words-en";

export type PatternVerdict = "confirmed" | "needs_validation" | "note";
export type PatternSeverity = "fix_now" | "fix_week" | "note";

export interface PatternFinding {
  file: string; line: number; rule: string; family: R2Family;
  severity: PatternSeverity; verdict: PatternVerdict;
  title: string; why: string;
  /** Facts the rule recorded (never a secret). */
  facts: Record<string, string>;
  /** A masked value, for the rules that found one. */
  masked?: string;
  fingerprint: string;
  accepted?: Acceptance;
}
export interface PatternRun {
  /** The JavaScript / TypeScript syntax rules ran (the TypeScript compiler was found). */
  astRan: boolean;
  /** Files the rules looked at; and the JavaScript / TypeScript files among them (parsed, or counted by name when the compiler was not found). */
  files: number; scripts: number;
  /** Files a rule could not read exactly: no finding was made from them. */
  unreadable: string[];
}

let cached: Promise<Ts | null> | null = null;
/** The TypeScript compiler when one is installed where Node resolves it from this file; else null. */
export function loadTypescript(): Promise<Ts | null> {
  cached ??= (async () => {
    try {
      const name = "typescript";   // not a literal import: the bundler must not pull the compiler into yof
      const mod: unknown = await import(name);
      const isTs = (m: unknown): m is Ts => !!m && (typeof m === "object" || typeof m === "function") && "createSourceFile" in m && typeof (m as Ts).createSourceFile === "function";
      if (isTs(mod)) return mod;
      const inner = mod && typeof mod === "object" && "default" in mod ? (mod as Record<string, unknown>)["default"] : undefined;
      return isTs(inner) ? inner : null;
    } catch { return null; }
  })();
  return cached;
}

export const verdictOf = (rule: string): PatternVerdict => {
  const b = R2_RULE_BY_ID[rule]?.basis;
  return b === "exact" ? "confirmed" : b === "practice" ? "note" : "needs_validation";
};

/** `ts`: undefined = look for the compiler; null = run without the syntax rules (tests, --no-syntax). */
export async function patternFindings(files: readonly R2File[], accepted: readonly AcceptedEntry[] = [], opts: { ts?: Ts | null; disable?: readonly string[] } = {}): Promise<{ findings: PatternFinding[]; run: PatternRun }> {
  const ts = opts.ts === undefined ? await loadTypescript() : opts.ts;
  const r = runRules2(files, { ts, disable: opts.disable });
  const lines = new Map<string, string[]>();
  const lineOf = (file: string, line: number): string => {
    let l = lines.get(file);
    if (!l) { l = (files.find((f) => f.path === file)?.content ?? "").split(/\r?\n/); lines.set(file, l); }
    return l[line - 1] ?? "";
  };
  const findings: PatternFinding[] = r.findings.map((x) => {
    const rule = R2_RULE_BY_ID[x.ruleId]!;
    const words = R2_WORDS[x.ruleId];
    const verdict = verdictOf(x.ruleId);
    const text = lineOf(x.file, x.line);
    const acc = acceptanceFor(accepted, x.ruleId, x.file, text);
    return {
      file: x.file, line: x.line, rule: x.ruleId, family: rule.family,
      severity: rule.severity === "nice" ? "note" : rule.severity, verdict,
      title: words?.title ?? x.ruleId, why: words?.why ?? "", facts: x.meta,
      ...(x.masked ? { masked: x.masked } : {}),
      fingerprint: acceptFingerprint(x.ruleId, x.file, text),
      ...(acc ? { accepted: acc } : {}),
    };
  });
  // without the compiler nothing was parsed: count the script files by name, so the report can say what did not run
  const scripts = r.astRan ? r.scripts : files.filter((f) => /\.(?:[cm]?[jt]sx?)$/i.test(f.path) && !/\.d\.[cm]?ts$/i.test(f.path)).length;
  return { findings, run: { astRan: r.astRan, files: r.files, scripts, unreadable: r.unreadable } };
}

export const patternFixPrompt = (p: Pick<PatternFinding, "rule" | "file" | "line" | "masked">): string =>
  `In ${p.file} at line ${p.line}${p.masked ? ` (shortened value ${p.masked})` : ""}: ${R2_WORDS[p.rule]?.fix ?? ""}`.trim();
