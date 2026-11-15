/**
 * The second rule set, one entry point: files in, patterns out. Pure and offline (see ./types.ts for the truth rules
 * and the mirror between the hosted check and the CLI).
 *
 *   runRules2(files, { ts })  ->  findings, and what ran:
 *     astRan     the JavaScript / TypeScript syntax-tree rules ran (the caller handed in the TypeScript compiler).
 *                false = they did not run and nothing is claimed for them; the text rules still ran.
 *     unreadable files a rule could not read exactly (a rule threw on them): no finding, never a guess.
 */
import type * as TS from "typescript";
import { parseScript } from "./ast";
import { R2_RULE_BY_ID } from "./catalog";
import { composeFindings, isComposeFile } from "./compose";
import { cryptoFindings, textCryptoFindings } from "./crypto";
import { csrfFindings, type ParsedScript } from "./csrf";
import { deserializeFindings, textDeserializeFindings } from "./deserialize";
import { dockerFindings, isDockerfile } from "./docker";
import { injectionFindings, projectFacts, pyInjectionFindings } from "./injection";
import { k8sFindings, mayBeK8s } from "./k8s";
import { passwordFindings } from "./passwords";
import { isTerraformFile, isTfvarsFile, terraformFindings, tfvarsFindings } from "./terraform";
import { skipPath, VENDORED, type R2File, type R2Finding, type Ts } from "./types";
import { textUploadFindings, uploadFindings } from "./upload";

export * from "./catalog";
export { BASE_IMAGE_TABLE_DATE } from "./base-images";
export type { R2File, R2Finding, Ts } from "./types";

export interface Rules2Options {
  /** The TypeScript compiler. undefined or null: the syntax-tree rules do not run. */
  ts?: Ts | null;
  /** Rule ids to leave out. */
  disable?: readonly string[];
  /** Rule ids that are off by default and wanted anyway. */
  enable?: readonly string[];
}
export interface Rules2Result {
  findings: R2Finding[];
  astRan: boolean;
  /** Files the rules looked at (not vendored, not tests or docs), and how many of them are JavaScript / TypeScript. */
  files: number;
  scripts: number;
  unreadable: string[];
}

/** Files the config rules want read first (the hosted repository reader asks). */
export const isRules2ConfigFile = (p: string): boolean =>
  !VENDORED.test(p) && (isTerraformFile(p) || isTfvarsFile(p) || isComposeFile(p) || (/\.ya?ml$/i.test(p) && /(?:^|\/)(?:k8s|kubernetes|kube|manifests?|deploy|deployments?|helm|charts?|infra|infrastructure|ops)\//i.test(p)));

/** When two rules land on the same line, the one that names the place wins over the general password rule. */
const SPECIFIC = new Set(["inside.k8s_secret_env", "inside.compose_secret_env", "inside.docker_secret_env", "inside.tf_hardcoded_credentials", "inside.crypto_hardcoded_key", "inside.cred_url_password", "inside.cred_default_login"]);

export function runRules2(all: readonly R2File[], opts: Rules2Options = {}): Rules2Result {
  const files = all.filter((f) => !skipPath(f.path.replace(/\\/g, "/")));
  const ts = opts.ts ?? null;
  const out: R2Finding[] = [];
  const unreadable = new Set<string>();
  const run = (f: R2File, fn: () => R2Finding[]) => { try { out.push(...fn()); } catch { unreadable.add(f.path); } };

  const facts = projectFacts(all.filter((f) => !VENDORED.test(f.path)));
  const scripts: ParsedScript[] = [];
  let scriptCount = 0;
  for (const f of files) {
    const p = f.path;
    if (ts) {
      let sf: TS.SourceFile | null = null;
      try { sf = parseScript(ts, f); } catch { unreadable.add(p); }
      if (sf) {
        const s = sf;
        scriptCount++;
        scripts.push({ f, sf: s });
        run(f, () => injectionFindings(ts, f, s, facts));
        run(f, () => deserializeFindings(ts, f, s, facts));
        run(f, () => cryptoFindings(ts, f, s));
        run(f, () => uploadFindings(ts, f, s));
      }
    }
    run(f, () => pyInjectionFindings(f));
    run(f, () => textDeserializeFindings(f));
    run(f, () => textCryptoFindings(f));
    run(f, () => textUploadFindings(f));
    run(f, () => passwordFindings(f));
    if (isDockerfile(p)) run(f, () => dockerFindings(f));
    else if (isComposeFile(p)) run(f, () => composeFindings(f));
    else if (isTerraformFile(p)) run(f, () => terraformFindings(f));
    else if (isTfvarsFile(p)) run(f, () => tfvarsFindings(f));
    else if (mayBeK8s(p, f.content)) run(f, () => k8sFindings(f));
  }
  if (ts && scripts.length) { try { out.push(...csrfFindings(ts, scripts, files)); } catch { unreadable.add("(csrf)"); } }

  const disabled = new Set(opts.disable ?? []);
  const enabled = new Set(opts.enable ?? []);
  const seen = new Set<string>();
  const specificAt = new Set(out.filter((x) => SPECIFIC.has(x.ruleId)).map((x) => `${x.file}:${x.line}`));
  const findings = out.filter((x) => {
    const rule = R2_RULE_BY_ID[x.ruleId];
    if (!rule || disabled.has(x.ruleId) || (!rule.on && !enabled.has(x.ruleId))) return false;
    if (x.ruleId === "inside.cred_password_literal" && specificAt.has(`${x.file}:${x.line}`)) return false;
    const k = `${x.ruleId}|${x.file}|${x.line}|${x.key}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId) || a.key.localeCompare(b.key));
  return { findings, astRan: !!ts, files: files.length, scripts: scriptCount, unreadable: [...unreadable].sort() };
}
