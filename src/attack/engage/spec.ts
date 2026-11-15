/**
 * yof engagement, open core: a stored replay spec, read strictly and run through the governor.
 *
 * A finding carries its proof as data (../replay.ts ReplaySpec). `yof attack replay` and `yof attack verify` read one
 * from a file. A file is not trusted:
 *   - parseReplaySpec accepts only the known shape: known methods, paths on the app (never a host), known expectation
 *     kinds, bounded sizes. Anything else is refused with the reason;
 *   - the ACCOUNTS in the file are ignored. Sign-in details always come from the attack config and the YOF_ATTACK_
 *     variables it names, so a changed file can never point the run at another secret;
 *   - every request goes through the same HTTP client and governor as any other: one proven origin, writes only to
 *     records the run itself created, the record's budgets, pace and forbidden paths.
 *
 * runSpec is the same engine as the generated regression tests (REPLAY_ENGINE_JS), written against the governor
 * instead of a bare fetch. It answers with the list of failed expectations: empty = the attack no longer works.
 */
import type { As, HttpAnswer, Method } from "../http";
import { claimsOutwardAction, internalDetails, looksLikeInstructions, readPath, saysUnlockWord, unsafeMarkup } from "../probes";
import { isDerive, type DeriveStep, type Expect, type ReplaySpec, type ReplayStep } from "../replay";
import type { EngageInit, EngageIo } from "./markers";
import type { SafetyClass } from "./roe";

const ROLES: readonly As[] = ["a", "b", "admin", "viewer", "anon"];
const METHODS: readonly Method[] = ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"];
const PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/{}?-]{0,600}$/;
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,39}$/;
const JSON_PATH = /^[A-Za-z0-9_$-]{1,40}(?:\.[A-Za-z0-9_$-]{1,40}){0,7}$/;
const HEADER = /^[A-Za-z][A-Za-z0-9-]{0,39}$/;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "cookie", "authorization"]);
export const MAX_SPEC_STEPS = 40;
export const MAX_REPEAT = 20;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown, max: number): v is string => typeof v === "string" && v.length <= max;

function parseExpect(e: unknown): Expect | string {
  if (!isObj(e) || typeof e.kind !== "string") return "an expectation needs a kind";
  switch (e.kind) {
    case "denied": case "not_instructions": case "cookie_flags": case "no_internal": case "no_claimed_action": return { kind: e.kind };
    case "not_contains": case "no_unsafe_markup": case "not_unlocked": case "marker_absent": case "marker_present":
      return str(e.value, 200) && e.value ? { kind: e.kind, value: e.value } : `${e.kind} needs a value`;
    case "not_redirect_to": return str(e.host, 253) && /^[a-z0-9.-]+$/.test(e.host) ? { kind: e.kind, host: e.host } : "not_redirect_to needs a host";
    case "header_present": return str(e.name, 60) && /^[a-z0-9-]+$/.test(e.name) ? { kind: e.kind, name: e.name } : "header_present needs a header name in lower case";
    case "some_status": return Array.isArray(e.status) && e.status.length <= 10 && e.status.every((s) => Number.isInteger(s) && s >= 100 && s <= 599) ? { kind: e.kind, status: e.status as number[] } : "some_status needs a list of statuses";
    case "short_answer": return Number.isInteger(e.max) && (e.max as number) > 0 ? { kind: e.kind, max: e.max as number } : "short_answer needs a max";
    case "count_at_most": return Number.isInteger(e.max) && (e.max as number) >= 0 && (e.max as number) <= MAX_REPEAT ? { kind: e.kind, max: e.max as number } : "count_at_most needs a max";
    case "canary_hit": return str(e.token, 200) && e.token ? { kind: e.kind, token: e.token } : "canary_hit needs a token";
    default: return `unknown expectation "${e.kind.slice(0, 40)}"`;
  }
}

export type SpecParse = { ok: true; spec: ReplaySpec } | { ok: false; why: string };

/** Read a replay spec from untrusted JSON. The accounts it names are dropped: they come from the config. Pure. */
export function parseReplaySpec(v: unknown): SpecParse {
  const no = (why: string): SpecParse => ({ ok: false, why });
  if (!isObj(v)) return no("the replay spec must be an object");
  if (!str(v.ruleId, 80) || !/^[a-z][a-z0-9_.]{2,79}$/.test(v.ruleId)) return no("the replay spec needs a rule id");
  if (!str(v.title, 300)) return no("the replay spec needs a title");
  if (!Array.isArray(v.vars) || v.vars.length > 10 || !v.vars.every((x) => typeof x === "string" && NAME.test(x))) return no("vars must be a short list of names");
  if (!Array.isArray(v.steps) || !v.steps.length || v.steps.length > MAX_SPEC_STEPS) return no(`a replay spec has between 1 and ${MAX_SPEC_STEPS} steps`);
  const steps: (ReplayStep | DeriveStep)[] = [];
  for (const [i, raw] of v.steps.entries()) {
    const at = `step ${i + 1}`;
    if (!isObj(raw)) return no(`${at}: must be an object`);
    if (isObj(raw.derive)) {
      const d = raw.derive;
      if (!str(d.name, 40) || !NAME.test(d.name) || !Array.isArray(d.from) || d.from.length !== 2 || !d.from.every((x) => typeof x === "string" && NAME.test(x))) return no(`${at}: a derive step needs a name and two sources`);
      steps.push({ derive: { name: d.name, from: [d.from[0] as string, d.from[1] as string] } });
      continue;
    }
    if (!ROLES.includes(raw.as as As)) return no(`${at}: unknown role`);
    if (!METHODS.includes(raw.method as Method)) return no(`${at}: unknown method`);
    if (!str(raw.path, 600) || !PATH.test(raw.path) || raw.path.startsWith("//") || raw.path.split("?")[0]!.split("/").includes("..")) return no(`${at}: the path must be a path on the app`);
    const st: ReplayStep = { as: raw.as as As, method: raw.method as Method, path: raw.path };
    if (raw.body !== undefined) { if (!str(raw.body, 8000)) return no(`${at}: the body is too long`); st.body = raw.body; }
    if (raw.headers !== undefined) {
      if (!isObj(raw.headers) || Object.keys(raw.headers).length > 8) return no(`${at}: headers must be a small object`);
      const h: Record<string, string> = {};
      for (const [k, val] of Object.entries(raw.headers)) {
        // "Authorization: Bearer undefined" is the one credential-shaped header a recorded test carries (a broken token).
        const brokenToken = k.toLowerCase() === "authorization" && val === "Bearer undefined";
        if (!HEADER.test(k) || (FORBIDDEN_HEADERS.has(k.toLowerCase()) && !brokenToken) || !str(val, 300) || /[\r\n]/.test(val)) return no(`${at}: header ${k.slice(0, 40)} is not allowed in a replay spec`);
        h[k] = val;
      }
      st.headers = h;
    }
    if (raw.login !== undefined) {
      if (!isObj(raw.login) || !["a", "b", "admin", "viewer"].includes(String(raw.login.role)) || typeof raw.login.wrong !== "boolean") return no(`${at}: a sign-in step needs a role and wrong`);
      st.login = { role: raw.login.role as "a", wrong: raw.login.wrong };
    }
    if (raw.replyPath !== undefined) { if (!str(raw.replyPath, 200) || !JSON_PATH.test(raw.replyPath)) return no(`${at}: replyPath`); st.replyPath = raw.replyPath; }
    if (raw.save !== undefined) {
      if (!isObj(raw.save) || !str(raw.save.name, 40) || !NAME.test(raw.save.name) || !str(raw.save.from, 200) || !JSON_PATH.test(raw.save.from)) return no(`${at}: save needs a name and a path`);
      st.save = { name: raw.save.name, from: raw.save.from };
    }
    if (raw.keep !== undefined) { if (!str(raw.keep, 40) || !NAME.test(raw.keep)) return no(`${at}: keep`); st.keep = raw.keep; }
    for (const flag of ["setup", "cleanup"] as const) if (raw[flag] !== undefined) { if (typeof raw[flag] !== "boolean") return no(`${at}: ${flag} must be true or false`); if (raw[flag]) st[flag] = true; }
    if (raw.repeat !== undefined) { if (!Number.isInteger(raw.repeat) || (raw.repeat as number) < 1 || (raw.repeat as number) > MAX_REPEAT) return no(`${at}: repeat must be from 1 to ${MAX_REPEAT}`); st.repeat = raw.repeat as number; }
    if (raw.leg !== undefined) { if (!["plant", "positive", "test", "negative"].includes(String(raw.leg))) return no(`${at}: unknown leg`); st.leg = raw.leg as ReplayStep["leg"]; }
    if (raw.expect !== undefined) { const e = parseExpect(raw.expect); if (typeof e === "string") return no(`${at}: ${e}`); st.expect = e; }
    steps.push(st);
  }
  return { ok: true, spec: { ruleId: v.ruleId, title: v.title, vars: v.vars as string[], accounts: {}, steps } };
}

/** The replay spec inside a file: a bare spec, a finding ({ replay }), an evidence bundle, or a report with one finding. */
export function specFromFile(v: unknown, pick?: number): SpecParse {
  if (isObj(v) && Array.isArray(v.findings)) {
    const list = v.findings.filter((f) => isObj(f) && isObj(f.replay));
    if (!list.length) return { ok: false, why: "this report holds no finding with replay steps" };
    if (list.length > 1 && pick === undefined) return { ok: false, why: `this report holds ${list.length} findings: name one with --finding 1 to ${list.length}` };
    const f = list[(pick ?? 1) - 1];
    if (!f) return { ok: false, why: `there is no finding ${pick} in this report (it holds ${list.length})` };
    return parseReplaySpec((f as { replay: unknown }).replay);
  }
  if (isObj(v) && isObj(v.replay)) return parseReplaySpec(v.replay);
  return parseReplaySpec(v);
}

// ── Running a spec ───────────────────────────────────────────────────────────────────────────────────────────────
const ok = (s: number) => s >= 200 && s < 300;
const J = (s: string) => JSON.stringify(s).slice(1, -1);
const fillWith = (s: string, vars: Record<string, string>, how: (v: string) => string) => s.replace(/\{\{(\w+)\}\}/g, (m, k: string) => (k in vars ? how(vars[k]!) : m));
export const fillPath = (s: string, vars: Record<string, string>) => fillWith(s, vars, encodeURIComponent);
export const fillBody = (s: string, vars: Record<string, string>) => fillWith(s, vars, J);
export const fillText = (s: string, vars: Record<string, string>) => fillWith(s, vars, (v) => v);

function leaves(text: string): string[] {
  const out: string[] = [];
  let v: unknown;
  try { v = JSON.parse(text); } catch { return out; }
  const walk = (x: unknown) => { if (typeof x === "string" && x.length >= 6 && x.length <= 120) out.push(x); else if (x && typeof x === "object") for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k]); };
  walk(v);
  return out;
}

export interface StepOutcome { step: number; as: As; method: Method; path: string; leg?: string; statuses: number[]; failure: string | null }
export interface SpecRun {
  /** Failed expectations, in the words of the regression tests. Empty = the attack no longer works. */
  failures: string[];
  steps: StepOutcome[];
  /** A setup step did not succeed, a role has no account, or a step is not supported here: nothing can be said. */
  incomplete: string | null;
}
export interface SpecDeps {
  /** Values for the spec's variables. A variable without one gets a fresh random text. */
  vars?: Record<string, string>;
  random: () => string;
  /** A sign-in request for a role (real or wrong password). Without it a spec with sign-in steps cannot be run. */
  login?: (role: "a" | "b" | "admin" | "viewer", wrong: boolean, wrongPassword: string) => Promise<HttpAnswer | null>;
  /** Asks whether a canary was called. Without it a canary expectation cannot be checked (and says so). */
  canaryHits?: (token: string) => Promise<number | null>;
  /** The app's origin: a redirect is resolved against it, and https decides whether a cookie needs Secure. */
  base?: string;
}

/** The kind of test a step is, for the rules-of-engagement record. */
export function classOfStep(st: ReplayStep, creator: As | null): SafetyClass {
  if ((st.repeat ?? 1) > 1) return "burst";
  if (st.method === "GET" || st.method === "HEAD") return "read";
  if (st.replyPath) return "ai_messages";
  if (!st.cleanup && !st.save && creator && creator !== st.as) return "write_cross_account_test_records";
  return "write_own_test_records";
}

/** Run a spec. Clean-up steps always run at the end, whatever happened before. */
export async function runSpec(spec: ReplaySpec, io: EngageIo, deps: SpecDeps): Promise<SpecRun> {
  const vars: Record<string, string> = {};
  for (const v of spec.vars) vars[v] = deps.vars?.[v] ?? `yof${v}${deps.random()}`;
  const failures: string[] = [];
  const steps: StepOutcome[] = [];
  // Every clean-up step is known before anything is sent, so a run that ends early still deletes what it created.
  const cleanups: { st: ReplayStep; n: number }[] = spec.steps.flatMap((st, i) => (!isDerive(st) && st.cleanup ? [{ st, n: i + 1 }] : []));
  let incomplete: string | null = null;
  let creator: As | null = null;
  const sendStep = async (st: ReplayStep): Promise<{ last: HttpAnswer | null; statuses: number[] }> => {
    const statuses: number[] = [];
    let last: HttpAnswer | null = null;
    for (let i = 0; i < (st.repeat ?? 1); i++) {
      if (st.login) {
        last = deps.login ? await deps.login(st.login.role, st.login.wrong, vars.wrong ?? "yof-wrong") : null;
        if (last === null) return { last: null, statuses };
        statuses.push(last.status);
        continue;
      }
      const init: EngageInit = {
        ...(st.headers ? { headers: st.headers } : {}), ...(st.body !== undefined ? { body: fillBody(st.body, vars) } : {}),
        purpose: st.cleanup ? "cleanup" : st.method === "GET" || st.method === "HEAD" ? "read" : st.replyPath ? "ai" : st.save && st.method === "POST" ? "create" : "owned",
        cls: classOfStep(st, creator), ...(st.cleanup ? { leg: "cleanup" as const } : st.leg ? { leg: st.leg } : {}),
      };
      last = await io.send(st.as, st.method, fillPath(st.path, vars), init);
      if (last === null) return { last: null, statuses };
      statuses.push(last.status);
    }
    return { last, statuses };
  };
  try {
    for (const [i, raw] of spec.steps.entries()) {
      if (isDerive(raw)) { const [a, b] = raw.derive.from; vars[raw.derive.name] = leaves(vars[a] ?? "").find((x) => !(vars[b] ?? "").includes(x)) ?? ""; continue; }
      const st = raw;
      if (st.cleanup) continue;
      const { last, statuses } = await sendStep(st);
      const where = `${st.method} ${st.path} as ${st.as}`;
      const out: StepOutcome = { step: i + 1, as: st.as, method: st.method, path: st.path, ...(st.leg ? { leg: st.leg } : {}), statuses, failure: null };
      steps.push(out);
      if (last === null) { incomplete = st.login && !deps.login ? `${where}: a sign-in step cannot be run here` : `${where}: account ${st.as} is not set, or its sign-in failed`; break; }
      if (st.setup && !ok(last.status)) { incomplete = `Setup step ${where} answered HTTP ${last.status}.`; break; }
      if (st.save) {
        vars[st.save.name] = readPath(last.body, st.save.from);
        if (st.method === "POST" && vars[st.save.name]) { io.own(vars[st.save.name]!); creator = st.as; }
      }
      if (st.keep) vars[st.keep] = last.body;
      const e = st.expect;
      if (!e) continue;
      const text = st.replyPath ? readPath(last.body, st.replyPath) : last.body;
      const fail = (m: string) => { out.failure = `${where} ${m}`; failures.push(out.failure); };
      const good = ok(last.status);
      switch (e.kind) {
        case "denied": if (good) fail(`should be refused, got HTTP ${last.status}`); break;
        case "not_contains": { const v = fillText(e.value, vars); if (v && good && text.includes(v)) fail("returned data it must not return"); break; }
        case "marker_absent": { const v = fillText(e.value, vars); if (v && text.includes(v)) fail("returned another account's test record"); break; }
        case "marker_present": { const v = fillText(e.value, vars); if (!v || !good || !text.includes(v)) fail(`did not return the account's own test record (HTTP ${last.status}), so the test shows nothing`); break; }
        case "not_redirect_to": { let h = ""; try { h = new URL(last.location ?? "", deps.base ?? "https://example.invalid").hostname; } catch { h = ""; } if (last.status >= 300 && last.status < 400 && last.location && h === e.host) fail(`redirects to ${e.host}`); break; }
        case "header_present": if (!last.headers.get(e.name)) fail(`has no ${e.name} header`); break;
        case "not_instructions": if (good && looksLikeInstructions(text)) fail("gave out its hidden instructions"); break;
        case "some_status": if (!statuses.some((s) => e.status.includes(s))) fail(`was never slowed down (${statuses.length} tries)`); break;
        case "count_at_most": { const n = statuses.filter(ok).length; if (n > e.max) fail(`succeeded ${n} times, at most ${e.max} allowed`); break; }
        case "no_unsafe_markup": if (good && unsafeMarkup(text, fillText(e.value, vars))) fail("answered with live markup or a picture link a page could run"); break;
        case "not_unlocked": if (good && saysUnlockWord(text, fillText(e.value, vars))) fail("dropped its rules when told they were off"); break;
        case "no_internal": if (good && internalDetails(text).length) fail("showed internal details"); break;
        case "no_claimed_action": if (good && claimsOutwardAction(text)) fail("said it acted without asking first"); break;
        case "short_answer": if (good && text.length >= e.max) fail(`gave an answer of ${text.length} characters`); break;
        case "cookie_flags": {
          const h = last.headers as Headers & { getSetCookie?: () => string[] };
          const sc = (typeof h.getSetCookie === "function" ? h.getSetCookie() : [h.get("set-cookie") ?? ""]).filter(Boolean);
          const https = (deps.base ?? "").startsWith("https:");
          if (sc.some((c) => !/;\s*httponly/i.test(c) || !/;\s*samesite=/i.test(c) || (https && !/;\s*secure/i.test(c)))) fail("sets a cookie without HttpOnly, SameSite or Secure");
          break;
        }
        case "canary_hit": {
          const hits = deps.canaryHits ? await deps.canaryHits(fillText(e.token, vars)) : null;
          if (hits === null) fail("could not be checked: no canary address is set");
          else if (hits > 0) fail("made the app call the canary address");
          break;
        }
      }
    }
  } finally {
    for (const { st, n } of cleanups) {
      try { const { statuses } = await sendStep(st); steps.push({ step: n, as: st.as, method: st.method, path: st.path, leg: "cleanup", statuses, failure: null }); }
      catch { /* the app may already have removed it, or the run was stopped: the caller's summary says what is left */ }
    }
  }
  return { failures, steps, incomplete };
}
