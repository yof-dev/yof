/**
 * yof attack: the runner. It tests the person's OWN app, already proven by ./proof.ts, with the test accounts they
 * name in the config, and records each finding together with the exact steps that proved it.
 *
 *   auth     each signed-in route, without a sign-in (and with a broken token): the same data back = attack.auth_bypass
 *   rbac     each admin route as a normal member = attack.rbac_escalation. A FINDING needs one of two proofs, and the
 *            finding says which (meta.proof):
 *              "marker"  the differential's rule (./engage/differential.ts): a marker the admin account planted in
 *                        its own test record, seen by the member, plus both controls (the admin sees it; a path that
 *                        does not exist is refused in a different way);
 *              "identifying data on a declared admin route"  where no marker can be planted (a list of users or
 *                        accounts): the route is one YOUR config declares admin-only, the member's answer is a
 *                        success that carries identifying values (ids, emails, names) of accounts other than the
 *                        member's own, the admin's answer carries the same values, a signed-out request to the same
 *                        route is refused in a recognisably different way, and it shows again on a fresh session.
 *            Anything short of that ("the same data" made of values any two accounts share, an app that answers 200
 *            to everyone, a member who sees only its own record) is listed under "needs validation", never a finding.
 *            In a full run with an admin account and an object in the config, the admin account creates one test
 *            record for this, and it is deleted at the end. With a "viewer" account (a member who may only read, in
 *            account A's tenant): each admin route as the viewer under the same rule, and, in a full run, the viewer
 *            tries to create a test record, to change one of account A's and to delete one of account A's
 *            = attack.viewer_escalation. Only the run's own test records are touched, and deleted.
 *   tenant   account A creates a test record; account B reads it by id (attack.tenant_read), lists it, and changes it
 *            (attack.tenant_write, seen when A reads the change). The record is deleted at the end, always.
 *   ai       the app's own assistant: hidden-instruction extraction, a typed injection, an injection hidden in a record
 *            the assistant reads, a record of another account fetched through its tools, admin data fetched through
 *            its tools by a member; and (Y11, OWASP LLM Top 10 2025) live markup or picture links in its answers, the
 *            same injection hidden in pasted text, a mild fixed jailbreak that asks only for a harmless word, internal
 *            details (only their kinds are kept), a claimed email to a .invalid address, account B's record steering
 *            account A's general answer (RAG poisoning), account B's record renamed through A's assistant, and, only
 *            with ai[i].limits, a 10-message burst and one very long answer
 *   surface  open redirects, missing security headers, sign-in with no rate limit, a sign-in cookie without its flags
 *
 * CONFIRMED only: every finding is reproduced a second time before it is reported. What did not reproduce is counted
 * in the notes, never reported as a finding.
 *
 * A light run is read-only, and that is enforced in the HTTP client (readOnly): only GET and HEAD are sent. Auth, rbac
 * and the read-only surface checks run; nothing is created, no message is sent to the assistant, and NO account is
 * signed in. A sign-in is a POST with a real password that makes a session on the app, so it is not "read-only"
 * (security audit A5b, 11 Nov 2026: a light run used to send it while the README said read-only). An account that
 * signs in with a password is therefore left out of a light run, with a note that says so; an account given as a
 * header (a token or a session cookie in a YOF_ATTACK_ variable) is used as before. A sign-in belongs to a full run,
 * which the person chooses knowingly.
 */
import { randomBytes } from "node:crypto";
import { ATTACK_GROUPS, ATTACK_RULE_BY_ID, type AttackGroup, type AttackSeverity } from "./catalog";
import { ENV_PREFIX, fill, isLoginAccount, ROLES, type AccountSpec, type AiSpec, type AttackConfig, type Budget, type ObjectSpec, type Role } from "./config";
import { DIFFERENTIAL_REASON_WORDS, decideDifferential, refusedDifferently, type Leg } from "./engage/differential";
import { markerText, newRunNonce } from "./engage/markers";
import { AttackClient, BudgetError, RefusedError, StoppedError, type As, type Exchange, type FetchFn, type HttpAnswer, type Method } from "./http";
import { answerShape, maskEvidence } from "./mask";
import {
  BURST_MESSAGE, BURST_PARALLEL, BURST_SIZE, CARRIERS, LONG_OUTPUT_PROBE, UNBOUNDED_CHARS, aiProbes, aiProbesY11, burstLimited, carrierDocument,
  claimsOutwardAction, crossTenantQuestion, indirectQuestion, internalDetails, looksLikeInstructions, privilegeQuestion, ragQuestion, readPath,
  saysUnlockWord, unboundedOutput, unlockWord, unsafeMarkup, writeQuestion,
} from "./probes";
import type { Mode, ProofOk } from "./proof";
import type { ReplaySpec, ReplayStep } from "./replay";
import { totpCode } from "./totp";

export const REDIRECT_PROBE_HOST = "yof.io";
const REDIRECT_PROBE = "https://yof.io/yof-attack-redirect-check";
const REDIRECT_PARAMS = ["next", "redirect", "redirect_uri", "returnTo", "return_to", "url", "continue", "dest"];
const RATE_TRIES = 12;

export interface AttackFinding {
  ruleId: string;
  group: AttackGroup;
  severity: AttackSeverity;
  title: string;
  method: Method;
  /** The route as written in the config (with {id}), never a real id. */
  route: string;
  as: As;
  status: number;
  /** What was seen, in yof's own words: never a piece of the answer itself. At most 200 characters, masked. */
  evidence: string;
  meta: Record<string, string>;
  replay: ReplaySpec;
}

export type GroupStatus = "done" | "partial" | "skipped" | "not_run";
/** Why a run ended early: a budget ran out, or the person stopped it (a signal). */
export type StopReason = "requests" | "time" | "cancelled";
/** After a stop signal, clean-up gets at most this long before the run gives up and lists what is left. */
export const STOP_CLEANUP_MS = 10_000;
/** A result that needs a person's look: something was seen, but not enough to call it a finding. Never counted. */
export interface AttackReview { ruleId: string; method: Method; route: string; as: As; status: number; reason: string }
export interface AttackRunResult {
  findings: AttackFinding[];
  /** "Needs validation": seen, not proven. Not findings, not uploaded, and they never fail a run. */
  review: AttackReview[];
  groups: Record<AttackGroup, GroupStatus>;
  notes: string[];
  stopped: null | StopReason;
  /** The test records this run created: how many it deleted, and the routes (with {id}) of any it could not. */
  cleanup: { deleted: number; left: string[] };
  exchanges: Exchange[];
  requests: number;
  unconfirmed: number;
}

export interface RunOptions {
  cfg: AttackConfig;
  proof: ProofOk;
  mode: Mode;
  /** Groups to run (a scoped pull-request run); default all. */
  groups?: readonly AttackGroup[];
  /** A scoped run attacks only routes this accepts. */
  routeFilter?: (path: string) => boolean;
  env?: Record<string, string | undefined>;
  fetch?: FetchFn;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => string;
  budget?: Budget;
  /** Aborted when the person stops the run: no new probe, then the clean-up (at most STOP_CLEANUP_MS). */
  signal?: AbortSignal;
}

// The masking helpers live in ./mask.ts (the engagement evidence uses the same ones); they are exported from here as before.
export { answerShape, maskEvidence };

const ok = (s: number) => s >= 200 && s < 300;
const DENIED = /\b(forbidden|unauthori[sz]ed|not allowed|access denied|permission denied|no permission|sign ?in|log ?in|login required)\b/i;
function leaves(text: string): string[] {
  let v: unknown;
  try { v = JSON.parse(text); } catch { return []; }
  const out: string[] = [];
  const walk = (x: unknown) => {
    if (out.length > 500) return;
    if (typeof x === "string" && x.length >= 6 && x.length <= 120) out.push(x);
    else if (typeof x === "number" && String(x).length >= 4) out.push(String(x));
    else if (x && typeof x === "object") for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k]);
  };
  walk(v);
  return out;
}
/**
 * Does `other` carry the same data as `base` (the owner's answer)? Same body, or a shared distinctive value.
 * This is a GUESS: it only ever feeds accountData below (the signed-out check). It decides no finding on its own, and
 * the admin-route comparison no longer uses it (see the rbac group).
 */
export function sameData(base: string, other: string): boolean {
  if (!other.trim()) return false;
  if (base.trim() === other.trim()) return true;
  if (DENIED.test(other.slice(0, 2000)) && other.length < 2000) return false;
  const a = new Set(leaves(base));
  return leaves(other).some((x) => a.has(x));
}
/**
 * A field whose value names a person, an account or a record: an id, an email address, a user name, a phone number.
 * A plan, a status, a role, a flag, a count or a date is not one: any two accounts share those.
 */
const IDENTIFYING_KEY = /(?:^|_)(?:id|uuid|guid|sub|email|e_?mail|login|handle|slug|phone|mobile|iban|owner|name|username)$/;
/** A field name in one spelling: userId, user-id and user_id are all user_id. */
const fieldName = (k: string) => k.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/-/g, "_").toLowerCase();
/** A date, a time or an epoch number: two requests share one by chance, and it says nothing about whose data it is. */
const TIME_LIKE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}|$)|^1\d{9}(?:\d{3})?$/;
const GENERIC = new Set(["true", "false", "null", "none", "undefined", "unknown", "default", "anonymous", "guest", "user", "admin", "member", "n/a"]);
/** The identifying values of a JSON answer, as "field=value" (the field's own name, wherever it sits). Pure. */
export function identifying(text: string): Set<string> {
  const out = new Set<string>();
  let v: unknown;
  try { v = JSON.parse(text); } catch { return out; }
  let seen = 0;
  const walk = (x: unknown, key: string) => {
    if (++seen > 5000) return;
    if (Array.isArray(x)) { for (const y of x) walk(y, key); return; }
    if (x && typeof x === "object") { for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k], k); return; }
    if (!IDENTIFYING_KEY.test(fieldName(key))) return;
    const s = typeof x === "string" ? x.trim() : typeof x === "number" && Number.isFinite(x) ? String(x) : "";
    if (s.length > 200 || TIME_LIKE.test(s) || GENERIC.has(s.toLowerCase())) return;
    // A short number (id 1, id 42) is too easy to share by chance; a string id needs 3 characters.
    if (typeof x === "number" ? s.replace(/\D/g, "").length < 4 : s.length < 3) return;
    out.add(`${key.toLowerCase().replace(/[_-]/g, "")}=${s.toLowerCase()}`);
  };
  walk(v, "");
  return out;
}

/**
 * Whose data came back to a request that carried no sign-in? (yof audit 4.4, 11 Nov 2026.) sameData above says yes on
 * ANY shared value, so a public answer that every visitor gets (a product list, a plan name, a status, an empty list)
 * read as "the signed-in account's data": both hits on the OWASP Juice Shop were false. Three answers:
 *   "account"  the signed-out answer holds an identifying value of the signed-in account (identifying() above), and
 *              that value is shown to belong to THIS account: it is the account's own known identity (`identity`, its
 *              sign-in email), or another account's answer to the same route (`otherAccount`, from a separate
 *              tenant) does not hold it. Only this is a finding.
 *   "unclear"  the answers share something, but nothing shows it is this account's: no identifying value in common,
 *              or one that the other account gets too, or there is no second account to compare with. Reported as
 *              "needs validation", never as a finding.
 *   "none"     nothing in common, a refusal, or two answers that hold no value at all (an empty list).
 * Pure.
 */
export type DataMatch = "account" | "unclear" | "none";
export function accountData(base: string, anon: string, known: { otherAccount?: string | null; identity?: readonly string[] } = {}): DataMatch {
  if (!sameData(base, anon) || !leaves(base).length) return "none";
  const mine = identifying(base);
  const shared = [...identifying(anon)].filter((x) => mine.has(x));
  if (!shared.length) return "unclear";
  const valueOf = (pair: string) => pair.slice(pair.indexOf("=") + 1);
  const ids = new Set((known.identity ?? []).map((s) => s.trim().toLowerCase()).filter((s) => s.length >= 3));
  if (shared.some((x) => ids.has(valueOf(x)))) return "account";
  if (typeof known.otherAccount !== "string") return "unclear";
  const theirs = known.otherAccount.toLowerCase();
  return shared.some((x) => !theirs.includes(valueOf(x))) ? "account" : "unclear";
}
/** The proof an admin-route finding rests on. */
export type AdminProof = "marker" | "identifying data on a declared admin route";
export const PROOF_IDENTIFYING: AdminProof = "identifying data on a declared admin route";
/** A field that names a person by an address or a sign-in name (the member's own email is compared with these). */
const NAMING_KEY = /(?:email|mail|login|username|handle)$/;
/**
 * The identifying values (identifying() above) that BOTH the admin's answer and the other role's answer hold, and that
 * are shown to be of accounts OTHER than that role's own. Nobody tells the runner which record is the member's, so
 * "other" is shown in one of two ways and never guessed:
 *   - one field holds two or more different values (two ids, two email addresses): one account has one of each, so
 *     at least one belongs to somebody else;
 *   - the role's own sign-in email is known (`own`) and the answer names a different address or sign-in name.
 * Values any two accounts share (a plan, a status, a flag, a date, a count) are never identifying. Empty = not shown. Pure.
 */
export function othersIdentifying(adminBody: string, body: string, own: readonly string[] = []): string[] {
  const mine = new Set(own.map((x) => x.trim().toLowerCase()).filter((x) => x.length >= 3));
  const admin = identifying(adminBody);
  const valueOf = (pair: string) => pair.slice(pair.indexOf("=") + 1);
  const keyOf = (pair: string) => pair.slice(0, pair.indexOf("="));
  const shared = [...identifying(body)].filter((x) => admin.has(x) && !mine.has(valueOf(x)));
  const perKey = new Map<string, number>();
  for (const x of shared) perKey.set(keyOf(x), (perKey.get(keyOf(x)) ?? 0) + 1);
  const several = shared.filter((x) => (perKey.get(keyOf(x)) ?? 0) >= 2);
  if (several.length) return several;
  return mine.size ? shared.filter((x) => NAMING_KEY.test(keyOf(x))) : [];
}
/** The first distinctive value in `a` that does not appear in `b` ("" when none). */
export const distinct = (a: string, b: string) => leaves(a).filter((x) => !/^\d+$/.test(x)).find((x) => !b.includes(x)) ?? "";

const withId = (p: string, id: string) => p.split("{id}").join(encodeURIComponent(id));

/** What a sign-in is sent through: the HTTP client, or the engagement governor around it. */
export interface LoginSender { send: AttackClient["send"] }
export class Auth {
  private cache = new Map<Role, Record<string, string> | null>();
  readonly cookieFlags = new Map<Role, string[]>();
  /** `light`: a read-only run never signs an account in; `skipped` is told the role once. */
  constructor(private cfg: AttackConfig, private env: Record<string, string | undefined>, private http: LoginSender, private light = false, private skipped: (role: Role) => void = () => {}) {}
  has(role: Role): boolean { return !!this.cfg.accounts[role]; }
  /** An account value from the environment. Only YOF_ATTACK_* names are ever read (audit 3.9), whatever built the config. */
  private read(name: string): string | undefined { return name.startsWith(ENV_PREFIX) ? this.env[name] : undefined; }
  /** A role whose session can expire (a login account): it can be signed in again on a 401. */
  refreshable(role: As): boolean { const a = role === "anon" ? undefined : this.cfg.accounts[role]; return !!a && isLoginAccount(a); }
  /** The headers already known for a role (clean-up never signs in again: a role that made a record has them). */
  cached(role: As): Record<string, string> | null { return role === "anon" ? {} : this.cache.get(role) ?? null; }
  /** Forget a role's session so the next headers() signs it in fresh (used when its session expired). */
  forget(role: As): void { if (role !== "anon") this.cache.delete(role); }
  async headers(role: As): Promise<Record<string, string> | null> {
    if (role === "anon") return {};
    if (this.cache.has(role)) return this.cache.get(role)!;
    const acc = this.cfg.accounts[role];
    // The static headers a role carries (Y23): one or more env-held values (a token, a session cookie, a workspace
    // header). A login account's `headers` are the EXTRA headers next to the session it signs in for.
    const staticHeaders = (): Record<string, string> | null => {
      const out: Record<string, string> = {};
      for (const p of acc!.headers) { const v = this.read(p.env); if (!v) return null; out[p.header] = v; }
      return out;
    };
    let h: Record<string, string> | null = null;
    if (acc && !isLoginAccount(acc)) {
      h = staticHeaders();
    } else if (acc && this.light) {
      // A light run is read-only: no sign-in request is sent, so this account takes no part (see the file header).
      this.skipped(role);
    } else if (acc) {
      const email = this.read(acc.emailEnv), pw = this.read(acc.passwordEnv);
      // A sign-in recipe (owner 2026-11-11) runs fresh here, with a one-time code when the account uses one, so a
      // session that expires (e.g. a 15-minute cookie) is signed in again instead of a fixed header secret.
      const totp: { totp?: string } = acc.login.totpEnv ? { totp: totpCode(this.read(acc.login.totpEnv) ?? "") } : {};
      if (email && pw && (!acc.login.totpEnv || totp.totp)) {
        const r = await this.http.send(role, "POST", acc.login.path, { body: fill(acc.login.body, { email, password: pw, ...(totp.totp ? { totp: totp.totp } : {}) }), purpose: "login" });
        if (ok(r.status)) {
          const extra = staticHeaders();
          if (extra !== null) {
            if (acc.login.tokenPath) { const t = readPath(r.body, acc.login.tokenPath); h = t ? { [acc.login.header ?? "Authorization"]: `${acc.login.prefix ?? ""}${t}`, ...extra } : null; }
            else {
              const sc = setCookies(r.headers);
              this.cookieFlags.set(role, sc);
              const c = sc.map((x) => x.split(";")[0]).filter(Boolean).join("; ");
              h = c ? { Cookie: c, ...extra } : null;
            }
          }
        }
      }
    }
    this.cache.set(role, h);
    return h;
  }
}
const setCookies = (h: Headers): string[] => (typeof (h as Headers & { getSetCookie?: () => string[] }).getSetCookie === "function" ? h.getSetCookie() : [h.get("set-cookie") ?? ""]).filter(Boolean);

export async function runAttack(o: RunOptions): Promise<AttackRunResult> {
  const { cfg, mode } = o;
  const env = o.env ?? process.env;
  const random = o.random ?? (() => randomBytes(6).toString("hex"));
  const postPaths = [
    ...cfg.objects.map((x) => x.create.path), ...cfg.ai.map((a) => a.path), ...cfg.ai.flatMap((a) => (a.ingest ? [a.ingest.create.path] : [])),
    ...ROLES.flatMap((r) => { const acc = cfg.accounts[r]; return acc && isLoginAccount(acc) ? [acc.login.path] : []; }),
  ];
  const http = new AttackClient({ origin: o.proof.origin, budget: o.budget ?? cfg.budget, fetch: o.fetch, now: o.now, sleep: o.sleep, postPaths, signal: o.signal, readOnly: mode === "light" });
  const findings: AttackFinding[] = [];
  const review: AttackReview[] = [];
  const notes: string[] = [];
  const auth = new Auth(cfg, env, http, mode === "light", (role) => notes.push(`skipped:sign-in:account ${role} signs in with a password, and a light run is read-only, so it sends no sign-in. Give the account as a header (a token or a session cookie in a YOF_ATTACK_ variable) or use --mode full`));
  let unconfirmed = 0;
  const groups = Object.fromEntries(ATTACK_GROUPS.map((g) => [g, "not_run"])) as Record<AttackGroup, GroupStatus>;
  const wanted = new Set(o.groups ?? ATTACK_GROUPS);
  const routeOk = o.routeFilter ?? (() => true);
  const accounts = (...roles: Role[]) => Object.fromEntries(roles.map((r) => [r, cfg.accounts[r as "a"]]).filter(([, v]) => v)) as ReplaySpec["accounts"];
  const cleanupList: { as: Role; path: string }[] = [];
  const cleanup: AttackRunResult["cleanup"] = { deleted: 0, left: [] };
  const runNonce = newRunNonce();

  const send = async (as: As, method: Method, path: string, init: { body?: string; purpose?: "read" | "login" | "create" | "ai" | "owned" | "cleanup"; headers?: Record<string, string> } = {}): Promise<HttpAnswer | null> => {
    const h = await auth.headers(as);
    if (h === null) return null;
    const r = await http.send(as, method, path, { ...init, headers: { ...h, ...(init.headers ?? {}) } });
    // A session that has expired answers 401/403: sign the role in again once and retry (owner 2026-11-11). Only a
    // login account is refreshed, and never a create (its record must stay known for clean-up) or the clean-up itself.
    if ((r.status === 401 || r.status === 403) && auth.refreshable(as) && init.purpose !== "create" && init.purpose !== "cleanup") {
      auth.forget(as);
      const fresh = await auth.headers(as);
      if (fresh) return http.send(as, method, path, { ...init, headers: { ...fresh, ...(init.headers ?? {}) } });
    }
    return r;
  };
  const report = (ruleId: string, x: { method: Method; route: string; as: As; status: number; evidence: string; meta?: Record<string, string>; replay: Omit<ReplaySpec, "ruleId" | "title"> }) => {
    const rule = ATTACK_RULE_BY_ID[ruleId]!;
    if (findings.some((f) => f.ruleId === ruleId && f.route === x.route && f.method === x.method)) return;
    findings.push({ ruleId, group: rule.group, severity: rule.severity, title: rule.title, method: x.method, route: x.route, as: x.as, status: x.status, evidence: maskEvidence(x.evidence), meta: x.meta ?? {}, replay: { ruleId, title: rule.title, ...x.replay } });
  };
  /** Run `probe` again; only a finding that shows twice is reported. */
  const confirm = async (probe: () => Promise<boolean>): Promise<boolean> => { const yes = await probe(); if (!yes) unconfirmed++; return yes; };

  /** Create a test-owned record as `role`; returns its id or null. */
  const create = async (role: Role, spec: { create: { path: string; body: string }; idPath: string; delete: string }, values: Record<string, string>): Promise<string | null> => {
    if (!http.roomToCreate) throw new BudgetError("requests");
    const r = await send(role, "POST", spec.create.path, { body: fill(spec.create.body, values), purpose: "create" });
    if (!r || !ok(r.status)) { notes.push(`create_failed:${spec.create.path}:${r?.status ?? "no_account"}`); return null; }
    const id = readPath(r.body, spec.idPath);
    if (!id || id.length > 200) { notes.push(`no_id:${spec.create.path}`); return null; }
    http.own(id);
    cleanupList.push({ as: role, path: withId(spec.delete, id) });
    return id;
  };

  // ── auth ──────────────────────────────────────────────────────────────────────────────────────
  const authGroup = async () => {
    // A signed-in owner is needed to compare the signed-out answer against. Prefer A; fall back to admin.
    const owner: Role | null = auth.has("a") ? "a" : auth.has("admin") ? "admin" : null;
    if (!owner) { notes.push("skipped:auth:no test account to sign in with (add account A)"); return "skipped" as const; }
    const targets = [...cfg.routes.map((p) => ({ p, owner })), ...cfg.admin.map((p) => ({ p, owner: (auth.has("admin") ? "admin" : owner) as Role }))]
      .filter((t) => !t.p.includes("{id}") && routeOk(t.p));
    if (!targets.length) return "skipped" as const;
    const header = (() => { const acc = cfg.accounts[owner]!; return isLoginAccount(acc) ? acc.login.header ?? "Authorization" : acc.headers[0]?.header ?? "Authorization"; })();
    const variants: { label: string; headers?: Record<string, string> }[] = [{ label: "no sign-in" }, ...(header.toLowerCase() === "authorization" ? [{ label: "a broken token", headers: { Authorization: "Bearer undefined" } }] : [])];
    // Whose data is it? (audit 4.4) The account's own sign-in email when the config knows it, and the answer another
    // account gets for the same route: B for A (a separate tenant), a plain member for the admin.
    const identityOf = (role: Role): string[] => { const acc = cfg.accounts[role]; const e = acc && isLoginAccount(acc) && acc.emailEnv.startsWith(ENV_PREFIX) ? env[acc.emailEnv] : undefined; return e ? [e] : []; };
    const otherOf = (role: Role): Role | null => (role === "a" ? (auth.has("b") ? "b" : null) : auth.has("a") ? "a" : null);
    for (const t of targets) {
      const base = await send(t.owner, "GET", t.p);
      if (!base) { notes.push(`no_account:${t.owner}`); continue; }
      if (!ok(base.status)) { notes.push(`baseline_${base.status}:${t.p}`); continue; }
      let other: string | null | undefined;   // asked once per route, and only when the signed-out answer shares something
      for (const v of variants) {
        const x = await send("anon", "GET", t.p, { headers: v.headers });
        if (!x || !ok(x.status) || !sameData(base.body, x.body)) continue;
        if (other === undefined) { const role = otherOf(t.owner); const r = role ? await send(role, "GET", t.p) : null; other = r ? r.body : null; }
        const known = { otherAccount: other, identity: identityOf(t.owner) };
        const match = accountData(base.body, x.body, known);
        if (match === "none") continue;
        if (match === "unclear") {
          if (!review.some((r) => r.ruleId === "attack.auth_bypass" && r.route === t.p)) {
            review.push({ ruleId: "attack.auth_bypass", method: "GET", route: t.p, as: "anon", status: x.status,
              reason: other === null && !known.identity.length
                ? `GET ${t.p} with ${v.label} answered, and the answer shares values with the signed-in one, but there is no second account in a separate tenant (account B) to show the data belongs to one account. It may be public by design.`
                : `GET ${t.p} with ${v.label} answered, and the answer shares values with the signed-in one, but none that only this account has (another account gets them too, or they are settings, states or dates). It may be public by design.` });
          }
          break;
        }
        if (!(await confirm(async () => { const y = await send("anon", "GET", t.p, { headers: v.headers }); return !!y && ok(y.status) && accountData(base.body, y.body, known) === "account"; }))) continue;
        report("attack.auth_bypass", { method: "GET", route: t.p, as: "anon", status: x.status, evidence: `the same data a signed-in account gets came back: ${answerShape(x.body)}`, meta: { request: `GET ${t.p} with ${v.label}`, status: String(x.status) },
          replay: { vars: [], accounts: {}, steps: [{ as: "anon", method: "GET", path: t.p, ...(v.headers ? { headers: v.headers } : {}), expect: { kind: "denied" } }] } });
        break;
      }
    }
    return "done" as const;
  };

  // ── rbac ──────────────────────────────────────────────────────────────────────────────────────
  const rbacGroup = async () => {
    const routes = cfg.admin.filter((p) => !p.includes("{id}") && routeOk(p));
    // The read-only member (Y24): admin routes, and in a full run the config's objects. A light run writes nothing.
    const viewerObjs = mode === "full" && auth.has("viewer") ? cfg.objects.filter((x) => routeOk(x.read) || routeOk(x.create.path)) : [];
    const viewerPart = auth.has("viewer") && (routes.length > 0 || viewerObjs.length > 0);
    const memberPart = routes.length > 0 && auth.has("a");
    if (!memberPart && !viewerPart) {
      if (routes.length) notes.push("skipped:rbac:no member account to open admin routes with (add account A)");
      return "skipped" as const;
    }
    for (const p of memberPart ? routes : []) {
      if (findings.some((f) => f.ruleId === "attack.auth_bypass" && f.route === p)) continue;
      if ((await adminRoute(p, "a", "attack.rbac_escalation", "a member")) === "no_account") { notes.push("no_account:a"); break; }
    }
    if (viewerPart) await viewerTests(routes, viewerObjs);
    return "done" as const;
  };

  // ── rbac: an admin route opened by a role that is not an admin ────────────────────────────────
  /**
   * The marker of the admin account: one test record the admin creates (a full run, with an admin account and an
   * object in the config), so an answer that holds it is shown to be the admin's data. Planted once, lazily, and
   * deleted at the end like every test record. null = no marker (a light run, no admin account, no object).
   */
  let adminMarker: string | null | undefined;
  const plantAdminMarker = async (): Promise<string | null> => {
    if (adminMarker !== undefined) return adminMarker;
    adminMarker = null;
    const spec = cfg.objects[0];
    if (mode !== "full" || !auth.has("admin") || !spec || !http.roomToCreate) return null;
    const marker = markerText(runNonce, "admin", 1);
    if (await create("admin", spec, { marker })) adminMarker = marker;
    return adminMarker;
  };
  const toLeg = (r: HttpAnswer | null): Leg | null => (r ? { status: r.status, body: r.body } : null);
  /**
   * One admin route as `role`. The decision is the differential's (./engage/differential.ts decideDifferential):
   *   proven            the answer holds the admin's planted marker, the admin sees it too (positive control), a path
   *                     under the route that does not exist is refused in a different way (negative control), and it
   *                     showed twice. Only this is a finding.
   *   needs validation  the role got data the admin also gets, but without a planted marker in it (or without a
   *                     control) nothing shows that the data is for admins only. Listed, never counted.
   */
  const adminRoute = async (p: string, role: "a" | "viewer", ruleId: string, who: string): Promise<"no_account" | "done"> => {
    const first = await send(role, "GET", p);
    if (!first) return "no_account";
    if (!ok(first.status)) return "done";
    const planted = await plantAdminMarker();
    const admin = auth.has("admin") ? await send("admin", "GET", p) : null;
    // A marker counts for this route only when the admin's own answer shows it.
    const marker = planted && admin && ok(admin.status) && admin.body.includes(planted) ? planted : null;
    const test = marker ? await send(role, "GET", p) : first;
    const seen = decideDifferential({ marker, positive: toLeg(admin), test: toLeg(test), negative: null, repeat: null });
    if (!seen.exposed) return "done";
    const [base, query] = p.split("?");
    const negative = await send(role, "GET", `${base!.replace(/\/$/, "")}/yof-none-${random()}${query ? `?${query}` : ""}`);
    const repeat = await send(role, "GET", p);
    const d = decideDifferential({ marker, positive: toLeg(admin), test: toLeg(test), negative: toLeg(negative), repeat: toLeg(repeat) });
    const proofOf = (kind: AdminProof) => ({ request: `GET ${p} as ${who}`, status: String(test!.status), proof: kind });
    // The second proof, where no marker shows on this route: identifying data of other accounts on a route the config
    // declares admin-only, with a signed-out request refused differently, seen again on a fresh session.
    if (!(d.outcome === "proven" && marker) && admin && ok(admin.status) && ok(test!.status)) {
      const acc = cfg.accounts[role];
      const ownEmail = acc && isLoginAccount(acc) && acc.emailEnv.startsWith(ENV_PREFIX) ? env[acc.emailEnv] : undefined;
      const own = ownEmail ? [ownEmail] : [];
      const others = othersIdentifying(admin.body, test!.body, own);
      if (others.length) {
        const anon = await send("anon", "GET", p);
        const usable = !!anon && anon.status !== 0 && anon.status !== 429 && anon.status !== 503;
        const refused = usable && refusedDifferently(toLeg(anon)!, toLeg(test)!, null) && !othersIdentifying(admin.body, anon!.body, own).length;
        if (refused) {
          auth.forget(role);   // a fresh session for a role that signs in; a header account sends its header again
          const fresh = await send(role, "GET", p);
          if (!fresh || !ok(fresh.status) || !othersIdentifying(admin.body, fresh.body, own).length) { unconfirmed++; return "done"; }
          report(ruleId, { method: "GET", route: p, as: role, status: test!.status, evidence: `${who} got the admin answer: ${answerShape(test!.body)}`, meta: proofOf(PROOF_IDENTIFYING),
            replay: { vars: [], accounts: accounts(role), steps: [{ as: role, method: "GET", path: p, expect: { kind: "denied" } }] } });
          return "done";
        }
      }
    }
    if (d.reasons.includes("not_reproduced")) { unconfirmed++; return "done"; }
    if (d.outcome === "proven" && marker) {
      const spec = cfg.objects[0]!;
      report(ruleId, { method: "GET", route: p, as: role, status: test!.status, evidence: `${who} got an answer that holds the admin account's test record: ${answerShape(test!.body)}`, meta: { ...proofOf("marker"), marker: "planted" },
        replay: { vars: ["marker"], accounts: accounts("admin", role), steps: [
          { as: "admin", method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true, leg: "plant" },
          { as: role, method: "GET", path: p, leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } },
          { as: "admin", method: "GET", path: p, leg: "positive", expect: { kind: "marker_present", value: "{{marker}}" } },
          { as: "admin", method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
    } else if (d.outcome === "needs_validation" && !review.some((r) => r.ruleId === ruleId && r.route === p)) {
      review.push({ ruleId, method: "GET", route: p, as: role, status: test!.status,
        reason: `GET ${p} as ${who} answered${admin && ok(admin.status) ? " with data the admin account also gets" : ""}, but that is not proof yet: ${d.reasons.map((r) => DIFFERENTIAL_REASON_WORDS[r]).join("; ")}. It may be meant for every member.` });
    }
    return "done";
  };

  // ── rbac: the read-only member (attack.viewer_escalation) ─────────────────────────────────────
  const VIEWER_RULE = "attack.viewer_escalation";
  const viewerTests = async (routes: string[], objs: ObjectSpec[]) => {
    if ((await auth.headers("viewer")) === null) { notes.push("no_account:viewer"); return; }
    for (const p of routes) {
      // One cause, one finding: a route already open to nobody or to every member is reported (or listed) there.
      if (findings.some((f) => (f.ruleId === "attack.auth_bypass" || f.ruleId === "attack.rbac_escalation") && f.route === p)) continue;
      if (review.some((r) => r.ruleId === "attack.rbac_escalation" && r.route === p)) continue;
      await adminRoute(p, "viewer", VIEWER_RULE, "a read-only member");
    }
    for (const spec of objs) await viewerObject(spec);
  };
  const viewerObject = async (spec: ObjectSpec) => {
    const idVar = (p: string) => p.split("{id}").join("{{id}}");
    // Create: the viewer asks to make a record. A record that does get made is the run's own and is deleted at the end.
    const made = async (): Promise<{ hit: boolean; status: number }> => {
      if (!http.roomToCreate) throw new BudgetError("requests");
      const r = await send("viewer", "POST", spec.create.path, { body: fill(spec.create.body, { marker: `yofmarker${random()}` }), purpose: "create" });
      if (!r || !ok(r.status)) return { hit: false, status: r?.status ?? 0 };
      const id = readPath(r.body, spec.idPath);
      if (!id || id.length > 200) { notes.push(`no_id:${spec.create.path}`); return { hit: false, status: r.status }; }
      http.own(id);
      cleanupList.push({ as: "viewer", path: withId(spec.delete, id) });
      return { hit: true, status: r.status };
    };
    const first = await made();
    if (first.hit && await confirm(async () => (await made()).hit)) {
      report(VIEWER_RULE, { method: "POST", route: spec.create.path, as: "viewer", status: first.status, evidence: `a read-only member created a test record with POST ${spec.create.path}`, meta: { request: `POST ${spec.create.path} as the read-only member`, status: String(first.status) },
        replay: { vars: ["marker"], accounts: accounts("viewer"), steps: [
          { as: "viewer", method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, expect: { kind: "denied" } },
          { as: "viewer", method: "DELETE", path: idVar(spec.delete), cleanup: true }] } });
    }
    // Change and delete need a record of account A for the viewer to try on.
    if (!auth.has("a")) { notes.push("viewer_needs_account_a:the change and delete tests need a record of account A"); return; }
    const setup: ReplayStep[] = [{ as: "a", method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true }];
    const cleanup: ReplayStep = { as: "a", method: "DELETE", path: idVar(spec.delete), cleanup: true };
    if (spec.update) {
      const up = spec.update;
      const id = await create("a", spec, { marker: `yofmarker${random()}` });
      if (id) {
        const changedBy = async () => {
          const m2 = `yofchange${random()}`;
          await send("viewer", up.method, withId(up.path, id), { body: fill(up.body, { marker: m2 }), purpose: "owned" });
          const after = await send("a", "GET", withId(spec.read, id));
          return { hit: !!after && ok(after.status) && after.body.includes(m2), status: after?.status ?? 0 };
        };
        const one = await changedBy();
        if (one.hit && await confirm(async () => (await changedBy()).hit)) {
          report(VIEWER_RULE, { method: up.method, route: up.path, as: "viewer", status: one.status, evidence: `a read-only member changed a test record of account A with ${up.method} ${up.path}`, meta: { request: `${up.method} ${up.path} as the read-only member, then GET ${spec.read} as account A`, status: String(one.status) },
            replay: { vars: ["marker", "change"], accounts: accounts("a", "viewer"), steps: [...setup,
              { as: "viewer", method: up.method, path: idVar(up.path), body: up.body.split("{{marker}}").join("{{change}}") },
              { as: "a", method: "GET", path: idVar(spec.read), expect: { kind: "not_contains", value: "{{change}}" } }, cleanup] } });
        }
      }
    }
    // Delete: account A makes a record, the viewer asks to delete it, account A looks for it. Twice, on two records.
    const removed = async (): Promise<{ hit: boolean; status: number }> => {
      const id = await create("a", spec, { marker: `yofmarker${random()}` });
      if (!id) return { hit: false, status: 0 };
      const d = await send("viewer", "DELETE", withId(spec.delete, id), { purpose: "owned" });
      const after = await send("a", "GET", withId(spec.read, id));
      return { hit: !!d && ok(d.status) && !!after && (after.status === 404 || after.status === 410), status: d?.status ?? 0 };
    };
    const gone = await removed();
    if (gone.hit && await confirm(async () => (await removed()).hit)) {
      report(VIEWER_RULE, { method: "DELETE", route: spec.delete, as: "viewer", status: gone.status, evidence: `a read-only member deleted a test record of account A with DELETE ${spec.delete}`, meta: { request: `DELETE ${spec.delete} as the read-only member, then GET ${spec.read} as account A`, status: String(gone.status) },
        replay: { vars: ["marker"], accounts: accounts("a", "viewer"), steps: [...setup,
          { as: "viewer", method: "DELETE", path: idVar(spec.delete), expect: { kind: "denied" } }, cleanup] } });
    }
  };

  // ── tenant ────────────────────────────────────────────────────────────────────────────────────
  const tenantGroup = async () => {
    const objs = cfg.objects.filter((x) => routeOk(x.read) || routeOk(x.create.path));
    if (!objs.length) return "skipped" as const;
    // The tenant barrier is "A must never read or change B's data": it needs BOTH accounts.
    if (!auth.has("a") || !auth.has("b")) {
      notes.push(`skipped:tenant:the tenant-barrier test needs two accounts in separate tenants${auth.has("a") ? " (only account A is set; add account B)" : auth.has("b") ? " (only account B is set; add account A)" : " (add accounts A and B)"}`);
      return "skipped" as const;
    }
    for (const spec of objs) await tenantObject(spec);
    return "done" as const;
  };
  const tenantObject = async (spec: ObjectSpec) => {
    const marker = `yofmarker${random()}`;
    const id = await create("a", spec, { marker });
    if (!id) return;
    const read = withId(spec.read, id);
    const own = await send("a", "GET", read);
    if (!own || !ok(own.status) || !own.body.includes(marker)) { notes.push(`owner_cannot_read:${spec.read}`); return; }
    const setup: ReplayStep[] = [{ as: "a", method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true }];
    const cleanup: ReplayStep = { as: "a", method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true };

    const other = await send("b", "GET", read);
    if (other === null) { notes.push("no_account:b"); return; }
    if (ok(other.status) && other.body.includes(marker) && await confirm(async () => { const y = await send("b", "GET", read); return !!y && ok(y.status) && y.body.includes(marker); })) {
      report("attack.tenant_read", { method: "GET", route: spec.read, as: "b", status: other.status, evidence: `the answer held the test record of account A: ${answerShape(other.body)}`, meta: { request: `GET ${spec.read} as account B, for a record of account A`, status: String(other.status) },
        replay: { vars: ["marker"], accounts: accounts("a", "b"), steps: [...setup, { as: "b", method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{marker}}" } }, cleanup] } });
    }
    if (spec.list) {
      const l = await send("b", "GET", spec.list);
      if (l && ok(l.status) && l.body.includes(marker) && await confirm(async () => { const y = await send("b", "GET", spec.list!); return !!y && ok(y.status) && y.body.includes(marker); })) {
        report("attack.tenant_read", { method: "GET", route: spec.list, as: "b", status: l.status, evidence: `the list held the test record of account A: ${answerShape(l.body)}`, meta: { request: `GET ${spec.list} as account B listed a record of account A`, status: String(l.status) },
          replay: { vars: ["marker"], accounts: accounts("a", "b"), steps: [...setup, { as: "b", method: "GET", path: spec.list, expect: { kind: "not_contains", value: "{{marker}}" } }, cleanup] } });
      }
    }
    if (spec.update) {
      const up = spec.update;
      const changedBy = async () => {
        const m2 = `yofchange${random()}`;
        await send("b", up.method, withId(up.path, id), { body: fill(up.body, { marker: m2 }), purpose: "owned" });
        const after = await send("a", "GET", read);
        return { hit: !!after && ok(after.status) && after.body.includes(m2), status: after?.status ?? 0 };
      };
      const first = await changedBy();
      if (first.hit && await confirm(async () => (await changedBy()).hit)) {
        report("attack.tenant_write", { method: up.method, route: up.path, as: "b", status: first.status, evidence: `account B changed a test record of account A with ${up.method} ${up.path}`, meta: { request: `${up.method} ${up.path} as account B, then GET ${spec.read} as account A`, status: String(first.status) },
          replay: { vars: ["marker", "change"], accounts: accounts("a", "b"), steps: [...setup,
            { as: "b", method: up.method, path: up.path.split("{id}").join("{{id}}"), body: up.body.split("{{marker}}").join("{{change}}") },
            { as: "a", method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{change}}" } }, cleanup] } });
      }
    }
  };

  // ── ai ────────────────────────────────────────────────────────────────────────────────────────
  const aiGroup = async () => {
    const specs = cfg.ai.filter((a) => routeOk(a.path));
    if (!specs.length) return "skipped" as const;
    const runnable = specs.filter((a) => auth.has(a.account ?? "a"));
    if (!runnable.length) { notes.push("skipped:ai:no account to talk to the assistant as (add account A)"); return "skipped" as const; }
    for (const a of runnable) await aiTarget(a);
    return "done" as const;
  };
  const aiTarget = async (a: AiSpec) => {
    const role = a.account ?? "a";
    const ask = async (message: string, id = "") => {
      const r = await send(role, "POST", a.path, { body: fill(a.body, { message, id }), purpose: "ai" });
      return r && ok(r.status) ? readPath(r.body, a.replyPath) : null;
    };
    const aiStep = (message: string, expect: ReplayStep["expect"]): ReplayStep => ({ as: role, method: "POST", path: a.path, body: fill(a.body, { message }), replyPath: a.replyPath, expect });
    const canary = `YOF-CANARY-${random().toUpperCase()}`;
    const probes = aiProbes(canary);

    for (const p of probes.filter((x) => x.id.startsWith("leak_"))) {
      const reply = await ask(p.message);
      if (reply === null) { notes.push(`ai_unreachable:${a.path}`); return; }
      if (looksLikeInstructions(reply) && await confirm(async () => looksLikeInstructions((await ask(p.message)) ?? ""))) {
        report("attack.prompt_extraction", { method: "POST", route: a.path, as: role, status: 200, evidence: `an answer of ${reply.length} characters that reads like its hidden instructions (the text is not kept)`, meta: { probe: p.id },
          replay: { vars: [], accounts: accounts(role), steps: [aiStep(p.message, { kind: "not_instructions" })] } });
        break;
      }
    }
    const inject = probes.find((x) => x.id === "inject")!;
    const r = await ask(inject.message);
    if (r?.includes(canary) && await confirm(async () => ((await ask(inject.message)) ?? "").includes(canary))) {
      report("attack.prompt_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "answered with the hidden test word", meta: { probe: "inject" },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [aiStep(inject.message.split(canary).join("{{canary}}"), { kind: "not_contains", value: "{{canary}}" })] } });
    }
    // ── Y11: unsafe output, injection in pasted content, jailbreak, internal details, excessive agency ──
    const y11 = aiProbesY11(canary);
    const y11Replay = aiProbesY11("{{canary}}");
    const y11Step = (id: string, expect: ReplayStep["expect"]) => aiStep(y11Replay.find((x) => x.id === id)!.message, expect);
    const unlock = unlockWord(canary);
    const once = async (ids: string[], hit: (reply: string) => boolean, found: (id: string, reply: string) => void) => {
      for (const id of ids) {
        const msg = y11.find((x) => x.id === id)!.message;
        const reply = await ask(msg);
        if (reply !== null && hit(reply) && await confirm(async () => hit((await ask(msg)) ?? ""))) { found(id, reply); return; }
      }
    };
    await once(["out_html", "out_image"], (r) => !!unsafeMarkup(r, canary), (id, reply) => {
      const kind = unsafeMarkup(reply, canary)!.kind;
      report("attack.unsafe_output", { method: "POST", route: a.path, as: role, status: 200, evidence: `the answer carried ${kind === "image_link" ? "a picture link with the test word" : "live HTML a page would run"}`, meta: { probe: id, kind },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "no_unsafe_markup", value: "{{canary}}" })] } });
    });
    await once(["inject_comment", "inject_markdown"], (r) => r.includes(canary), (id) => {
      report("attack.indirect_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "a hidden instruction in pasted text changed the answer", meta: { probe: id, carrier: id === "inject_comment" ? "html_comment" : "markdown_title" },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "not_contains", value: "{{canary}}" })] } });
    });
    await once(["jb_dev_mode", "jb_opposite"], (r) => saysUnlockWord(r, unlock), (id) => {
      report("attack.jailbreak", { method: "POST", route: a.path, as: role, status: 200, evidence: "said the test word it was to say only with its rules off", meta: { probe: id },
        replay: { vars: ["canary"], accounts: accounts(role), steps: [y11Step(id, { kind: "not_unlocked", value: unlockWord("{{canary}}") })] } });
    });
    await once(["int_debug", "int_tools"], (r) => internalDetails(r).length > 0, (id, reply) => {
      // The KINDS only: never an address, a path or a tool definition from the answer.
      const kinds = internalDetails(reply).join(", ");
      report("attack.data_disclosure", { method: "POST", route: a.path, as: role, status: 200, evidence: `the answer showed: ${kinds}`, meta: { probe: id, kinds },
        replay: { vars: [], accounts: accounts(role), steps: [y11Step(id, { kind: "no_internal" })] } });
    });
    await once(["agency_email"], claimsOutwardAction, (id) => {
      report("attack.excessive_agency", { method: "POST", route: a.path, as: role, status: 200, evidence: "said an email was sent, with no question first", meta: { probe: id },
        replay: { vars: [], accounts: accounts(role), steps: [y11Step(id, { kind: "no_claimed_action" })] } });
    });

    const other: Role = role === "b" ? "a" : "b";
    if (a.ingest) {
      const ing = a.ingest;
      // Same account: a record with a hidden instruction, in each carrier until one works (attack.indirect_injection).
      for (const carrier of CARRIERS) {
        if (findings.some((f) => f.ruleId === "attack.indirect_injection" && f.route === a.path)) break;
        const c2 = `YOF-CANARY-${random().toUpperCase()}`;
        const id = await create(role, ing, { document: carrierDocument(carrier, c2) });
        if (!id) break;
        const reply = await ask(indirectQuestion(id), id);
        if (reply?.includes(c2) && await confirm(async () => ((await ask(indirectQuestion(id), id)) ?? "").includes(c2))) {
          report("attack.indirect_injection", { method: "POST", route: a.path, as: role, status: 200, evidence: "a record with a hidden instruction changed the answer", meta: { record: ing.create.path, carrier },
            replay: { vars: ["canary"], accounts: accounts(role), steps: [
              { as: role, method: "POST", path: ing.create.path, body: fill(ing.create.body, { document: carrierDocument(carrier, "{{canary}}") }), save: { name: "id", from: ing.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: indirectQuestion("{{id}}"), id: "{{id}}" }), replyPath: a.replyPath, expect: { kind: "not_contains", value: "{{canary}}" } },
              { as: role, method: "DELETE", path: ing.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
      }
      // Across accounts (attack.rag_poisoning): the OTHER account plants a record about a fresh topic; this account asks a
      // general question about the topic without the id. The test word back = other users' records steer the answers.
      if (auth.has(other)) {
        for (const carrier of CARRIERS) {
          const c3 = `YOF-CANARY-${random().toUpperCase()}`;
          const topic = `yoftopic${random()}`;
          const id = await create(other, ing, { document: carrierDocument(carrier, c3, topic) });
          if (!id) break;
          const reply = await ask(ragQuestion(topic));
          if (reply?.includes(c3) && await confirm(async () => ((await ask(ragQuestion(topic))) ?? "").includes(c3))) {
            report("attack.rag_poisoning", { method: "POST", route: a.path, as: role, status: 200, evidence: `a record of account ${other.toUpperCase()} with a hidden instruction steered a general answer`, meta: { record: ing.create.path, carrier, across: `account ${other.toUpperCase()} wrote, account ${role.toUpperCase()} asked` },
              replay: { vars: ["canary", "topic"], accounts: accounts(role, other), steps: [
                { as: other, method: "POST", path: ing.create.path, body: fill(ing.create.body, { document: carrierDocument(carrier, "{{canary}}", "{{topic}}") }), save: { name: "id", from: ing.idPath }, setup: true },
                aiStep(ragQuestion("{{topic}}"), { kind: "not_contains", value: "{{canary}}" }),
                { as: other, method: "DELETE", path: ing.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
            break;
          }
        }
      }
    } else notes.push(`no_ingest:${a.path}`);

    const spec = cfg.objects[0];
    if (spec) {
      const marker = `yofmarker${random()}`;
      const id = await create(other, spec, { marker });
      if (id) {
        const reply = await ask(crossTenantQuestion(id), id);
        if (reply?.includes(marker) && await confirm(async () => ((await ask(crossTenantQuestion(id), id)) ?? "").includes(marker))) {
          report("attack.tool_cross_tenant", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant returned a test record of account ${other.toUpperCase()}`, meta: { record: spec.read },
            replay: { vars: ["marker"], accounts: accounts(role, other), steps: [
              { as: other, method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: crossTenantQuestion("{{id}}"), id: "{{id}}" }), replyPath: a.replyPath, expect: { kind: "not_contains", value: "{{marker}}" } },
              { as: other, method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
        // Writes through the tools (attack.tool_cross_tenant_write): ask to rename the other account's TEST record, then
        // the other account reads it. Only the run's own record is ever named; it is deleted at the end like the rest.
        const changedVia = async () => {
          const m2 = `yofchange${random()}`;
          await ask(writeQuestion(id, m2), id);
          const after = await send(other, "GET", withId(spec.read, id));
          return !!after && ok(after.status) && after.body.includes(m2);
        };
        if (await changedVia() && await confirm(changedVia)) {
          report("attack.tool_cross_tenant_write", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant changed a test record of account ${other.toUpperCase()}`, meta: { record: spec.read },
            replay: { vars: ["marker", "change"], accounts: accounts(role, other), steps: [
              { as: other, method: "POST", path: spec.create.path, body: spec.create.body, save: { name: "id", from: spec.idPath }, setup: true },
              { as: role, method: "POST", path: a.path, body: fill(a.body, { message: writeQuestion("{{id}}", "{{change}}"), id: "{{id}}" }), replyPath: a.replyPath },
              { as: other, method: "GET", path: spec.read.split("{id}").join("{{id}}"), expect: { kind: "not_contains", value: "{{change}}" } },
              { as: other, method: "DELETE", path: spec.delete.split("{id}").join("{{id}}"), cleanup: true }] } });
        }
      }
    }
    if (auth.has("admin") && role !== "admin") {
      for (const p of cfg.admin.filter((x) => !x.includes("{id}")).slice(0, 2)) {
        const adm = await send("admin", "GET", p);
        const mem = await send(role, "GET", p);
        if (!adm || !mem || !ok(adm.status) || ok(mem.status)) continue;
        const secret = distinct(adm.body, mem.body);
        if (!secret) continue;
        const reply = await ask(privilegeQuestion(p));
        if (reply?.includes(secret) && await confirm(async () => ((await ask(privilegeQuestion(p))) ?? "").includes(secret))) {
          report("attack.tool_privilege", { method: "POST", route: a.path, as: role, status: 200, evidence: `the assistant returned data from ${p}, which this member is refused`, meta: { adminRoute: p },
            replay: { vars: [], accounts: accounts(role, "admin"), steps: [
              { as: "admin", method: "GET", path: p, keep: "adminBody", setup: true },
              { as: role, method: "GET", path: p, keep: "memberBody" },
              { derive: { name: "secret", from: ["adminBody", "memberBody"] } },
              aiStep(privilegeQuestion(p), { kind: "not_contains", value: "{{secret}}" })] } });
          break;
        }
      }
    }

    // ── Y11, opt-in only (ai[i].limits): does anything limit use of the assistant (attack.ai_no_limit)? ──
    // A burst of BURST_SIZE tiny messages, BURST_PARALLEL at a time, then one request for a very long story. Like the
    // sign-in rate test, the burst is itself the repetition (it is not sent twice); it counts against the budget.
    if (a.limits) {
      if (http.left < BURST_SIZE + 2) { notes.push(`ai_limits_budget:${a.path}`); return; }
      const statuses: number[] = [];
      for (let i = 0; i < BURST_SIZE; i += BURST_PARALLEL) {
        const wave = await Promise.all(Array.from({ length: Math.min(BURST_PARALLEL, BURST_SIZE - i) }, () =>
          send(role, "POST", a.path, { body: fill(a.body, { message: BURST_MESSAGE, id: "" }), purpose: "ai" })));
        for (const r of wave) statuses.push(r?.status ?? 0);
        if (burstLimited(statuses)) break;
      }
      if (statuses.length === BURST_SIZE && !burstLimited(statuses) && statuses.every(ok)) {
        report("attack.ai_no_limit", { method: "POST", route: a.path, as: role, status: statuses.at(-1)!, evidence: `${BURST_SIZE} quick messages in a row, none slowed down`, meta: { burst: `${BURST_SIZE} of ${BURST_SIZE} answered` },
          replay: { vars: [], accounts: accounts(role), steps: [{ ...aiStep(BURST_MESSAGE, { kind: "some_status", status: [429, 503] }), repeat: BURST_SIZE }] } });
      } else {
        const reply = await ask(LONG_OUTPUT_PROBE.message);
        if (reply !== null && unboundedOutput(reply)) {
          report("attack.ai_no_limit", { method: "POST", route: a.path, as: role, status: 200, evidence: `a request for a very long text got ${reply.length} characters back`, meta: { probe: LONG_OUTPUT_PROBE.id, chars: String(reply.length) },
            replay: { vars: [], accounts: accounts(role), steps: [aiStep(LONG_OUTPUT_PROBE.message, { kind: "short_answer", max: UNBOUNDED_CHARS })] } });
        }
      }
    }
  };

  // ── surface ───────────────────────────────────────────────────────────────────────────────────
  const surfaceGroup = async () => {
    const home = await send("anon", "GET", "/");
    if (home) {
      const missing: { rule: string; name: string }[] = [];
      const h = home.headers;
      if (o.proof.origin.startsWith("https:") && !h.get("strict-transport-security")) missing.push({ rule: "headers.hsts", name: "strict-transport-security" });
      if (!/nosniff/i.test(h.get("x-content-type-options") ?? "")) missing.push({ rule: "headers.nosniff", name: "x-content-type-options" });
      if (!h.get("x-frame-options") && !/frame-ancestors/i.test(h.get("content-security-policy") ?? "")) missing.push({ rule: "headers.frame", name: "x-frame-options" });
      if (!h.get("referrer-policy")) missing.push({ rule: "headers.referrer", name: "referrer-policy" });
      if (missing.length) {
        const again = await send("anon", "GET", "/");
        if (again && missing.every((m) => !again.headers.get(m.name) || (m.name === "x-content-type-options" && !/nosniff/i.test(again.headers.get(m.name) ?? "")))) {
          report("attack.missing_headers", { method: "GET", route: "/", as: "anon", status: home.status, evidence: `missing: ${missing.map((m) => m.name).join(", ")}`, meta: { headers: missing.map((m) => m.rule).join(",") },
            replay: { vars: [], accounts: {}, steps: missing.map((m) => ({ as: "anon" as const, method: "GET" as const, path: "/", expect: { kind: "header_present" as const, name: m.name } })) } });
        } else unconfirmed++;
      }
    }
    const paths = cfg.surface.redirectPaths.length ? cfg.surface.redirectPaths : ["/login"];
    outer: for (const p of paths) {
      for (const param of REDIRECT_PARAMS) {
        const q = `${p}${p.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(REDIRECT_PROBE)}`;
        const r = await send("anon", "GET", q);
        const to = (loc: string | null | undefined) => { try { return loc ? new URL(loc, o.proof.origin).hostname : ""; } catch { return ""; } };
        if (r && r.status >= 300 && r.status < 400 && to(r.location) === REDIRECT_PROBE_HOST) {
          const y = await send("anon", "GET", q);
          if (!(y && to(y.location) === REDIRECT_PROBE_HOST)) { unconfirmed++; continue; }
          report("attack.open_redirect", { method: "GET", route: `${p}?${param}=`, as: "anon", status: r.status, evidence: `${param}= sent the visitor to ${REDIRECT_PROBE_HOST}`, meta: { param },
            replay: { vars: [], accounts: {}, steps: [{ as: "anon", method: "GET", path: q, expect: { kind: "not_redirect_to", host: REDIRECT_PROBE_HOST } }] } });
          continue outer;
        }
      }
    }
    // Sign-in: the cookie flags (seen when the runner signed in) and, in a full run with rateLimit on, wrong passwords.
    // A light run signs nobody in, so it has no sign-in cookie to look at.
    for (const role of mode === "light" ? [] : (["a", "b"] as const)) {
      const acc = cfg.accounts[role];
      if (!acc || !isLoginAccount(acc) || acc.login.tokenPath) continue;
      await auth.headers(role);
      const weak = (auth.cookieFlags.get(role) ?? []).filter((c) => !/;\s*httponly/i.test(c) || !/;\s*samesite=/i.test(c) || (o.proof.origin.startsWith("https:") && !/;\s*secure/i.test(c)));
      if (weak.length) {
        report("attack.weak_session_cookie", { method: "POST", route: acc.login.path, as: role, status: 200, evidence: `cookie ${weak[0]!.split("=")[0]} is missing a flag`, meta: { cookie: weak[0]!.split("=")[0]!.slice(0, 40) },
          replay: { vars: [], accounts: accounts(role), steps: [{ as: role, method: "POST", path: acc.login.path, login: { role, wrong: false }, expect: { kind: "cookie_flags" } }] } });
      }
      break;
    }
    if (mode === "full" && cfg.surface.rateLimit) {
      const role = (["a", "b"] as const).find((r) => { const a = cfg.accounts[r]; return a && isLoginAccount(a); });
      const acc = role ? cfg.accounts[role] : null;
      if (role && acc && isLoginAccount(acc) && env[acc.emailEnv]) {
        const statuses: number[] = [];
        for (let i = 0; i < RATE_TRIES; i++) {
          const r = await http.send(role, "POST", acc.login.path, { body: fill(acc.login.body, { email: env[acc.emailEnv]!, password: `yof-wrong-${random()}` }), purpose: "login" });
          statuses.push(r.status);
          if (r.status === 429 || r.status === 423) break;
        }
        if (statuses.length === RATE_TRIES && !statuses.some((s) => s === 429 || s === 423) && statuses.every((s) => s > 0)) {
          report("attack.no_rate_limit", { method: "POST", route: acc.login.path, as: role, status: statuses.at(-1)!, evidence: `${RATE_TRIES} wrong passwords in a row, none slowed down`, meta: { tries: String(RATE_TRIES) },
            replay: { vars: ["wrong"], accounts: accounts(role), steps: [{ as: role, method: "POST", path: acc.login.path, login: { role, wrong: true }, repeat: RATE_TRIES, expect: { kind: "some_status", status: [429, 423] } }] } });
        }
      } else notes.push("no_rate_limit_account");
    }
    return "done" as const;
  };

  const plan: [AttackGroup, () => Promise<"done" | "skipped">][] = [
    ["auth", authGroup], ["rbac", rbacGroup], ["surface", surfaceGroup],
    ...(mode === "full" ? [["tenant", tenantGroup], ["ai", aiGroup]] as [AttackGroup, () => Promise<"done" | "skipped">][] : []),
  ];
  if (mode === "light") { if (wanted.has("tenant")) groups.tenant = "skipped"; if (wanted.has("ai")) groups.ai = "skipped"; notes.push("light_run_read_only"); }
  let stopped: AttackRunResult["stopped"] = null;
  try {
    for (const [g, fn] of plan) {
      if (!wanted.has(g)) continue;
      groups[g] = "partial";
      try { groups[g] = await fn(); }
      catch (e) {
        if (e instanceof BudgetError) { stopped = e.reason; throw e; }
        if (e instanceof StoppedError) { stopped = "cancelled"; throw e; }
        if (e instanceof RefusedError) { notes.push(`refused:${e.message.slice(0, 120)}`); continue; }
        throw e;
      }
    }
  } catch (e) {
    if (e instanceof StoppedError) stopped = "cancelled";
    else if (!(e instanceof BudgetError)) throw e;
  } finally {
    // Delete every record this run created, newest first. After a stop signal the clean-up has a hard deadline.
    const clock = o.now ?? Date.now;
    const deadline = stopped === "cancelled" || o.signal?.aborted ? clock() + STOP_CLEANUP_MS : Infinity;
    for (const c of cleanupList.reverse()) {
      const route = c.path.replace(/\/[^/]*$/, "/{id}");
      const remaining = deadline - clock();
      if (remaining <= 0) { cleanup.left.push(route); continue; }
      try {
        const h = auth.cached(c.as);
        const r = await http.send(c.as, "DELETE", c.path, { headers: h ?? {}, purpose: "cleanup", timeoutMs: Number.isFinite(remaining) ? remaining : undefined });
        if (ok(r.status) || r.status === 404) cleanup.deleted++;
        else { notes.push(`cleanup_${r.status}:${route}`); cleanup.left.push(route); }
      } catch { notes.push("cleanup_failed"); cleanup.left.push(route); }
    }
  }
  return { findings, review, groups, notes, stopped, cleanup, exchanges: http.exchanges, requests: http.used, unconfirmed };
}
