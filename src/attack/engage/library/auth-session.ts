/**
 * yof engagement, attack library: SIGN-IN AND SESSIONS.
 *
 *   session.sign_out         after the test account signs out, its old session is sent again: it must be refused
 *   session.reset_reuse      the reset link of yof's OWN test account is redeemed again: it must work once
 *   session.jwt_none         the account's own token, re-labelled "unsigned" with its signature removed
 *   session.jwt_signature    the account's own token with its signature replaced
 *   session.cookie_flags     HttpOnly, Secure and SameSite on the sign-in cookie (an observation; nothing is sent)
 *   session.password_limit   a small fixed number of wrong passwords (8) on yof's OWN test account, then the right
 *                            one, to see whether a limit exists
 *
 * NEVER: a wrong password, a reset or a sign-out on an account that is not a test account of this run (the session
 * says which are; a technique asks, and refuses without a yes). Never more wrong passwords than the fixed number, and
 * only where the record allows bursts. A password and a reset link never pass through the library: the session sends
 * those requests itself, so they are in no evidence.
 *
 * The oracles are fixed status rules with controls: the route answers the signed-in account, refuses nobody-signed-in
 * and refuses a made-up token, before an altered token or an old session is tried. Each shown twice.
 */
import type { As, HttpAnswer } from "../../http";
import type { ReplaySpec } from "../../replay";
import { sharesValues } from "../differential";
import { notTestable, ok, plant, replayPath, result, sendRequest, specOf, stepOf, unusable, fillRequest } from "./kit";
import { WRONG_PASSWORD_TRIES, payload } from "./payloads";
import type { ImpactFacts, SessionAccess, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";
import { EVIDENCE } from "./words";

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const unb64 = (s: string): string => Buffer.from(s, "base64url").toString("utf8");
const JWT = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/;

export interface FoundToken { header: string; before: string; token: string; after: string; alg: string }
/** The signed token (three parts, a header that names an algorithm) among a role's sign-in headers, or null. Pure. */
export function findToken(headers: Record<string, string>): FoundToken | null {
  for (const [header, value] of Object.entries(headers)) {
    const m = JWT.exec(value);
    if (!m) continue;
    try {
      const h = JSON.parse(unb64(m[0].split(".")[0]!)) as { alg?: unknown };
      if (typeof h.alg !== "string") continue;
      return { header, before: value.slice(0, m.index), token: m[0], after: value.slice(m.index + m[0].length), alg: h.alg };
    } catch { continue; }
  }
  return null;
}
/** The token re-labelled as unsigned (`alg` as given), its signature removed. Pure. */
export function unsignedToken(token: string, alg: string): string {
  const [h, p] = token.split(".");
  const head = JSON.parse(unb64(h!)) as Record<string, unknown>;
  return `${b64(JSON.stringify({ ...head, alg }))}.${p}.`;
}
/** The token with its signature replaced by a fixed text (changed again if the fixed text happens to be the signature). Pure. */
export function resignedToken(token: string, signature: string): string {
  const [h, p, s] = token.split(".");
  return `${h}.${p}.${s === signature ? `${signature.slice(1)}y` : signature}`;
}
/** Which of the three flags a sign-in cookie lacks. `https`: Secure is expected. Pure. */
export function missingCookieFlags(setCookies: readonly string[], https: boolean): string[] {
  const lines = setCookies.filter((c) => c.includes("="));
  const lacks = (re: RegExp) => lines.some((c) => !re.test(c));
  return [...(lacks(/;\s*httponly\b/i) ? ["HttpOnly"] : []), ...(https && lacks(/;\s*secure\b/i) ? ["Secure"] : []), ...(lacks(/;\s*samesite\s*=/i) ? ["SameSite"] : [])];
}
/** Did the sign-in slow down or lock within the wrong tries? A 429, 423 or 503, or a status that changes after the first tries. Pure. */
export function limitSeen(statuses: readonly number[]): boolean {
  if (statuses.some((s) => s === 429 || s === 423 || s === 503)) return true;
  return statuses.length >= 2 && statuses.slice(1).some((s) => s !== statuses[0]);
}

const SESSION_IMPACT: ImpactFacts = { what: "rule_broken", position: "same_tenant_member", reach: "one_object", data: "ordinary" };
const FORGE_IMPACT: ImpactFacts = { what: "privilege_gain", position: "anonymous", reach: "all_tenants", data: "ordinary" };
type Head = Omit<Technique, "run" | "chain">;
const NO_SESSION = "this run cannot tell how the test account is signed in";
const LOCAL = /^(?:localhost|127\.0\.0\.1|\[::1\])$/;

const SIGN_OUT: Head = {
  id: "session.sign_out", ruleId: "attack.session_not_ended", title: "A session still works after sign-out",
  invariants: ["session"], prerequisites: ["account_a", "own_test_account", "signed_in_route", "sign_out_route"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: [],
  oracle: "The route answers the signed-in test account and refuses nobody-signed-in; the account signs out; its old session, sent again, is still answered with the account's data, twice.",
  shows: "that signing out does not end the session on the server", cannotShow: "how long the old session keeps working",
  best: "confirmed", impact: SESSION_IMPACT, owasp: "A07 / API2",
};
const RESET: Head = {
  id: "session.reset_reuse", ruleId: "attack.single_use_reuse", title: "A single-use link or code works more than once",
  invariants: ["single_use", "session"], prerequisites: ["own_test_account", "reset_flow"], safetyClass: "write_own_test_records", classes: ["write_own_test_records"], payloads: ["use.twice"],
  oracle: "The reset link of the run's own test account is redeemed once, and then works a second and a third time.",
  shows: "that a used reset link is not thrown away", cannotShow: "whether the link also expires with time",
  best: "confirmed", impact: SESSION_IMPACT, owasp: "A07 / API2",
  chainLimit: "The reset link arrives in a message only the session can read, so a replay cannot fetch one. Its steps use a made-up link and only show the shape of the test.",
};
const JWT_NONE: Head = {
  id: "session.jwt_none", ruleId: "attack.token_unverified", title: "The app accepts a sign-in token whose signature it never checked",
  invariants: ["session", "auth_required"], prerequisites: ["account_a", "token_session", "signed_in_route"], safetyClass: "read", classes: ["read"], payloads: ["jwt.alg_none", "jwt.alg_None", "jwt.alg_NONE"],
  oracle: "The route answers the test account's own token, refuses no token and refuses a made-up token; the account's token re-labelled as unsigned, with its signature removed, is answered with the account's data, twice.",
  shows: "that the server reads a token without checking who signed it, so anyone can write one", cannotShow: "another person's data: only the test account's own token is altered",
  best: "confirmed", impact: FORGE_IMPACT, owasp: "A02 / API2",
  chainLimit: "A replay cannot alter a token (it never holds one). Its steps check that a broken token is refused.",
};
const JWT_SIGNATURE: Head = {
  ...JWT_NONE, id: "session.jwt_signature", payloads: ["jwt.bad_signature"],
  oracle: "The same controls; then the account's token with its signature replaced by a fixed text is answered with the account's data, twice.",
};
const COOKIE_FLAGS: Head = {
  id: "session.cookie_flags", ruleId: "attack.weak_session_cookie", title: "The sign-in cookie is missing a safety flag",
  invariants: ["session"], prerequisites: ["account_a", "cookie_session"], safetyClass: "read", classes: ["read"], payloads: ["observe.own_values"],
  oracle: "A cookie set at sign-in lacks HttpOnly, SameSite, or (on https) Secure.",
  shows: "that a layer of protection is missing", cannotShow: "that the cookie can be stolen or sent from another site: nothing is tried",
  best: "needs_validation", impact: { ...SESSION_IMPACT, what: "none" }, owasp: "A05",
};
const PASSWORD_LIMIT: Head = {
  id: "session.password_limit", ruleId: "attack.no_rate_limit", title: "Your sign-in accepts unlimited wrong passwords",
  invariants: ["session"], prerequisites: ["own_test_account"], safetyClass: "burst", classes: ["burst", "write_own_test_records"], payloads: ["password.wrong"],
  oracle: `${WRONG_PASSWORD_TRIES} wrong passwords in a row on the run's own test account are all answered the same way (no 429, no lock), and the right password still works afterwards.`,
  shows: "that no limit was seen within the fixed number of tries", cannotShow: "that no limit exists: one may start after more tries than this test sends",
  best: "needs_validation", impact: { ...SESSION_IMPACT, what: "none" }, owasp: "A07 / API2",
};

const session = (ctx: TechniqueContext): SessionAccess | null => ctx.session ?? null;

async function runForged(t: Head, ctx: TechniqueContext, target: TechniqueTarget, forge: (tok: FoundToken, id: string) => string): Promise<TechniqueResult> {
  const s = session(ctx);
  if (!s) return notTestable(t, NO_SESSION);
  const cred = await s.credential("a");
  if (!cred) return notTestable(t, "the test account is not set, or its sign-in failed");
  const tok = findToken(cred);
  if (!tok) return notTestable(t, "the test account's session is not a signed token (three parts with a named algorithm)");
  if (/^none$/i.test(tok.alg)) return notTestable(t, "the test account's own token is already unsigned");
  // With a test record, the proof is the account's own planted marker; without one, the account's own answer.
  let path = target.session?.route ?? "", marker: string | null = null, route = path;
  if (target.object) {
    const planted = await plant(ctx, "a", target.object);
    if (planted.ok) { marker = planted.record.marker; route = target.object.read; path = target.object.read.split("{id}").join(encodeURIComponent(planted.record.id)); }
  }
  if (!path) return notTestable(t, "the app model names no route that needs a sign-in");
  const others = Object.fromEntries(Object.entries(cred).filter(([k]) => k !== tok.header));
  const withToken = (token: string | null) => ctx.io.send("anon", "GET", path, { headers: { ...others, ...(token === null ? {} : { [tok.header]: `${tok.before}${token}${tok.after}` }) }, purpose: "read", cls: "read", leg: token === tok.token ? "positive" : "test" });
  const own = await withToken(tok.token);
  if (!own || !ok(own.status) || (marker !== null && !own.body.includes(marker))) return notTestable(t, "the route did not answer the test account's own token, so the test would show nothing");
  const none = await withToken(null);
  if (unusable(none)) return notTestable(t, "a request with no token got no usable answer");
  if (ok(none!.status)) return notTestable(t, "the route answers with no token at all, so it shows nothing about tokens (see the sign-in test)");
  const junk = await withToken("yofyofyof.yofyofyof.yofyofyof");
  if (unusable(junk) || ok(junk!.status)) return notTestable(t, "the route answers a made-up token too, so it shows nothing about signatures");
  const same = (r: HttpAnswer | null) => !!r && ok(r.status) && (marker !== null ? r.body.includes(marker) : r.body.trim() === own.body.trim() || sharesValues(own.body, r.body));
  for (const id of t.payloads) {
    const forged = forge(tok, id);
    const r = await withToken(forged);
    if (!same(r)) continue;
    const twice = same(await withToken(forged));
    return result(t, twice ? "violated" : "needs_validation", {
      reason: twice ? "the altered token was answered with the account's own data twice, after no token and a made-up token were refused" : "it showed once and not a second time",
      route, as: "anon", status: r!.status, marker, payload: id, evidence: id === "jwt.bad_signature" ? EVIDENCE.tokenBadSignature() : EVIDENCE.tokenUnsigned(),
      meta: { payload: id, proof: marker ? "marker" : "the account's own answer", controls: "no token refused; made-up token refused" }, replay: tokenChain(t, route, ctx.accounts),
    });
  }
  return result(t, "held", { reason: "the altered token was refused", route, as: "anon", status: none!.status });
}
const tokenChain = (t: Pick<Technique, "ruleId" | "title">, route: string, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, [], accounts, [
    { as: "anon", method: "GET", path: replayPath(route).split("{{id}}").join("1"), expect: { kind: "denied" } },
    { as: "anon", method: "GET", path: replayPath(route).split("{{id}}").join("1"), headers: { Authorization: "Bearer undefined" }, expect: { kind: "denied" } },
  ]);

export const AUTH_SESSION_TECHNIQUES: readonly Technique[] = [
  {
    ...SIGN_OUT,
    chain: (target, accounts) => (target.session?.signOut ? specOf(SIGN_OUT, [], accounts, [
      { as: "a", method: "GET", path: target.session.route, setup: true },
      stepOf("a", target.session.signOut),
      { as: "a", method: "GET", path: target.session.route, expect: { kind: "denied" } },
    ]) : null),
    run: async (ctx, target) => {
      const t = SIGN_OUT, s = session(ctx), spec = target.session;
      if (!s) return notTestable(t, NO_SESSION);
      if (!spec?.signOut) return notTestable(t, "the app model names no sign-out request");
      if (!s.testAccount("a")) return notTestable(t, "account a is not marked as a test account of this run, so it is not signed out");
      const cred = await s.credential("a");
      if (!cred) return notTestable(t, "the test account is not set, or its sign-in failed");
      const route = spec.route, as: As = "a";
      const old = () => ctx.io.send("anon", "GET", route, { headers: cred, purpose: "read", cls: "read", leg: "test" });
      const own = await old();
      if (!own || !ok(own.status)) return notTestable(t, "the route did not answer the signed-in test account");
      const none = await ctx.io.send("anon", "GET", route, { purpose: "read", cls: "read", leg: "negative" });
      if (unusable(none) || ok(none!.status)) return notTestable(t, "the route answers with no sign-in too, so it shows nothing about sessions");
      try {
        const out = await sendRequest(ctx, "a", fillRequest(spec.signOut, {}), { cls: "write_own_test_records", purpose: "login" });
        if (!out || unusable(out) || out.status >= 400) return notTestable(t, "the sign-out request did not work");
        const same = (r: HttpAnswer | null) => !!r && ok(r.status) && (r.body.trim() === own.body.trim() || sharesValues(own.body, r.body));
        const after = await old();
        if (!same(after)) return result(t, "held", { reason: "the old session was refused after sign-out", route, as, status: after?.status ?? 0 });
        const twice = same(await old());
        return result(t, twice ? "violated" : "needs_validation", {
          reason: twice ? "the old session was answered with the account's data twice after sign-out; nobody-signed-in was refused" : "it showed once and not a second time",
          route, as, status: after!.status, evidence: EVIDENCE.sessionAlive(), meta: { controls: "no sign-in refused", request: `${spec.signOut.method} ${spec.signOut.path.split("?")[0]}` },
          replay: AUTH_SESSION_TECHNIQUES[0]!.chain(target, ctx.accounts),
        });
      } finally { await s.fresh(); }
    },
  },
  {
    ...RESET,
    chain: (target, accounts) => (target.session?.reset ? specOf(RESET, ["token", "password"], accounts, [stepOf("anon", target.session.reset, { repeat: 2, expect: { kind: "count_at_most", max: 1 } })]) : null),
    run: async (ctx, target) => {
      const t = RESET, s = session(ctx);
      if (!s?.redeemReset) return notTestable(t, "this run has no way to read a reset link of the test account yet");
      if (!s.testAccount("a")) return notTestable(t, "account a is not marked as a test account of this run, so its password is not reset");
      const route = target.session?.reset?.path.split("?")[0] ?? "/", method = target.session?.reset?.method ?? "POST";
      try {
        const first = await s.redeemReset("a");
        if (!first || !ok(first.status)) return notTestable(t, "the reset link did not work the first time, so the test would show nothing");
        const second = await s.redeemReset("a");
        if (!second || unusable(second)) return notTestable(t, "the second try got no usable answer");
        if (!ok(second.status)) return result(t, "held", { reason: "the used reset link was refused", method, route, as: "anon", status: second.status });
        const third = await s.redeemReset("a");
        const twice = !!third && ok(third.status);
        return result(t, twice ? "violated" : "needs_validation", {
          reason: twice ? "the same reset link worked three times" : "the link worked a second time, and not a third", method, route, as: "anon", status: second.status, payload: "use.twice",
          evidence: EVIDENCE.resetReused(twice ? 3 : 2), meta: { count: twice ? "3" : "2", bound: "1" }, replay: AUTH_SESSION_TECHNIQUES[1]!.chain(target, ctx.accounts),
        });
      } finally { await s.fresh(); }
    },
  },
  {
    ...JWT_NONE,
    chain: (target, accounts) => (target.session ? tokenChain(JWT_NONE, target.session.route, accounts) : null),
    run: (ctx, target) => runForged(JWT_NONE, ctx, target, (tok, id) => unsignedToken(tok.token, payload(id).value)),
  },
  {
    ...JWT_SIGNATURE,
    chain: (target, accounts) => (target.session ? tokenChain(JWT_SIGNATURE, target.session.route, accounts) : null),
    run: (ctx, target) => runForged(JWT_SIGNATURE, ctx, target, (tok, id) => resignedToken(tok.token, payload(id).value)),
  },
  {
    ...COOKIE_FLAGS,
    chain: (target, accounts) => specOf(COOKIE_FLAGS, [], accounts, [{ as: "a", method: "POST", path: target.session?.route ?? "/", login: { role: "a", wrong: false }, expect: { kind: "cookie_flags" } }]),
    run: async (ctx, target) => {
      const t = COOKIE_FLAGS, s = session(ctx);
      if (!s) return notTestable(t, NO_SESSION);
      if (!(await s.credential("a"))) return notTestable(t, "the test account is not set, or its sign-in failed");
      const lines = s.cookieFlags("a");
      if (!lines.length) return notTestable(t, "no cookie was set at sign-in in this run (the account signs in with a header)");
      const missing = missingCookieFlags(lines, !LOCAL.test(ctx.host));
      if (!missing.length) return result(t, "held", { reason: "the sign-in cookie carries HttpOnly, Secure and SameSite", as: "a" });
      return result(t, "needs_validation", {
        reason: "an observation: a layer of protection is missing. Nothing was tried with it", method: "POST", route: target.session?.route ?? "/", as: "a", status: 200,
        evidence: EVIDENCE.cookieFlags(missing.join(", ")), meta: { cookie: `missing ${missing.join(", ")}`, kind: "observation" }, replay: AUTH_SESSION_TECHNIQUES[4]!.chain(target, ctx.accounts),
      });
    },
  },
  {
    ...PASSWORD_LIMIT,
    chain: (_target, accounts) => specOf(PASSWORD_LIMIT, ["wrong"], accounts, [{ as: "anon", method: "POST", path: "/", login: { role: "a", wrong: true }, repeat: WRONG_PASSWORD_TRIES, expect: { kind: "some_status", status: [429, 423] } }]),
    run: async (ctx, target) => {
      const t = PASSWORD_LIMIT, s = session(ctx);
      if (!s?.login) return notTestable(t, "this run has no sign-in request for the test account (it signs in with a header)");
      if (!s.testAccount("a")) return notTestable(t, "account a is not marked as a test account of this run, so no wrong password is sent for it");
      const route = target.session?.route ?? "/";
      const statuses: number[] = [];
      try {
        for (let i = 0; i < WRONG_PASSWORD_TRIES; i++) {
          const r = await s.login("a", true);
          if (!r) return notTestable(t, "the sign-in request could not be sent");
          statuses.push(r.status);
          if (limitSeen(statuses)) return result(t, "held", { reason: `the sign-in slowed down or locked after ${statuses.length} wrong passwords`, method: "POST", route, as: "anon", status: r.status });
        }
        const right = await s.login("a", false);
        if (!right || !ok(right.status)) return result(t, "held", { reason: "the right password was refused after the wrong ones: the account was slowed down or locked, which is a limit", method: "POST", route, as: "anon", status: right?.status ?? 0 });
        return result(t, "needs_validation", {
          reason: "no limit was seen within the fixed number of tries; one may start later, which this test does not look for", method: "POST", route, as: "anon", status: statuses[0] ?? 0, payload: "password.wrong",
          evidence: EVIDENCE.noPasswordLimit(WRONG_PASSWORD_TRIES), meta: { tries: String(WRONG_PASSWORD_TRIES), kind: "observation" }, replay: AUTH_SESSION_TECHNIQUES[5]!.chain(target, ctx.accounts),
        });
      } finally { await s.fresh(); }
    },
  },
];
