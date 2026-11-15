/**
 * yof engagement, attack library: REQUEST FORGERY (CSRF). A page on another site makes a signed-in person's browser
 * send a request that changes something. It works when the app's session is a cookie the browser sends by itself and
 * nothing else tells the app the request came from its own pages.
 *
 *   csrf.state_change   on the run's OWN test record: the change is sent the way another site could send it, with no
 *                       anti-forgery token and with the Origin and Referer of another site. Oracle: the owner reads
 *                       the record again and the change is there.
 *   csrf.observe        read only, for a production host: looks at the session cookie's flags and at whether a token
 *                       exists. It changes nothing and is worded as an observation, never as a finding.
 *
 * WHEN IT IS A FINDING. All of these, shown twice, after the ordinary request was shown to work:
 *   the forged request changed the record;
 *   the session cookie is set without SameSite, or with SameSite=None;
 *   a browser can send that request from another site with no permission from the app: a GET or a POST whose body
 *   goes as a form or as plain text. A PATCH, PUT or DELETE, or a body the app accepts only as JSON, needs the app's
 *   own cross-origin settings to allow it, which this test does not read: that case needs validation.
 * A test account that signs in with a header (a bearer token) is not affected: a browser never sends that by itself.
 */
import type { As } from "../../http";
import type { ReplaySpec } from "../../replay";
import { deleteStep, fillRequest, notTestable, ok, plant, plantStep, readId, replayPath, result, routeOf, sendRequest, specOf, stepOf, unusable, withChanged } from "./kit";
import { FOREIGN_ORIGIN } from "./payloads";
import type { ImpactFacts, StateChange, Technique, TechniqueContext, TechniqueResult, TestObject } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "write", position: "anonymous", reach: "one_object", data: "ordinary" };
const FORGED = { Origin: FOREIGN_ORIGIN, Referer: `${FOREIGN_ORIGIN}/` };

export type SameSite = "none" | "lax_or_strict" | "unknown";
/** What the sign-in cookies say about cross-site sending. One cookie without SameSite, or with SameSite=None, is "none". Pure. */
export function sameSiteOf(setCookies: readonly string[]): SameSite {
  const lines = setCookies.filter((c) => c.includes("="));
  if (!lines.length) return "unknown";
  return lines.some((c) => !/;\s*samesite\s*=\s*(?:lax|strict)\b/i.test(c)) ? "none" : "lax_or_strict";
}
/** Can a browser send this from another site with no permission from the app? Pure. */
export const browserCanSend = (method: string, hasBody: boolean, acceptedAsPlainText: boolean): boolean =>
  method === "GET" || (method === "POST" && (!hasBody || acceptedAsPlainText));
const isCookieSession = (h: Record<string, string> | null): boolean => !!h && Object.keys(h).some((k) => k.toLowerCase() === "cookie");

type Head = Omit<Technique, "run" | "chain">;
const STATE_CHANGE: Head = {
  id: "csrf.state_change", ruleId: "attack.csrf", title: "Another website can make a signed-in user's browser change their data",
  invariants: ["session"], prerequisites: ["account_a", "test_object", "state_change", "cookie_session"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"],
  payloads: ["csrf.no_token", "csrf.foreign_origin"],
  oracle: "The ordinary change of the run's own test record works; the same change with no anti-forgery token and another site's Origin and Referer is then read back by the owner, twice; the session cookie has no SameSite protection; and a browser can send that request from another site.",
  shows: "that the app accepts a change it cannot tell from one another site made the browser send", cannotShow: "a real browser doing it: the request is sent directly, with the headers another site's page would cause",
  best: "confirmed", impact: IMPACT, owasp: "A01",
};
const OBSERVE: Head = {
  id: "csrf.observe", ruleId: "attack.csrf", title: STATE_CHANGE.title,
  invariants: ["session"], prerequisites: ["account_a", "cookie_session"], safetyClass: "read", classes: ["read"], payloads: [],
  oracle: "The session cookie is set without SameSite (or with SameSite=None), or the page that should hand out an anti-forgery token hands out none. Nothing is changed.",
  shows: "that a layer against forged requests is missing", cannotShow: "that a forged request works: none is sent",
  best: "needs_validation", impact: { ...IMPACT, what: "none" }, owasp: "A01",
};

const chain = (t: Pick<Technique, "ruleId" | "title">, o: TestObject, c: StateChange, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, ["marker", "changed"], accounts, [
    plantStep("a", o),
    stepOf("a", { ...c.request, body: c.request.body?.split("{{marker}}").join("{{changed}}"), headers: { ...(c.request.headers ?? {}), ...FORGED } }),
    { as: "a", method: "GET", path: replayPath(o.read), expect: { kind: "not_contains", value: "{{changed}}" } },
    deleteStep("a", o),
  ]);

async function tokenOf(ctx: TechniqueContext, c: StateChange): Promise<string | null> {
  if (!c.token) return null;
  const r = await ctx.io.send("a", "GET", c.token.from.path, { purpose: "read", cls: "read" });
  return r && ok(r.status) ? readId(r.body, c.token.from.jsonPath) || null : null;
}

export const CSRF_TECHNIQUES: readonly Technique[] = [
  {
    ...STATE_CHANGE,
    chain: (target, accounts) => (target.object && target.change ? chain(STATE_CHANGE, target.object, target.change, accounts) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = STATE_CHANGE, o = target.object, c = target.change;
      if (!o || !c) return notTestable(t, "the app model names no change of the test record for this");
      if (!ctx.session) return notTestable(t, "this run cannot tell how the test account is signed in");
      const cred = await ctx.session.credential("a");
      if (!cred) return notTestable(t, "the test account is not set, or its sign-in failed");
      if (!isCookieSession(cred)) return notTestable(t, "the test account signs in with a header, not a cookie: a browser never sends that by itself, so there is nothing to forge");
      const planted = await plant(ctx, "a", o);
      if (!planted.ok) return notTestable(t, (planted as { why: string }).why);
      const rec = planted.record;
      const route = routeOf(c.request.path), method = c.request.method, as: As = "a";
      // The record's marker is replaced by the test: it is deleted here, whatever marker of this run it holds by then.
      return withChanged(ctx, rec, async () => {
      const sees = async (m: string): Promise<boolean> => { const r = await ctx.io.send("a", "GET", o.read.split("{id}").join(encodeURIComponent(rec.id)), { purpose: "read", cls: "read", leg: "positive" }); return !!r && ok(r.status) && r.body.includes(m); };
      const change = (m: string, headers: Record<string, string>, body?: (b: string) => string) => {
        const f = fillRequest(c.request, { id: rec.id, marker: m });
        return sendRequest(ctx, "a", { ...f, ...(f.body !== undefined && body ? { body: body(f.body) } : {}) }, { cls: "write_own_test_records", leg: "test", headers }, [rec.id]);
      };
      const token = await tokenOf(ctx, c);
      // The control: the ordinary request, with its token when the app has one. It must work, or nothing below means anything.
      const m0 = ctx.registry.next("a");
      const plain = await change(m0, c.token && token ? { [c.token.header]: token } : {});
      if (!plain || unusable(plain) || !(await sees(m0))) return notTestable(t, "the ordinary change of the test record did not work, so the test would show nothing");
      // The forged request: no token, and the Origin and Referer of another site.
      const m1 = ctx.registry.next("a");
      const forged = await change(m1, FORGED);
      if (!forged || !(await sees(m1))) return result(t, "held", { reason: "the change was refused without its token or from another site's address", method, route, as, status: forged?.status ?? 0 });
      const m2 = ctx.registry.next("a");
      await change(m2, FORGED);
      const twice = await sees(m2);
      let asText = false;
      if (method === "POST" && c.request.body !== undefined) {
        const m3 = ctx.registry.next("a");
        await change(m3, { ...FORGED, "Content-Type": "text/plain" });
        asText = await sees(m3);
      }
      const cookie = sameSiteOf(ctx.session!.cookieFlags("a"));
      const sendable = browserCanSend(method, c.request.body !== undefined, asText);
      const how = c.token ? "without its anti-forgery token and with another site's Origin" : "with another site's Origin and Referer";
      const cookieWords = cookie === "none" ? "has no SameSite protection" : cookie === "lax_or_strict" ? "is set with SameSite" : "could not be looked at";
      const missing = [
        ...(twice ? [] : ["it did not show a second time"]),
        ...(cookie === "none" ? [] : [cookie === "unknown" ? "the session cookie's flags could not be looked at in this run" : "the session cookie is set with SameSite, which stops most browsers from sending it from another site"]),
        ...(sendable ? [] : [method === "POST" ? "the app accepts this body only as JSON, which a browser sends from another site only when the app's cross-origin settings allow it" : `a browser sends a ${method} from another site only when the app's cross-origin settings allow it`]),
      ];
      return result(t, missing.length ? "needs_validation" : "violated", {
        reason: missing.length ? missing.join("; ") : "the forged request changed the run's own record twice, the cookie has no SameSite protection, and a browser can send the request from another site",
        method, route, as, status: forged.status, marker: m1, payload: c.token ? "csrf.no_token" : "csrf.foreign_origin",
        evidence: EVIDENCE.forgedChange(how, cookieWords), meta: { cookie: cookieWords, kind: sendable ? "a browser can send it" : "needs cross-origin permission", proof: "marker" },
        replay: chain(t, o, c, ctx.accounts),
      });
      });
    },
  },
  {
    ...OBSERVE,
    chain: (target, accounts) => (target.session ? specOf(OBSERVE, [], accounts, [{ as: "a", method: "GET", path: target.session.route, login: { role: "a", wrong: false }, expect: { kind: "cookie_flags" } }]) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = OBSERVE;
      if (!ctx.session) return notTestable(t, "this run cannot tell how the test account is signed in");
      const cred = await ctx.session.credential("a");
      if (!cred) return notTestable(t, "the test account is not set, or its sign-in failed");
      if (!isCookieSession(cred)) return notTestable(t, "the test account signs in with a header, not a cookie: a browser never sends that by itself");
      const cookie = sameSiteOf(ctx.session!.cookieFlags("a"));
      const c = target.change;
      const token = c?.token ? await tokenOf(ctx, c) : null;
      const seen = [
        ...(cookie === "none" ? ["the session cookie has no SameSite protection"] : []),
        ...(c?.token && !token ? ["the page that should hand out an anti-forgery token handed out none"] : []),
      ];
      const route = c ? routeOf(c.request.path) : target.session?.route ?? "/";
      if (!seen.length) return result(t, cookie === "unknown" ? "not_testable" : "held", { reason: cookie === "unknown" ? "the session cookie's flags could not be looked at in this run" : "the session cookie is set with SameSite", route, as: "a" });
      return result(t, "needs_validation", {
        reason: "an observation: a layer against forged requests is missing. No forged request was sent, so nothing is shown to work", route, as: "a", status: 200,
        evidence: EVIDENCE.forgeryObserved(seen.join("; ")), meta: { cookie: cookie === "none" ? "no SameSite" : "SameSite set", kind: "observation" },
        replay: CSRF_TECHNIQUES[1]!.chain(target, ctx.accounts),
      });
    },
  },
];
