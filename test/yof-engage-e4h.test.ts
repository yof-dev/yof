/**
 * E4h (board Y24/OA4): the techniques the first library pass declared but had never been HIT-TESTED, because the
 * in-memory fixture modelled no cookie or token sessions and no out-of-band canary. The fixture now models them
 * (test/fixtures/vuln-app.ts: /api/login cookie and JWT sign-in, sign-out, reset redemption, a wrong-password limit,
 * a CSRF-able change, an ordered-step flow, a method/content-type-gated record, a stored-markup page, a timing branch,
 * and a counted canary). Each technique below is run twice: a TRUE HIT on the vulnerable app, and SILENCE on its twin.
 *
 *   HIT    = "violated" (the oracle saw its whole demonstration) or "needs_validation" (a sign, honestly short of proof).
 *   SILENT = "held" / "not_testable" / "not_tested" / "not_allowed" / "blocked_not_tested".
 *
 * Every stage-4 safety rule still holds: the payloads are the harmless markers from the fixed list; the timing test is
 * refused on a production host (owner decision D8, asserted below); nothing reads a file or the environment; and the
 * SSRF test only ever names the yof canary (library/ssrf.ts canaryAllowed), never an internal or metadata address.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MarkerRegistry } from "../src/attack/engage/markers";
import { ACCESS_TECHNIQUES } from "../src/attack/engage/library/access";
import { INJECTION_TECHNIQUES } from "../src/attack/engage/library/injection";
import { LOGIC_TECHNIQUES } from "../src/attack/engage/library/logic";
import { CSRF_TECHNIQUES } from "../src/attack/engage/library/csrf";
import { AUTH_SESSION_TECHNIQUES } from "../src/attack/engage/library/auth-session";
import { CRYPTO_TECHNIQUES } from "../src/attack/engage/library/crypto";
import { SSRF_TECHNIQUES } from "../src/attack/engage/library/ssrf";
import { techniqueAllowed } from "../src/attack/engage/library";
import type { Outcome, SessionAccess, Technique, TechniqueTarget, TestObject } from "../src/attack/engage/library/types";
import { CANARY_BASE, contextFor, cookieSession, ioFor, jwtSession, publicCanaryAccess, startVulnApp, type VulnServer } from "./fixtures/vuln-app";
import { roe } from "./engage-helpers";

const byId = (arr: readonly Technique[], id: string): Technique => arr.find((t) => t.id === id)!;
const HIT: Outcome[] = ["violated", "needs_validation"];
const SILENT: Outcome[] = ["held", "not_testable", "not_tested", "not_allowed", "blocked_not_tested"];

const notesObject = (): TestObject => ({
  create: { path: "/api/notes", body: '{"title":"{{marker}}"}' },
  idPath: "id", read: "/api/notes/{id}",
  update: { method: "PATCH", path: "/api/notes/{id}", body: '{"title":"{{marker}}"}' },
  delete: "/api/notes/{id}",
});
const docsObject = (): TestObject => ({
  create: { path: "/api/docs", body: '{"title":"{{marker}}"}' },
  idPath: "id", read: "/api/docs/{id}",
  update: { method: "PATCH", path: "/api/docs/{id}", body: '{"title":"{{marker}}"}' },
  delete: "/api/docs/{id}",
});

interface Case {
  name: string;
  t: () => Technique;
  target: () => TechniqueTarget;
  /** The session this technique signs in through; `vuln` picks a per-app style where it matters (crypto). */
  sess?: (v: VulnServer, vuln: boolean) => SessionAccess;
  canary?: boolean;
}

const runOn = async (c: Case, v: VulnServer, vuln: boolean): Promise<ReturnType<Technique["run"]>> => {
  const ctx = contextFor(v, ioFor(v.base), new MarkerRegistry(), {
    ...(c.sess ? { session: c.sess(v, vuln) } : {}),
    ...(c.canary ? { canary: publicCanaryAccess(v) } : {}),
  });
  return c.t().run(ctx, c.target());
};

const CASES: Case[] = [
  // CSRF
  { name: "csrf.state_change", t: () => byId(CSRF_TECHNIQUES, "csrf.state_change"), sess: (v) => cookieSession(v),
    target: () => ({ object: notesObject(), change: { request: { method: "POST", path: "/api/notes/{id}/title", body: '{"title":"{{marker}}"}' } } }) },
  { name: "csrf.observe", t: () => byId(CSRF_TECHNIQUES, "csrf.observe"), sess: (v) => cookieSession(v),
    target: () => ({ session: { route: "/api/me" } }) },
  // Session and token tests
  { name: "session.sign_out", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.sign_out"), sess: (v) => cookieSession(v),
    target: () => ({ session: { route: "/api/me", signOut: { method: "POST", path: "/api/signout" } } }) },
  { name: "session.reset_reuse", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.reset_reuse"), sess: (v) => cookieSession(v),
    target: () => ({ session: { reset: { method: "POST", path: "/api/reset/redeem", body: "{}" } } }) },
  { name: "session.jwt_none", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.jwt_none"), sess: (v) => jwtSession(v),
    target: () => ({ session: { route: "/api/me" } }) },
  { name: "session.jwt_signature", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.jwt_signature"), sess: (v) => jwtSession(v),
    target: () => ({ session: { route: "/api/me" } }) },
  { name: "session.cookie_flags", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.cookie_flags"), sess: (v) => cookieSession(v),
    target: () => ({ session: { route: "/api/me" } }) },
  { name: "session.password_limit", t: () => byId(AUTH_SESSION_TECHNIQUES, "session.password_limit"), sess: (v) => cookieSession(v),
    target: () => ({ session: { route: "/api/me" } }) },
  { name: "crypto.short_token", t: () => byId(CRYPTO_TECHNIQUES, "crypto.short_token"), sess: (v, vuln) => cookieSession(v, vuln ? "short" : "strong"),
    target: () => ({}) },
  { name: "crypto.predictable_token", t: () => byId(CRYPTO_TECHNIQUES, "crypto.predictable_token"), sess: (v, vuln) => cookieSession(v, vuln ? "predictable" : "strong"),
    target: () => ({}) },
  // Stored XSS
  { name: "injection.xss_stored", t: () => byId(INJECTION_TECHNIQUES, "injection.xss_stored"),
    target: () => ({ object: notesObject(), input: { request: { method: "POST", path: "/api/render", body: '{"value":"{{value}}"}' }, render: { path: "/api/notes/{id}/page", as: "a" } } }) },
  // Id moved
  { name: "access.id_moved", t: () => byId(ACCESS_TECHNIQUES, "access.id_moved"),
    target: () => ({ object: { ...notesObject(), alternates: [{ method: "GET", path: "/api/notes/by?id={id}" }] } }) },
  // Method override / content type
  { name: "access.method_override", t: () => byId(ACCESS_TECHNIQUES, "access.method_override"), target: () => ({ object: docsObject() }) },
  { name: "access.content_type", t: () => byId(ACCESS_TECHNIQUES, "access.content_type"), target: () => ({ object: docsObject() }) },
  // Timing injection
  { name: "injection.sql_time", t: () => byId(INJECTION_TECHNIQUES, "injection.sql_time"),
    target: () => ({ input: { request: { method: "GET", path: "/api/report?q={{value}}" }, as: "a" } }) },
  // Step skipping
  { name: "logic.state_skip", t: () => byId(LOGIC_TECHNIQUES, "logic.state_skip"),
    target: () => ({ object: notesObject(), ordered: { statePath: "stage", steps: [
      { name: "step 1", request: { method: "POST", path: "/api/notes/{id}/step1" }, state: "1" },
      { name: "step 2", request: { method: "POST", path: "/api/notes/{id}/step2" }, state: "2" },
      { name: "step 3", request: { method: "POST", path: "/api/notes/{id}/step3" }, state: "3" },
    ] } }) },
  // SSRF against our own canary
  { name: "ssrf.canary", t: () => byId(SSRF_TECHNIQUES, "ssrf.canary"), canary: true,
    target: () => ({ fetch: { request: { method: "POST", path: "/api/fetch", body: '{"url":"{{url}}"}' }, restricted: true, as: "a", canaryBase: CANARY_BASE } }) },
];

describe("E4h: each technique hits the vulnerable app and stays silent on the twin", () => {
  let vuln: VulnServer, twin: VulnServer;
  beforeEach(async () => { vuln = await startVulnApp(true); twin = await startVulnApp(false); });
  afterEach(async () => { await vuln.close(); await twin.close(); });

  for (const c of CASES) {
    it(c.name, async () => {
      const onVuln = await runOn(c, vuln, true);
      const onTwin = await runOn(c, twin, false);
      expect(HIT, `${c.name} vulnerable -> ${onVuln.outcome} (${onVuln.reason})`).toContain(onVuln.outcome);
      expect(SILENT, `${c.name} twin -> ${onTwin.outcome} (${onTwin.reason})`).toContain(onTwin.outcome);
    });
  }
});

describe("E4h safety: the timing test obeys owner decision D8", () => {
  it("refuses injection.sql_time on a production host", () => {
    const prod = roe({ host: "127.0.0.1", environment: "production", windows: ["01:00-05:00"], classes: ["read", "write_own_test_records", "timing"] });
    const a = techniqueAllowed(byId(INJECTION_TECHNIQUES, "injection.sql_time"), prod, "127.0.0.1");
    expect(a.ok).toBe(false);
  });
});
