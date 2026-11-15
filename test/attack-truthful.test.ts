/**
 * Two promises made true (audits of 11 Nov 2026):
 *   A5b  a light run is read-only in fact. It used to send the sign-in POST of an account with a `login` block while
 *        the README and the Action said "read-only". Now only GET and HEAD leave, enforced in the HTTP client.
 *   4.4  "a signed-in route answers without a sign-in" is a finding only when the signed-out answer holds data that
 *        is shown to be the signed-in ACCOUNT's. Any shared value used to count (a plan name, a status, a public
 *        list): both hits on the OWASP Juice Shop were false. Anything weaker is "needs validation", never a finding.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { parseAttackConfig, type AttackConfig } from "../src/attack/config";
import { AttackClient, RefusedError, type FetchFn } from "../src/attack/http";
import type { ProofOk } from "../src/attack/proof";
import { attackComment, formatAttackText, type AttackReport } from "../src/attack/report";
import { accountData, identifying, runAttack, sameData } from "../src/attack/runner";
import { scopeDocument } from "../src/attack/scope-doc";

const APP = "shop.example.com";
const proof: ProofOk = { ok: true, kind: "production", method: "dns", origin: `https://${APP}`, host: APP };
const config = (extra: Record<string, unknown>): AttackConfig => parseAttackConfig(JSON.stringify({
  app: APP, consent: consentText(APP), routes: ["/api/me"], budget: { requests: 100, seconds: 60, perSecond: 100 }, ...extra,
}));
const noSleep = async () => {};
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const LOGIN = { login: { path: "/api/login", body: '{"email":"{{email}}","password":"{{password}}"}', tokenPath: "token" }, emailEnv: "YOF_ATTACK_A_EMAIL", passwordEnv: "YOF_ATTACK_A_PASSWORD" };
const LOGIN_ENV = { YOF_ATTACK_A_EMAIL: "alice@example.com", YOF_ATTACK_A_PASSWORD: "correct horse" };

describe("A5b: a light run is read-only in fact", () => {
  function app() {
    const sent: { method: string; path: string; body?: string }[] = [];
    const f: FetchFn = async (u, init) => {
      const path = new URL(u).pathname;
      sent.push({ method: init.method, path, body: init.body });
      if (path === "/api/login") return json({ token: "session-token-1" });
      if (path === "/api/me") return init.headers.Authorization ? json({ id: "user-alice", email: "alice@example.com" }) : json({ error: "sign in" }, 401);
      return json({}, 404);
    };
    return { sent, f };
  }

  it("an account that signs in with a password sends NO sign-in in a light run, and the run says why", async () => {
    const a = app();
    const res = await runAttack({ cfg: config({ accounts: { a: LOGIN } }), proof, mode: "light", env: LOGIN_ENV, fetch: a.f, sleep: noSleep });
    expect(a.sent.filter((q) => q.method !== "GET" && q.method !== "HEAD")).toEqual([]);
    expect(JSON.stringify(a.sent)).not.toContain("correct horse");
    expect(a.sent.some((q) => q.path === "/api/login")).toBe(false);
    const note = res.notes.find((n) => n.startsWith("skipped:sign-in:"))!;
    expect(note).toContain("account a signs in with a password, and a light run is read-only, so it sends no sign-in");
    expect(note).toContain("--mode full");
    expect(res.notes.filter((n) => n.startsWith("skipped:sign-in:"))).toHaveLength(1);   // said once, not per request
    expect(res.findings.filter((x) => x.group !== "surface")).toEqual([]);
  });

  it("the same config in a full run does sign in (the mode the person chose knowingly)", async () => {
    const a = app();
    await runAttack({ cfg: config({ accounts: { a: LOGIN } }), proof, mode: "full", env: LOGIN_ENV, fetch: a.f, sleep: noSleep, groups: ["auth"] });
    expect(a.sent.filter((q) => q.method === "POST").map((q) => q.path)).toEqual(["/api/login"]);
  });

  it("an account given as a header is still used in a light run, with GET only", async () => {
    const a = app();
    const res = await runAttack({ cfg: config({ accounts: { a: { env: "YOF_ATTACK_A" } } }), proof, mode: "light", env: { YOF_ATTACK_A: "Bearer t" }, fetch: a.f, sleep: noSleep });
    expect(a.sent.length).toBeGreaterThan(1);
    expect(a.sent.every((q) => q.method === "GET")).toBe(true);
    expect(res.notes.some((n) => n.startsWith("skipped:sign-in:"))).toBe(false);
  });

  it("the HTTP client itself refuses every request that is not GET or HEAD, whatever asks for it", () => {
    const c = new AttackClient({ origin: `https://${APP}`, budget: { requests: 5, seconds: 60, perSecond: 100 }, postPaths: ["/api/login", "/api/notes"], readOnly: true, fetch: async () => json({}), sleep: noSleep });
    expect(() => c.check("GET", "/api/me", "read")).not.toThrow();
    expect(() => c.check("HEAD", "/api/me", "read")).not.toThrow();
    for (const [m, purpose] of [["POST", "login"], ["POST", "create"], ["POST", "ai"], ["PATCH", "owned"], ["PUT", "owned"], ["DELETE", "cleanup"]] as const) {
      expect(() => c.check(m, m === "POST" ? "/api/login" : "/api/notes/1", purpose), m).toThrow(RefusedError);
      expect(() => c.check(m, "/api/notes", purpose), m).toThrow(/a light run is read-only/);
    }
  });

  it("the words match the code: README, the Action, the help text and the scope document", () => {
    const root = join(__dirname, "..");
    const readme = readFileSync(join(root, "README.md"), "utf8");
    expect(readme).toContain("A light run is read-only and the HTTP client enforces it: only GET and HEAD requests are sent.");
    expect(readme).toContain("signs no account in");
    expect(readme).toContain("--mode <full|light>       light = read-only: GET and HEAD only, no sign-in");
    expect(readFileSync(join(root, "attack/action.yml"), "utf8")).toContain("light (read-only, GET and HEAD requests only, no account is signed in)");
    expect(readFileSync(join(root, "src/cli.ts"), "utf8")).toContain("light = read-only: GET and HEAD only (no sign-in, no test records,");
    const doc = scopeDocument({ cfg: config({ accounts: { a: LOGIN } }), mode: "light", target: null, date: "2026-11-11", version: "0.0.0", configPath: ".yof/attack.json" });
    expect(doc).toContain("- **Mode: light.** Read-only: only GET and HEAD requests are sent.");
    expect(doc).not.toContain("still sends its sign-in request");
  });
});

describe("4.4: whose data came back?", () => {
  const alice = JSON.stringify({ id: "user-alice-7781", email: "alice@example.com", plan: "team-plan-gold", status: "active-account", role: "member-role", createdAt: "2026-11-01T10:00:00Z", notes: [] });
  const bob = JSON.stringify({ id: "user-bob-9902", email: "bob@example.com", plan: "team-plan-gold", status: "active-account", role: "member-role", createdAt: "2026-11-01T10:00:00Z", notes: [] });
  const catalog = JSON.stringify({ products: [{ id: "prod-apple-juice", name: "Apple Juice (1000ml)", price: 1.99 }, { id: "prod-orange-juice", name: "Orange Juice (1000ml)", price: 2.99 }], updatedAt: "2026-11-11T09:00:00Z" });

  it("the account's own identifying data in a signed-out answer is the finding", () => {
    expect(accountData(alice, alice, { otherAccount: bob })).toBe("account");
    expect(accountData(alice, JSON.stringify({ user: { email: "alice@example.com" } }), { otherAccount: bob })).toBe("account");
    // No second account, but the config knows the account's sign-in email.
    expect(accountData(alice, alice, { identity: ["Alice@Example.com"] })).toBe("account");
  });

  it("false positives of the old test are no longer findings", () => {
    const cases: [string, string, string, string | null][] = [
      ["a public list every visitor gets (Juice Shop's product list)", catalog, catalog, catalog],
      ["defaults and enums: the same plan, status and role", alice, JSON.stringify({ plan: "team-plan-gold", status: "active-account", role: "member-role" }), bob],
      ["a timestamp both answers carry", alice, JSON.stringify({ createdAt: "2026-11-01T10:00:00Z", serverTime: "2026-11-11T12:00:00Z" }), bob],
      ["an id field holding a date, a flag or a tiny number", JSON.stringify({ id: 7, user_id: "2026-11-01T10:00:00Z", owner: "true", label: "shared-label-x" }), JSON.stringify({ id: 7, user_id: "2026-11-01T10:00:00Z", owner: "true", label: "shared-label-x" }), null],
      ["the account's data, but with no second account to compare with", alice, alice, null],
      ["an identifying value the other account gets too (a shared workspace name)", JSON.stringify({ id: "workspace-main-1", name: "Acme Workspace" }), JSON.stringify({ id: "workspace-main-1", name: "Acme Workspace" }), JSON.stringify({ id: "workspace-main-1", name: "Acme Workspace" })],
    ];
    for (const [name, base, anon, other] of cases) {
      expect(sameData(base, anon), `${name}: the old test said yes`).toBe(true);
      expect(accountData(base, anon, { otherAccount: other }), name).toBe("unclear");
    }
  });

  it("nothing in common, a refusal and empty answers are nothing at all", () => {
    expect(accountData(alice, bob.replace("team-plan-gold", "x").replace("active-account", "y").replace("member-role", "z").replace("2026-11-01T10:00:00Z", "w"), { otherAccount: bob })).toBe("none");
    expect(accountData(alice, JSON.stringify({ error: "Unauthorized", plan: "team-plan-gold" }), { otherAccount: bob })).toBe("none");
    expect(accountData("[]", "[]", { otherAccount: "[]" })).toBe("none");
    expect(accountData("{}", "{}", {})).toBe("none");
    expect(accountData(JSON.stringify({ items: [], total: 0 }), JSON.stringify({ items: [], total: 0 }), {})).toBe("none");
    expect(accountData(alice, "", { otherAccount: bob })).toBe("none");
  });

  it("identifying fields are ids, emails and names; never a word that only ends like one", () => {
    const got = identifying(JSON.stringify({ id: "user-1234", userId: "u-5678", owner_id: "o-9999", email: "a@example.com", displayName: "Alice Example", paid: "yes-paid-up", valid: "valid-forever", grid: "grid-layout-3", plan: "gold-plan", count: 12345, nested: [{ user_email: "n@example.com" }] }));
    expect([...got].sort()).toEqual(["displayname=alice example", "email=a@example.com", "id=user-1234", "ownerid=o-9999", "useremail=n@example.com", "userid=u-5678"]);
  });

  function shop(open: "account" | "public" | "closed", withB = true) {
    const users: Record<string, unknown> = { "Bearer a": JSON.parse(alice), "Bearer b": JSON.parse(bob) };
    const f: FetchFn = async (u, init) => {
      const path = new URL(u).pathname;
      const who = users[init.headers.Authorization ?? ""];
      if (path === "/api/me") return who ? json(who) : open === "account" ? json(JSON.parse(alice)) : json({ error: "sign in" }, 401);
      if (path === "/api/products") return who || open === "public" ? json(JSON.parse(catalog)) : json({ error: "sign in" }, 401);
      return json({}, 404);
    };
    const cfg = config({ routes: ["/api/me", "/api/products"], accounts: withB ? { a: { env: "YOF_ATTACK_A" }, b: { env: "YOF_ATTACK_B" } } : { a: { env: "YOF_ATTACK_A" } } });
    return runAttack({ cfg, proof, mode: "light", env: { YOF_ATTACK_A: "Bearer a", YOF_ATTACK_B: "Bearer b" }, fetch: f, sleep: noSleep, groups: ["auth"] });
  }

  it("the run: account A's record open to nobody is a confirmed finding", async () => {
    const res = await shop("account");
    expect(res.findings.map((x) => [x.ruleId, x.route])).toEqual([["attack.auth_bypass", "/api/me"]]);
    expect(res.review).toEqual([]);
  });

  it("the run: a public list on a route the config calls signed-in is 'needs validation', never a finding", async () => {
    const res = await shop("public");
    expect(res.findings).toEqual([]);
    expect(res.review).toHaveLength(1);
    expect(res.review[0]).toMatchObject({ ruleId: "attack.auth_bypass", method: "GET", route: "/api/products", as: "anon", status: 200 });
    expect(res.review[0]!.reason).toContain("none that only this account has");
    expect(res.review[0]!.reason).toContain("It may be public by design.");
  });

  it("the run: with one account only, even the account's own record is 'needs validation', and the reason asks for account B", async () => {
    const res = await shop("account", false);
    expect(res.findings).toEqual([]);
    expect(res.review.map((x) => x.route)).toEqual(["/api/me"]);
    expect(res.review[0]!.reason).toContain("no second account in a separate tenant (account B)");
  });

  it("the run: a closed app has neither", async () => {
    const res = await shop("closed");
    expect(res.findings).toEqual([]);
    expect(res.review).toEqual([]);
  });

  it("needs-validation items are shown apart, never counted and never fail a run", async () => {
    const res = await shop("public");
    const report: AttackReport = {
      tool: "yof", command: "attack", version: "0.0.0", app: APP, target: { origin: proof.origin, host: APP, kind: "production", proof: "dns" }, mode: "light",
      scope: { full: true, label: "full run", groups: ["auth"], reasons: [], routes: [] }, consent: { app: APP, text: consentText(APP) },
      startedAt: "2026-11-11T12:00:00.000Z", finishedAt: "2026-11-11T12:00:02.000Z", stopped: null, cleanup: res.cleanup, requests: res.requests,
      budget: { requests: 100, seconds: 60, perSecond: 100 }, groups: res.groups, findings: res.findings, review: res.review, tests: [], notes: res.notes,
      unconfirmed: res.unconfirmed, exchanges: [], failed: res.findings.some((x) => x.severity !== "nice"),
    };
    expect(report.failed).toBe(false);
    const text = formatAttackText(report);
    expect(text).toContain("Needs validation (not counted as findings: check these yourself)");
    expect(text).toContain("Nothing found in what was tested.");
    expect(text).not.toContain("\nFindings\n");
    const comment = attackComment(report, [], null);
    expect(comment).toContain("**Needs validation** (1 item, not counted as findings):");
    expect(comment).toContain("Nothing found in what was tested.");
  });
});
