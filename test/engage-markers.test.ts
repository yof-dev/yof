/**
 * yof engagement, open core: planted markers (src/attack/engage/markers.ts) and the differential
 * (src/attack/engage/differential.ts).
 *   1. a marker is YOF-MRK-<run nonce>-<role>-<n>; only a signed-in test account plants one, in its own record;
 *   2. the registry knows what was planted, and clean-up deletes exactly those records and nothing else;
 *   3. the differential: positive control, the test, negative control. PROVEN needs a planted marker and both
 *      controls and a second look; every other way stays "needs validation";
 *   4. the finder alone never confirms: confirmed needs the verifier too;
 *   5. the runner's admin-route comparison: a planted marker is the strongest proof;
 *   6. where no marker can be planted (a list of users), identifying data of other accounts on a route the config
 *      declares admin-only is a finding too, and each false-positive case stays out: values every account shares, an
 *      app that answers 200 to everyone, a member who sees only its own record, nothing to compare with.
 */
import { describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { parseAttackConfig } from "../src/attack/config";
import type { FetchFn } from "../src/attack/http";
import type { ProofOk } from "../src/attack/proof";
import { othersIdentifying, runAttack } from "../src/attack/runner";
import {
  DIFFERENTIAL_REASON_WORDS, decideDifferential, differentialSpec, finalVerdict, missingIdLike, refusedDifferently, runDifferential, sharesValues, type DifferentialPlan,
} from "../src/attack/engage/differential";
import { MARKER_SHAPE, MarkerRegistry, cleanUpMarkers, findMarkers, markerText, newRunNonce, parseMarker, plantMarker } from "../src/attack/engage/markers";
import { NOTE_OBJECT, counterRandom, notesApp, readId } from "./engage-helpers";

const NONCE = "QWHRTPLKXZMB";
const M = markerText(NONCE, "a", 1);
const ok = (body: unknown, status = 200) => ({ status, body: typeof body === "string" ? body : JSON.stringify(body) });
const plan = (over: Partial<DifferentialPlan> = {}): DifferentialPlan => ({ ruleId: "attack.tenant_read", title: "One user can read another user's records by changing the id", owner: "a", other: "b", object: NOTE_OBJECT, plant: true, ...over });
const deps = { readId, random: counterRandom };

describe("1. the marker", () => {
  it("has the shape YOF-MRK-<run nonce>-<role>-<n>", () => {
    expect(M).toBe("YOF-MRK-QWHRTPLKXZMB-A-1");
    expect(markerText(NONCE, "admin", 12)).toBe("YOF-MRK-QWHRTPLKXZMB-ADMIN-12");
    expect(parseMarker(M)).toEqual({ nonce: NONCE, role: "a", n: 1 });
    expect(parseMarker("YOF-MRK-QWHRTPLKXZMB-ANON-1")).toBeNull();
    expect(parseMarker(`${M} `)).toBeNull();
    expect(findMarkers(`{"a":"${M}","b":"x ${markerText(NONCE, "b", 2)} y","c":"${M}"}`)).toEqual([M, "YOF-MRK-QWHRTPLKXZMB-B-2"]);
  });
  it("a run nonce is 12 letters, new every time", () => {
    const seen = new Set(Array.from({ length: 50 }, () => newRunNonce()));
    expect(seen.size).toBe(50);
    for (const n of seen) expect(n).toMatch(/^[A-HJ-NP-Z]{12}$/);
    expect(MARKER_SHAPE.test(markerText(newRunNonce(), "viewer", 3))).toBe(true);
    expect(() => new MarkerRegistry("short")).toThrow();
  });
  it("only a signed-in test account plants, and only a marker this run issued can be registered", () => {
    const r = new MarkerRegistry(NONCE);
    expect(r.next("a")).toBe("YOF-MRK-QWHRTPLKXZMB-A-1");
    expect(r.next("a")).toBe("YOF-MRK-QWHRTPLKXZMB-A-2");
    expect(r.next("b")).toBe("YOF-MRK-QWHRTPLKXZMB-B-1");
    expect(() => r.next("anon" as never)).toThrow(/signed-in test account/);
    expect(() => r.register("YOF-MRK-AAAAAAAAAAAA-A-1", { id: "n1", createRoute: "/api/notes", deleteRoute: "/api/notes/{id}" })).toThrow(/not issued by this run/);
    expect(() => r.register(M, { id: "n1", createRoute: "/api/notes", deleteRoute: "/api/notes/all" })).toThrow(/\{id\}/);
    r.register(M, { id: "n1", createRoute: "/api/notes", deleteRoute: "/api/notes/{id}" });
    expect(() => r.register(M, { id: "n2", createRoute: "/api/notes", deleteRoute: "/api/notes/{id}" })).toThrow(/planted already/);
    expect(r.mine(M)).toBe(true);
    expect(r.mine("YOF-MRK-AAAAAAAAAAAA-A-1")).toBe(false);
  });
});

describe("2. planting and exact clean-up", () => {
  it("role A plants in A's own record; the record is owned and registered at once", async () => {
    const app = notesApp();
    const reg = new MarkerRegistry(NONCE);
    const p = await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    expect(p).toMatchObject({ ok: true, record: { marker: M, role: "a", id: "n1", createRoute: "/api/notes", readRoute: "/api/notes/{id}", deleteRoute: "/api/notes/{id}", state: "planted" } });
    expect(app.notes.get("n1")).toEqual({ owner: "a", title: M });
    expect(app.owned).toEqual(["n1"]);
    expect(app.requests).toEqual([{ as: "a", method: "POST", path: "/api/notes", body: `{"title":"${M}"}` }]);
  });
  it("clean-up deletes exactly the planted records, newest first, by the role that made each, and nothing else", async () => {
    const app = notesApp();
    // records that are NOT the run's: one of account A's own, one of B's
    app.handle("a", "POST", "/api/notes", '{"title":"A real note of account A"}');
    app.handle("b", "POST", "/api/notes", '{"title":"A real note of account B"}');
    const reg = new MarkerRegistry(NONCE);
    await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    await plantMarker(app.io, reg, "b", NOTE_OBJECT, readId);
    await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    expect([...app.notes.keys()]).toEqual(["n1", "n2", "n3", "n4", "n5"]);
    const before = app.requests.length;
    const sum = await cleanUpMarkers(app.io, reg);
    expect(sum).toEqual({ planted: 3, deleted: 3, left: [] });
    expect(app.requests.slice(before).filter((r) => r.method === "DELETE").map((r) => `${r.as} ${r.path}`)).toEqual(["a /api/notes/n5", "b /api/notes/n4", "a /api/notes/n3"]);
    expect([...app.notes.entries()]).toEqual([["n1", { owner: "a", title: "A real note of account A" }], ["n2", { owner: "b", title: "A real note of account B" }]]);
    expect((await cleanUpMarkers(app.io, reg)).deleted).toBe(3);   // a second pass sends nothing
    expect(app.requests.slice(before).filter((r) => r.method === "DELETE")).toHaveLength(3);
  });
  it("a record that no longer holds its marker is LEFT, never deleted on a guess; one that is gone counts as gone", async () => {
    const app = notesApp();
    const reg = new MarkerRegistry(NONCE);
    await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    app.notes.set("n1", { owner: "a", title: "Somebody's real note now lives under this id" });
    app.notes.delete("n2");
    const sum = await cleanUpMarkers(app.io, reg);
    expect(sum).toEqual({ planted: 2, deleted: 1, left: [{ route: "/api/notes/{id}", why: "the record no longer holds the run's marker, so it was not deleted" }] });
    expect(app.requests.filter((r) => r.method === "DELETE")).toEqual([]);
    expect(app.notes.has("n1")).toBe(true);
  });
  it("nothing is created when it could not be deleted again, or without an account", async () => {
    const app = notesApp();
    const reg = new MarkerRegistry(NONCE);
    const blocked = { ...app.io, pathAllowed: (p: string) => !p.includes("/api/notes/") };
    expect(await plantMarker(blocked, reg, "a", NOTE_OBJECT, readId)).toEqual({ ok: false, why: "forbidden_path" });
    expect(await plantMarker({ ...app.io, send: async () => null }, reg, "a", NOTE_OBJECT, readId)).toEqual({ ok: false, why: "no_account" });
    expect(app.requests).toEqual([]);
    expect(reg.all()).toEqual([]);
    // past the deadline, clean-up leaves and says so
    await plantMarker(app.io, reg, "a", NOTE_OBJECT, readId);
    expect(await cleanUpMarkers(app.io, reg, { deadline: 5, now: () => 10 })).toEqual({ planted: 1, deleted: 0, left: [{ route: "/api/notes/{id}", why: "the clean-up ran out of time" }] });
  });
});

describe("3. the differential rule", () => {
  const leak = { marker: M, positive: ok({ id: "n1", title: M }), test: ok({ id: "n1", title: M }), negative: ok({ error: "not found" }, 404), repeat: ok({ id: "n1", title: M }) };
  it("proven: the marker, the owner sees it, the other role sees it twice, a missing id is refused differently", () => {
    expect(decideDifferential(leak)).toEqual({ outcome: "proven", reasons: [], exposed: true });
  });
  it("held: the other role is refused, or gets an answer without the marker while the owner sees it", () => {
    expect(decideDifferential({ ...leak, test: ok({ error: "not found" }, 404) })).toEqual({ outcome: "held", reasons: [], exposed: false });
    expect(decideDifferential({ ...leak, test: ok({ id: "n9", title: "my own note" }) })).toEqual({ outcome: "held", reasons: [], exposed: false });
  });
  it("EVERY way short of proven stays needs validation", () => {
    const cases: [string, Parameters<typeof decideDifferential>[0], string[]][] = [
      ["no marker planted", { ...leak, marker: null }, ["no_marker"]],
      ["positive control failed", { ...leak, positive: ok({ id: "n1" }) }, ["positive_control_failed"]],
      ["positive control refused", { ...leak, positive: ok({ error: "forbidden" }, 403) }, ["positive_control_failed"]],
      ["positive control missing", { ...leak, positive: null }, ["positive_control_missing"]],
      ["negative control missing", { ...leak, negative: null }, ["negative_control_missing"]],
      ["negative control got no answer", { ...leak, negative: ok("", 0) }, ["negative_control_missing"]],
      ["negative control failed: 200 with a page", { ...leak, negative: ok({ page: "Welcome. Nothing is stored under this address yet, please come back." }) }, ["negative_control_failed"]],
      ["negative control failed: the same answer", { ...leak, negative: leak.test }, ["negative_control_failed"]],
      ["did not show a second time", { ...leak, repeat: ok({ error: "not found" }, 404) }, ["not_reproduced"]],
      ["never looked a second time", { ...leak, repeat: undefined }, ["not_reproduced"]],
      ["no marker and no negative control", { ...leak, marker: null, negative: null }, ["no_marker", "negative_control_missing"]],
      ["no marker and nobody to compare with", { ...leak, marker: null, positive: null }, ["no_marker", "positive_control_missing"]],
    ];
    for (const [name, input, reasons] of cases) {
      const d = decideDifferential(input);
      expect(d.outcome, name).toBe("needs_validation");
      expect(d.reasons, name).toEqual(reasons);
      expect(finalVerdict(d.outcome, null), name).toBe("needs_validation");
      expect(finalVerdict(d.outcome, { stands: true }), name).toBe("needs_validation");
      for (const r of d.reasons) expect(DIFFERENTIAL_REASON_WORDS[r]).toBeTruthy();
    }
  });
  it("an answer that says nothing is never read as a refusal: no answer, 429, 503", () => {
    for (const status of [0, 429, 503]) expect(decideDifferential({ ...leak, test: ok("", status) })).toEqual({ outcome: "not_testable", reasons: ["no_answer"], exposed: false });
    expect(decideDifferential({ ...leak, test: null }).outcome).toBe("not_testable");
    // the owner cannot see its own marker and the other role gets a page without it: nothing was tested
    expect(decideDifferential({ ...leak, positive: ok({ id: "n1" }), test: ok({ id: "n1" }) })).toEqual({ outcome: "not_testable", reasons: ["positive_control_failed"], exposed: false });
  });
  it("without a marker, an app that answers the same for an id that does not exist shows nothing at all", () => {
    const shell = ok("<html><body>Loading the dashboard application shell...</body></html>");
    expect(decideDifferential({ marker: null, positive: shell, test: shell, negative: shell, repeat: shell })).toEqual({ outcome: "not_testable", reasons: ["answers_everything"], exposed: false });
  });
  it("the controls, one by one", () => {
    const t = ok({ id: "n1", title: M });
    expect(refusedDifferently(ok({ error: "not found" }, 404), t, M)).toBe(true);
    expect(refusedDifferently(ok("null"), t, M)).toBe(true);
    expect(refusedDifferently(ok("[]"), t, M)).toBe(true);
    expect(refusedDifferently(ok({ error: "No such record" }), t, M)).toBe(true);
    expect(refusedDifferently(t, t, M)).toBe(false);
    expect(refusedDifferently(ok({ id: "zz", title: M }, 404), t, M)).toBe(false);
    expect(refusedDifferently(ok({ id: "zz", title: "another full record entirely" }), t, M)).toBe(false);
    expect(sharesValues('{"users":["alice-admin"]}', '{"users":["alice-admin"]}')).toBe(true);
    expect(sharesValues('{"users":["alice-admin"]}', '{"error":"forbidden"}')).toBe(false);
    expect(sharesValues("[]", "[]")).toBe(false);
    expect(missingIdLike("4812", counterRandom)).toMatch(/^9\d{7,13}$/);
    expect(missingIdLike("5a3b1e00-0000-4000-8000-000000000000", counterRandom)).toMatch(/^[0-9a-f]{8}-0000-4000-8000-[0-9a-f]{12}$/);
    expect(missingIdLike("n1", counterRandom)).toMatch(/^yofnone[0-9a-f]{12}$/);
  });
});

describe("3b. the differential, run", () => {
  it("a leaking app: all three legs, the same request for both roles, and the chain as a replay spec", async () => {
    const app = notesApp({ leak: true });
    const reg = new MarkerRegistry(NONCE);
    const r = await runDifferential(app.io, reg, plan(), deps);
    expect(r).toMatchObject({ outcome: "proven", reasons: [], exposed: true, marker: M });
    expect(r.legs.positive).toEqual({ as: "a", method: "GET", route: "/api/notes/{id}", status: 200, sawMarker: true });
    expect(r.legs.test).toEqual({ as: "b", method: "GET", route: "/api/notes/{id}", status: 200, sawMarker: true });
    expect(r.legs.negative).toMatchObject({ as: "b", status: 404, sawMarker: false });
    const sent = app.requests.map((q) => `${q.as} ${q.method} ${q.path}`);
    expect(sent.slice(0, 3)).toEqual(["a POST /api/notes", "a GET /api/notes/n1", "b GET /api/notes/n1"]);
    expect(sent[3]).toMatch(/^b GET \/api\/notes\/yofnone[0-9a-f]+$/);
    expect(sent[4]).toBe("b GET /api/notes/n1");
    expect(r.replay!.vars).toEqual(["marker"]);
    expect(r.replay!.steps).toEqual([
      { as: "a", method: "POST", path: "/api/notes", body: '{"title":"{{marker}}"}', save: { name: "id", from: "id" }, setup: true, leg: "plant" },
      { as: "b", method: "GET", path: "/api/notes/{{id}}", leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } },
      { as: "a", method: "GET", path: "/api/notes/{{id}}", leg: "positive", expect: { kind: "marker_present", value: "{{marker}}" } },
      { as: "a", method: "DELETE", path: "/api/notes/{{id}}", cleanup: true },
    ]);
    expect(JSON.stringify(r.replay)).not.toContain(NONCE);   // a spec holds no marker value: a replay makes its own
    expect((await cleanUpMarkers(app.io, reg)).left).toEqual([]);
    expect(app.notes.size).toBe(0);
  });
  it("nobody signed in is tested the same way", async () => {
    const app = notesApp();
    const r = await runDifferential(app.io, new MarkerRegistry(NONCE), plan({ other: "anon" }), deps);
    expect(r.outcome).toBe("held");
    expect(r.legs.test).toMatchObject({ as: "anon", status: 401, sawMarker: false });
    expect(r.legs.negative).toBeNull();   // the controls are sent only when the test showed the marker
  });
  it("a correct app holds; an app with a soft 404 or a blind owner is not proven", async () => {
    expect((await runDifferential(notesApp().io, new MarkerRegistry(NONCE), plan(), deps)).outcome).toBe("held");
    const soft = await runDifferential(notesApp({ leak: true, softMissing: true }).io, new MarkerRegistry(NONCE), plan(), deps);
    expect(soft).toMatchObject({ outcome: "needs_validation", reasons: ["negative_control_failed"] });
    const blind = await runDifferential(notesApp({ leak: true, ownerBlind: true }).io, new MarkerRegistry(NONCE), plan(), deps);
    expect(blind).toMatchObject({ outcome: "needs_validation", reasons: ["positive_control_failed"] });
    const slow = await runDifferential(notesApp({ leak: true, slowDown: true }).io, new MarkerRegistry(NONCE), plan(), deps);
    expect(slow).toMatchObject({ outcome: "not_testable", reasons: ["no_answer"] });
  });
  it("a read-only run plants nothing and can be needs validation at most", async () => {
    const app = notesApp({ adminOpen: true });
    app.handle("admin", "POST", "/api/notes", '{"title":"quarterly numbers for the board"}');
    const before = app.requests.length;
    const r = await runDifferential(app.io, new MarkerRegistry(NONCE), plan({ owner: "admin", other: "a", plant: false, readOnlyPath: "/api/admin/notes" }), deps);
    expect(r).toMatchObject({ outcome: "needs_validation", reasons: ["no_marker"], marker: null, replay: null });
    expect(app.requests.slice(before).length).toBeGreaterThanOrEqual(3);
    expect(app.requests.slice(before).every((q) => q.method === "GET")).toBe(true);
  });
  it("the spec builder tags each step with its leg", () => {
    const spec = differentialSpec(plan({ other: "anon" }), {});
    expect(spec.steps.map((s) => ("leg" in s ? s.leg : undefined))).toEqual(["plant", "test", "positive", undefined]);
  });
});

describe("4. the finder alone never confirms", () => {
  it("confirmed needs a proven finder AND a verifier that could not refute it", () => {
    expect(finalVerdict("proven", null)).toBe("needs_validation");
    expect(finalVerdict("proven", { stands: null })).toBe("needs_validation");
    expect(finalVerdict("proven", { stands: true })).toBe("confirmed");
    expect(finalVerdict("proven", { stands: false })).toBe("rejected");
    expect(finalVerdict("needs_validation", { stands: true })).toBe("needs_validation");
    expect(finalVerdict("needs_validation", { stands: false })).toBe("rejected");
    expect(finalVerdict("held", { stands: true })).toBeNull();
    expect(finalVerdict("not_testable", null)).toBeNull();
  });
});

describe("5. the runner's admin-route comparison follows the same rule", () => {
  const APP = "shop.example.com";
  const proof: ProofOk = { ok: true, kind: "preview", method: "github-deployment", origin: `https://${APP}`, host: APP };
  const cfg = (objects: boolean) => parseAttackConfig(JSON.stringify({
    app: APP, consent: consentText(APP), accounts: { a: { env: "YOF_ATTACK_A" }, admin: { env: "YOF_ATTACK_ADMIN" } }, admin: ["/api/admin/notes"],
    objects: objects ? [NOTE_OBJECT] : [], budget: { requests: 200, seconds: 100, perSecond: 20 },
  }));
  const env = { YOF_ATTACK_A: "Bearer a", YOF_ATTACK_ADMIN: "Bearer admin" };
  const fetchOf = (app: ReturnType<typeof notesApp>): FetchFn => async (url, init) => {
    const u = new URL(url);
    const as = (["a", "admin"] as const).find((r) => init.headers.Authorization === `Bearer ${r}`) ?? "anon";
    const r = app.handle(as, init.method as "GET", `${u.pathname}${u.search}`, init.body);
    return new Response(r.status === 204 ? null : r.body, { status: r.status, headers: { "Content-Type": "application/json" } });
  };
  const run = (app: ReturnType<typeof notesApp>, mode: "full" | "light", objects = true) =>
    runAttack({ cfg: cfg(objects), proof, mode, env, fetch: fetchOf(app), sleep: async () => {}, groups: ["rbac"] });

  it("a member who gets the admin's planted record: a finding, with the marker chain as its replay", async () => {
    const app = notesApp({ adminOpen: true });
    const r = await run(app, "full");
    expect(r.findings.map((f) => [f.ruleId, f.route, f.as])).toEqual([["attack.rbac_escalation", "/api/admin/notes", "a"]]);
    expect(r.review).toEqual([]);
    const f = r.findings[0]!;
    expect(f.evidence).toMatch(/^a member got an answer that holds the admin account's test record: a JSON object with 1 field \(notes\), \d+ characters$/);
    expect(f.meta.marker).toBe("planted");
    expect(JSON.stringify(f)).not.toContain("YOF-MRK-");
    expect(f.replay.steps.map((s) => ("leg" in s ? s.leg : null))).toEqual(["plant", "test", "positive", null]);
    expect(f.replay.steps[1]).toMatchObject({ as: "a", method: "GET", path: "/api/admin/notes", expect: { kind: "marker_absent", value: "{{marker}}" } });
    expect(app.notes.size).toBe(0);
    expect(r.cleanup).toEqual({ deleted: 1, left: [] });
  });
  it("the same open route without a planted marker (a light run, or no object) is needs validation, never a finding", async () => {
    for (const [mode, objects] of [["light", true], ["full", false]] as const) {
      const app = notesApp({ adminOpen: true });
      app.handle("admin", "POST", "/api/notes", '{"title":"quarterly numbers for the board"}');
      const before = app.requests.length;
      const r = await run(app, mode, objects);
      expect(r.findings, mode).toEqual([]);
      expect(r.review.map((v) => [v.ruleId, v.route, v.as]), mode).toEqual([["attack.rbac_escalation", "/api/admin/notes", "a"]]);
      expect(r.review[0]!.reason, mode).toContain("no marker was planted");
      expect(app.requests.slice(before).every((q) => q.method === "GET"), mode).toBe(true);
    }
  });
  it("a closed admin route is neither, and nothing is planted for it", async () => {
    const app = notesApp();
    const r = await run(app, "full");
    expect(r.findings).toEqual([]);
    expect(r.review).toEqual([]);
    expect(app.requests.map((q) => `${q.as} ${q.method} ${q.path}`)).toEqual(["a GET /api/admin/notes"]);
  });
});

describe("6. the second proof: identifying data on a declared admin route", () => {
  const APP = "shop.example.com";
  const proof: ProofOk = { ok: true, kind: "preview", method: "github-deployment", origin: `https://${APP}`, host: APP };
  const USERS = [{ id: "usr_1001", email: "alice@example.com", name: "Alice Example", role: "admin" }, { id: "usr_1002", email: "bob@example.com", name: "Bob Example", role: "member" }, { id: "usr_1003", email: "mem@example.com", name: "Mem Example", role: "member" }];
  const SETTINGS = { plan: "team-plan-gold", roles: ["admin", "member"], seats: 12345, updated_at: "2026-11-12T02:00:00Z", sso: true, items: [] };
  type Kind = "open" | "closed" | "own_record" | "shared_values" | "shell" | "open_to_signed_out";
  const cfg = (admin = true) => parseAttackConfig(JSON.stringify({
    app: APP, consent: consentText(APP), accounts: { a: { env: "YOF_ATTACK_A" }, ...(admin ? { admin: { env: "YOF_ATTACK_ADMIN" } } : {}) }, admin: ["/api/admin/users"],
    budget: { requests: 200, seconds: 100, perSecond: 20 },
  }));
  const env = { YOF_ATTACK_A: "Bearer a", YOF_ATTACK_ADMIN: "Bearer admin" };
  const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
  function app(kind: Kind) {
    const seen: string[] = [];
    const f: FetchFn = async (url, init) => {
      const path = new URL(url).pathname;
      const who = init.headers.Authorization === "Bearer admin" ? "admin" : init.headers.Authorization === "Bearer a" ? "a" : "anon";
      seen.push(`${who} ${init.method} ${path}`);
      if (kind === "shell") return json({ users: USERS });   // the same answer to everyone, for every path
      if (path !== "/api/admin/users") return json({ error: "not found" }, 404);
      if (who === "anon") return kind === "open_to_signed_out" ? json({ users: USERS }) : json({ error: "unauthorized" }, 401);
      if (kind === "shared_values") return json(SETTINGS);
      if (who === "admin") return json({ users: USERS });
      if (kind === "open" || kind === "open_to_signed_out") return json({ users: USERS });
      if (kind === "own_record") return json({ users: [USERS[2]] });
      return json({ error: "forbidden" }, 403);
    };
    return { f, seen };
  }
  const run = (kind: Kind, admin = true) => { const a = app(kind); return runAttack({ cfg: cfg(admin), proof, mode: "light", env, fetch: a.f, sleep: async () => {}, groups: ["rbac"] }).then((r) => ({ r, seen: a.seen })); };

  it("a member who gets the admin's list of users (the Juice Shop /api/Users case) is a finding, and says which proof", async () => {
    const { r, seen } = await run("open");
    expect(r.findings.map((f) => [f.ruleId, f.route, f.as, f.meta.proof])).toEqual([["attack.rbac_escalation", "/api/admin/users", "a", "identifying data on a declared admin route"]]);
    expect(r.review).toEqual([]);
    expect(r.findings[0]!.evidence).toMatch(/^a member got the admin answer: a JSON object with 1 field \(users\), \d+ characters$/);
    expect(JSON.stringify(r.findings)).not.toMatch(/alice|bob|usr_100/i);
    // the signed-out control was asked, and the member was asked again
    expect(seen).toContain("anon GET /api/admin/users");
    expect(seen.filter((x) => x === "a GET /api/admin/users").length).toBeGreaterThanOrEqual(2);
    expect(seen.every((x) => x.includes(" GET "))).toBe(true);
  });
  it("values every account shares (a plan, roles, a count, a date, a flag, an empty list) are never a finding", async () => {
    const { r } = await run("shared_values");
    expect(r.findings).toEqual([]);
    expect(r.review.map((v) => [v.ruleId, v.route])).toEqual([["attack.rbac_escalation", "/api/admin/users"]]);
    expect(othersIdentifying(JSON.stringify(SETTINGS), JSON.stringify(SETTINGS))).toEqual([]);
  });
  it("an app that answers 200 to everyone is not a finding: the signed-out control must be refused differently", async () => {
    for (const kind of ["shell", "open_to_signed_out"] as const) {
      const { r } = await run(kind);
      expect(r.findings, kind).toEqual([]);
    }
  });
  it("a member who sees only its own record is not a finding", async () => {
    const { r } = await run("own_record");
    expect(r.findings).toEqual([]);
    expect(r.review).toHaveLength(1);
    expect(othersIdentifying(JSON.stringify({ users: USERS }), JSON.stringify({ users: [USERS[2]] }))).toEqual([]);
    // when the member's own sign-in address is known, somebody else's single record does count
    expect(othersIdentifying(JSON.stringify({ users: USERS }), JSON.stringify({ users: [USERS[0]] }), ["mem@example.com"])).toEqual(["email=alice@example.com"]);
    expect(othersIdentifying(JSON.stringify({ users: USERS }), JSON.stringify({ users: [USERS[2]] }), ["mem@example.com"])).toEqual([]);
  });
  it("with no admin account there is nothing the values could be the admin's: needs validation; a closed route is neither", async () => {
    const none = await run("open", false);
    expect(none.r.findings).toEqual([]);
    expect(none.r.review).toHaveLength(1);
    const closed = await run("closed");
    expect(closed.r.findings).toEqual([]);
    expect(closed.r.review).toEqual([]);
  });
  it("the values must be in the admin's answer too", () => {
    expect(othersIdentifying(JSON.stringify({ users: USERS.slice(0, 1) }), JSON.stringify({ users: [{ id: "usr_9001", email: "x@example.com" }, { id: "usr_9002", email: "y@example.com" }] }))).toEqual([]);
    expect(othersIdentifying(JSON.stringify({ users: USERS }), JSON.stringify({ users: USERS.slice(0, 2) })).length).toBeGreaterThanOrEqual(2);
  });
});
