/**
 * yof engagement, open core: the verifier (src/attack/engage/verifier.ts).
 *   1. it is handed the replay spec only, signs in again, plants a NEW marker, and runs the chain in its own order
 *      (the other role first, then the owner, then the controls);
 *   2. every refutation rule, each on an app built to trip exactly that rule;
 *   3. what it cannot tell stays undecided (never confirmed), and says why;
 *   4. it deletes exactly what it planted, whatever happened.
 */
import { describe, expect, it } from "vitest";
import { consentText } from "../src/attack/catalog";
import { parseAttackConfig } from "../src/attack/config";
import type { ReplaySpec } from "../src/attack/replay";
import { factsFromConfig } from "../src/attack/engage/command";
import { differentialSpec, finalVerdict } from "../src/attack/engage/differential";
import { MarkerRegistry, type EngageIo } from "../src/attack/engage/markers";
import { REFUTATION_RULES, cacheSaysHit, decideVerification, markedPublic, sameTenant, specLegs, verifySpec, type Observations, type VerifierFacts } from "../src/attack/engage/verifier";
import { NOTE_OBJECT, counterRandom, notesApp, type NotesFlaws } from "./engage-helpers";

const VNONCE = "VRFYNNCEABCD";
const VM = `YOF-MRK-${VNONCE}-A-1`;
const SPEC = differentialSpec({ ruleId: "attack.tenant_read", title: "One user can read another user's records by changing the id", owner: "a", other: "b", object: NOTE_OBJECT }, {});
const verify = async (flaws: NotesFlaws, opts: { spec?: ReplaySpec; facts?: VerifierFacts; io?: (io: EngageIo) => EngageIo } = {}) => {
  const app = notesApp(flaws);
  const registry = new MarkerRegistry(VNONCE);
  let sessions = 0;
  const result = await verifySpec(opts.spec ?? SPEC, opts.io ? opts.io(app.io) : app.io, { registry, random: counterRandom, facts: opts.facts, newSessions: () => { sessions++; } });
  return { app, registry, result, sessions, sent: app.requests.map((q) => `${q.as} ${q.method} ${q.path}`) };
};

describe("1. a separate pass", () => {
  it("takes the spec, an io and its own tools: there is no place for the finder's conclusion", () => {
    expect(verifySpec.length).toBe(3);
    expect(Object.keys(SPEC).sort()).toEqual(["accounts", "ruleId", "steps", "title", "vars"]);
  });
  it("new sessions, a new marker, and its own order: the other role asks BEFORE the owner has read the new record", async () => {
    const { result, sent, sessions, app } = await verify({ leak: true });
    expect(result).toMatchObject({ stands: true, refutedBy: null, undecided: null, marker: VM });
    expect(sessions).toBe(1);
    expect(sent.slice(0, 4)).toEqual(["a POST /api/notes", "b GET /api/notes/n1", "a GET /api/notes/n1", "b GET /api/notes/n1"]);
    expect(sent[4]).toMatch(/^b GET \/api\/notes\/yofnone[0-9a-f]+$/);
    // then the clean-up: a look at its own record, and the delete
    expect(sent.slice(5)).toEqual(["a GET /api/notes/n1", "a DELETE /api/notes/n1"]);
    expect(app.requests[0]!.body).toBe(`{"title":"${VM}"}`);
    expect(app.notes.size).toBe(0);
    expect(result.cleanup).toEqual({ planted: 1, deleted: 1, left: [] });
    expect(finalVerdict("proven", result)).toBe("confirmed");
  });
});

describe("2. every refutation rule", () => {
  it("has exactly these six rules", () => {
    expect([...REFUTATION_RULES].sort()).toEqual(["cache_served", "marked_public", "marker_reflected", "negative_control_failed", "not_reproduced", "same_tenant"]);
  });
  it("marker_reflected: the test request itself carries the marker; nothing is sent", async () => {
    const spec: ReplaySpec = { ...SPEC, steps: [SPEC.steps[0]!, { as: "b", method: "GET", path: "/api/search?q={{marker}}", leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } }, SPEC.steps[3]!] };
    const { result, sent } = await verify({}, { spec });
    expect(result).toMatchObject({ stands: false, refutedBy: "marker_reflected", marker: null });
    expect(sent).toEqual([]);
    const inHeader: ReplaySpec = { ...SPEC, steps: [SPEC.steps[0]!, { as: "b", method: "GET", path: "/api/notes/{{id}}", headers: { "X-Note": "{{marker}}" }, expect: { kind: "not_contains", value: "{{marker}}" } }, SPEC.steps[3]!] };
    expect((await verify({}, { spec: inHeader })).result.refutedBy).toBe("marker_reflected");
  });
  it("same_tenant: the two accounts share a tenant; nothing is sent", async () => {
    const { result, sent } = await verify({ leak: true }, { facts: { tenants: { a: "acme", b: "acme" } } });
    expect(result).toMatchObject({ stands: false, refutedBy: "same_tenant" });
    expect(sent).toEqual([]);
    expect(sameTenant({ tenants: { a: "acme" } }, "a", "b")).toBe(false);   // unknown is not "the same"
    // the config's own word: the viewer is a member of account A's tenant, B is a second tenant
    const APP = "shop.example.com";
    const cfg = parseAttackConfig(JSON.stringify({ app: APP, consent: consentText(APP), accounts: { a: { env: "YOF_ATTACK_A" }, b: { env: "YOF_ATTACK_B" }, viewer: { env: "YOF_ATTACK_V" } } }));
    const facts = factsFromConfig(cfg);
    expect(sameTenant(facts, "a", "viewer")).toBe(true);
    expect(sameTenant(facts, "a", "b")).toBe(false);
    const viewerSpec = differentialSpec({ ruleId: "attack.tenant_read", title: "t", owner: "a", other: "viewer", object: NOTE_OBJECT }, {});
    expect((await verify({ leak: true }, { spec: viewerSpec, facts })).result.refutedBy).toBe("same_tenant");
  });
  it("marked_public: the customer marked the object public on purpose; nothing is sent", async () => {
    const { result, sent } = await verify({ leak: true }, { facts: { publicRoutes: ["/api/notes/{id}"] } });
    expect(result).toMatchObject({ stands: false, refutedBy: "marked_public" });
    expect(sent).toEqual([]);
    expect(markedPublic({ publicRoutes: ["/api/other/{id}"] }, { path: "/api/notes/{{id}}" }, "id")).toBe(false);
  });
  it("cache_served: the other role sees the marker only after the owner's read, and not with a cache-buster", async () => {
    const { result, sent, app } = await verify({ cache: true });
    expect(result).toMatchObject({ stands: false, refutedBy: "cache_served" });
    expect(sent.slice(0, 4)).toEqual(["a POST /api/notes", "b GET /api/notes/n1", "a GET /api/notes/n1", "b GET /api/notes/n1"]);
    expect(sent[4]).toMatch(/^b GET \/api\/notes\/n1\?yofcb=[0-9a-f]+$/);
    expect(app.notes.size).toBe(0);
  });
  it("negative_control_failed: the app answers 200 for an id that does not exist", async () => {
    const { result, app } = await verify({ leak: true, softMissing: true });
    expect(result).toMatchObject({ stands: false, refutedBy: "negative_control_failed" });
    expect(app.notes.size).toBe(0);
  });
  it("not_reproduced: with a new record and a new marker the other role sees nothing", async () => {
    const { result, app } = await verify({});
    expect(result).toMatchObject({ stands: false, refutedBy: "not_reproduced" });
    expect(app.notes.size).toBe(0);
    expect(finalVerdict("proven", result)).toBe("rejected");
  });
});

describe("2b. the decision over what was seen, as a pure rule", () => {
  const M = "YOF-MRK-AAAAAAAAAAAA-A-1";
  const yes = { status: 200, body: `{"title":"${M}"}`, cacheHit: false };
  const no = { status: 404, body: '{"error":"not found"}', cacheHit: false };
  const o = (over: Partial<Observations>): Observations => ({ marker: M, first: yes, positive: yes, negative: no, second: yes, busted: null, ...over });
  it("stands only with both controls and two sightings", () => {
    expect(decideVerification(o({}))).toEqual({ stands: true, notes: [] });
    expect(decideVerification(o({ second: no }))).toMatchObject({ stands: false, refutedBy: "not_reproduced" });
    expect(decideVerification(o({ negative: yes }))).toMatchObject({ stands: false, refutedBy: "negative_control_failed" });
    expect(decideVerification(o({ negative: null }))).toMatchObject({ stands: null, undecided: "no_answer" });
    expect(decideVerification(o({ positive: no }))).toMatchObject({ stands: null, undecided: "positive_control_failed" });
    expect(decideVerification(o({ first: { ...yes, status: 429 } }))).toMatchObject({ stands: null, undecided: "no_answer" });
    expect(decideVerification(o({ first: null }))).toMatchObject({ stands: null, undecided: "no_answer" });
  });
  it("seen only after the owner's read: a cache, unless a cache-busted request shows it too", () => {
    expect(decideVerification(o({ first: no, busted: no }))).toMatchObject({ stands: false, refutedBy: "cache_served" });
    expect(decideVerification(o({ first: no, busted: null }))).toMatchObject({ stands: false, refutedBy: "cache_served" });
    expect(decideVerification(o({ first: no, busted: { ...yes, cacheHit: true } }))).toMatchObject({ stands: false, refutedBy: "cache_served" });
    expect(decideVerification(o({ first: no, second: { ...yes, cacheHit: true }, busted: yes }))).toMatchObject({ stands: false, refutedBy: "cache_served" });
    const d = decideVerification(o({ first: no, busted: yes }));
    expect(d.stands).toBe(true);
    expect(d.notes[0]).toContain("only after the owner had read the record");
  });
  it("reads the cache headers", () => {
    const h = (o2: Record<string, string>) => (n: string) => o2[n] ?? null;
    expect(cacheSaysHit(h({ age: "12" }))).toBe(true);
    expect(cacheSaysHit(h({ age: "0" }))).toBe(false);
    expect(cacheSaysHit(h({ "x-cache": "HIT from edge" }))).toBe(true);
    expect(cacheSaysHit(h({ "x-cache": "MISS" }))).toBe(false);
    expect(cacheSaysHit(h({ "cf-cache-status": "HIT" }))).toBe(true);
    expect(cacheSaysHit(h({ "cf-cache-status": "DYNAMIC" }))).toBe(false);
    expect(cacheSaysHit(h({}))).toBe(false);
  });
});

describe("3. undecided is never confirmed", () => {
  it("a spec that plants no marker cannot be verified", async () => {
    const spec: ReplaySpec = { ruleId: "attack.rbac_escalation", title: "t", vars: [], accounts: {}, steps: [{ as: "a", method: "GET", path: "/api/admin/users", expect: { kind: "denied" } }] };
    const { result, sent } = await verify({ leak: true }, { spec });
    expect(result).toMatchObject({ stands: null, undecided: "no_marker", refutedBy: null });
    expect(sent).toEqual([]);
    expect(finalVerdict("proven", result)).toBe("needs_validation");
  });
  it("a write differential, or a spec that could not clean up after itself, is not supported yet and plants nothing", async () => {
    const write: ReplaySpec = { ruleId: "attack.tenant_write", title: "t", vars: ["marker", "change"], accounts: {}, steps: [
      SPEC.steps[0]!, { as: "b", method: "PATCH", path: "/api/notes/{{id}}", body: '{"title":"{{change}}"}' },
      { as: "a", method: "GET", path: "/api/notes/{{id}}", expect: { kind: "not_contains", value: "{{change}}" } }, SPEC.steps[3]!] };
    expect(specLegs(write)).toEqual({ undecided: "not_supported" });
    const noCleanup: ReplaySpec = { ...SPEC, steps: SPEC.steps.slice(0, 3) };
    const { result, sent } = await verify({ leak: true }, { spec: noCleanup });
    expect(result).toMatchObject({ stands: null, undecided: "not_supported" });
    expect(sent).toEqual([]);
  });
  it("a missing account, a failed setup, a blind owner, an app that says slow down: each undecided, each cleaned up", async () => {
    const noB = await verify({ leak: true }, { io: (io) => ({ ...io, send: (as, m, p, i) => (as === "b" ? Promise.resolve(null) : io.send(as, m, p, i)) }) });
    expect(noB.result).toMatchObject({ stands: null, undecided: "no_account" });
    expect(noB.app.notes.size).toBe(0);
    const noCreate = await verify({ leak: true }, { io: (io) => ({ ...io, send: async (as, m, p, i) => (m === "POST" ? { status: 500, body: "{}", headers: new Headers(), location: null } : io.send(as, m, p, i)) }) });
    expect(noCreate.result).toMatchObject({ stands: null, undecided: "setup_failed" });
    const blind = await verify({ ownerBlind: true });
    expect(blind.result).toMatchObject({ stands: null, undecided: "positive_control_failed" });
    expect(blind.result.cleanup.planted).toBe(1);
    const slow = await verify({ leak: true, slowDown: true });
    expect(slow.result).toMatchObject({ stands: null, undecided: "no_answer" });
    for (const r of [noB, noCreate, blind, slow]) expect(finalVerdict("proven", r.result)).toBe("needs_validation");
  });
  it("a path the rules forbid: nothing is planted", async () => {
    const { result, sent } = await verify({ leak: true }, { io: (io) => ({ ...io, pathAllowed: (p) => !p.startsWith("/api/notes") }) });
    expect(result).toMatchObject({ stands: null, undecided: "not_supported" });
    expect(sent).toEqual([]);
  });
});
