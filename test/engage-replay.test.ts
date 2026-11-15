/**
 * yof engagement, open core: the new expectation kinds, stored specs, the evidence bundle and the commands.
 *   1. marker_absent, marker_present, count_at_most and canary_hit in the generated test's engine (the same code a
 *      customer's regression test carries), and in the Python twin; every older spec stays valid;
 *   2. a spec from a file is read strictly, and its accounts are dropped (they come from the config);
 *   3. the same spec run through the governor's io gives the same answer as the generated test;
 *   4. the evidence bundle: masked exchanges, marker ids kept whole, the replay spec, a hash;
 *   5. the commands: --roe, replay, verify, stop, --engage. A run from the command line is always the owner's own.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { parseAttackConfig } from "../src/attack/config";
import { proveTarget } from "../src/attack/proof";
import { PY_ENGINE, detectFramework, synthesizeTest } from "../src/attack/regression";
import { REPLAY_ENGINE_JS, type ReplaySpec } from "../src/attack/replay";
import { runAttack } from "../src/attack/runner";
import { ENGAGE_NOT_AVAILABLE, STOP_FILE, attackStop, stopAskedAt, stopWatch } from "../src/attack/engage/command";
import { differentialSpec } from "../src/attack/engage/differential";
import { buildEvidenceBundle, bundleHash, bundleIntact, maskKeepingMarkers, recordingIo } from "../src/attack/engage/evidence";
import { MarkerRegistry, plantMarker } from "../src/attack/engage/markers";
import { parseReplaySpec, runSpec, specFromFile } from "../src/attack/engage/spec";
import { main } from "../src/cli";
import { fakeConfig, fakeEnv, startFakeApp, type FakeApp } from "./fake-app";
import { NOTE_OBJECT, TOKEN, counterRandom, notesApp, readId, type NotesFlaws } from "./engage-helpers";

const ACCOUNTS = { a: { headers: [{ header: "Authorization", env: "YOF_ATTACK_A" }] }, b: { headers: [{ header: "Authorization", env: "YOF_ATTACK_B" }] } };
const SPEC = differentialSpec({ ruleId: "attack.tenant_read", title: "One user can read another user's records by changing the id", owner: "a", other: "b", object: NOTE_OBJECT }, ACCOUNTS);
const ENV = { YOF_ATTACK_TARGET: "http://app.test", YOF_ATTACK_A: TOKEN.a, YOF_ATTACK_B: TOKEN.b };
// The engine exactly as a generated regression test carries it.
const yofReplay = new Function(`${REPLAY_ENGINE_JS}\nreturn yofReplay;`)() as (spec: ReplaySpec, env: Record<string, string>) => Promise<string[]>;

/** Serve the in-memory notes app (and a canary counter) through global fetch, as the generated test would reach it. */
function serve(flaws: NotesFlaws, canaryHits: number | null = 0) {
  const app = notesApp(flaws);
  vi.stubGlobal("fetch", async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
    const u = new URL(url);
    if (u.host === "canary.test") return canaryHits === null ? new Response("down", { status: 500 }) : Response.json({ hits: canaryHits });
    const as = (Object.keys(TOKEN) as (keyof typeof TOKEN)[]).find((r) => TOKEN[r] === init.headers?.Authorization) ?? "anon";
    const r = app.handle(as, (init.method ?? "GET") as "GET", `${u.pathname}${u.search}`, init.body);
    return new Response(r.status === 204 ? null : r.body, { status: r.status, headers: { "Content-Type": "application/json" } });
  });
  return app;
}
afterEach(() => { vi.unstubAllGlobals(); });

describe("1. the new expectation kinds, in the generated test's own engine", () => {
  it("marker_absent fails while another account sees the planted record, and passes once it is refused", async () => {
    const bad = serve({ leak: true });
    expect(await yofReplay(SPEC, ENV)).toEqual(["GET /api/notes/{{id}} as b returned another account's test record"]);
    expect(bad.notes.size).toBe(0);   // the test deleted its own record
    serve({});
    expect(await yofReplay(SPEC, ENV)).toEqual([]);
  });
  it("marker_present is the positive control: when the owner cannot see its own record the test says it shows nothing", async () => {
    serve({ ownerBlind: true });
    expect(await yofReplay(SPEC, ENV)).toEqual(["GET /api/notes/{{id}} as a did not return the account's own test record (HTTP 200), so the test shows nothing"]);
  });
  it("count_at_most counts the successes across the repeats", async () => {
    const spec = (max: number): ReplaySpec => ({ ruleId: "attack.single_use", title: "t", vars: ["marker"], accounts: ACCOUNTS, steps: [{ as: "a", method: "POST", path: "/api/notes", body: '{"title":"{{marker}}"}', repeat: 3, expect: { kind: "count_at_most", max } }] });
    serve({});
    expect(await yofReplay(spec(1), ENV)).toEqual(["POST /api/notes as a succeeded 3 times, at most 1 allowed"]);
    expect(await yofReplay(spec(3), ENV)).toEqual([]);
  });
  it("canary_hit: checked through YOF_CANARY_CHECK_URL, and never passed unchecked", async () => {
    const spec: ReplaySpec = { ruleId: "attack.ssrf", title: "t", vars: ["canary"], accounts: ACCOUNTS, steps: [{ as: "a", method: "GET", path: "/api/notes/n1", expect: { kind: "canary_hit", token: "{{canary}}" } }] };
    serve({}, 0);
    expect(await yofReplay(spec, ENV)).toEqual(["GET /api/notes/n1 as a could not be checked: set YOF_CANARY_CHECK_URL"]);
    expect(await yofReplay(spec, { ...ENV, YOF_CANARY_CHECK_URL: "http://canary.test/check" })).toEqual([]);
    serve({}, 2);
    expect(await yofReplay(spec, { ...ENV, YOF_CANARY_CHECK_URL: "http://canary.test/check" })).toEqual(["GET /api/notes/n1 as a made the app call the canary address"]);
    serve({}, null);
    expect(await yofReplay(spec, { ...ENV, YOF_CANARY_CHECK_URL: "http://canary.test/check" })).toEqual(["GET /api/notes/n1 as a could not be checked: the canary address did not answer"]);
  });
  it("the Python twin and every generated file carry the same four kinds", () => {
    for (const kind of ["marker_absent", "marker_present", "count_at_most", "canary_hit"]) {
      expect(PY_ENGINE, kind).toContain(`k == "${kind}"`);
      expect(REPLAY_ENGINE_JS, kind).toContain(`e.kind === "${kind}"`);
    }
    for (const framework of ["vitest", "jest", "playwright", "pytest", "generic"] as const) {
      const t = synthesizeTest(SPEC, { method: "GET", route: "/api/notes/{id}" }, { framework, dir: "t" });
      expect(t.content, framework).toContain("marker_absent");
      expect(t.content, framework).toContain("marker_present");
      expect(t.content, framework).not.toContain("YOF-MRK-");
    }
    expect(detectFramework({ read: () => null, exists: () => false }).framework).toBe("generic");
  });
  it("a spec written before these kinds existed is still valid and still runs", async () => {
    const old: ReplaySpec = { ruleId: "attack.tenant_read", title: "t", vars: ["marker"], accounts: ACCOUNTS, steps: [
      { as: "a", method: "POST", path: "/api/notes", body: '{"title":"{{marker}}"}', save: { name: "id", from: "id" }, setup: true },
      { as: "b", method: "GET", path: "/api/notes/{{id}}", expect: { kind: "not_contains", value: "{{marker}}" } },
      { as: "a", method: "DELETE", path: "/api/notes/{{id}}", cleanup: true }] };
    serve({ leak: true });
    expect(await yofReplay(old, ENV)).toEqual(["GET /api/notes/{{id}} as b returned data it must not return"]);
    expect(parseReplaySpec(JSON.parse(JSON.stringify(old)))).toMatchObject({ ok: true });
  });
});

describe("2. a spec from a file is read strictly", () => {
  const good = () => JSON.parse(JSON.stringify(SPEC)) as Record<string, unknown> & { steps: Record<string, unknown>[] };
  const why = (v: unknown) => { const r = parseReplaySpec(v); return r.ok ? "ok" : (r as { why: string }).why; };
  it("accepts the known shape and drops the accounts: sign-in details come from the config only", () => {
    const r = parseReplaySpec({ ...good(), accounts: { a: { headers: [{ header: "Authorization", env: "GITHUB_TOKEN" }] } }, verdict: "confirmed" });
    expect(r.ok).toBe(true);
    const spec = (r as { spec: ReplaySpec }).spec;
    expect(spec.accounts).toEqual({});
    expect(JSON.stringify(spec)).not.toMatch(/GITHUB_TOKEN|confirmed/);
    expect(spec.steps).toEqual(SPEC.steps);
  });
  it("refuses another host, an unknown method or kind, credentials in a header, and anything oversized", () => {
    const withStep = (patch: Record<string, unknown>) => { const s = good(); s.steps[1] = { ...s.steps[1], ...patch }; return s; };
    expect(why(withStep({ path: "https://evil.example/x" }))).toContain("path on the app");
    expect(why(withStep({ path: "//evil.example/x" }))).toContain("path on the app");
    expect(why(withStep({ path: "/api/../admin" }))).toContain("path on the app");
    expect(why(withStep({ method: "TRACE" }))).toContain("unknown method");
    expect(why(withStep({ as: "root" }))).toContain("unknown role");
    expect(why(withStep({ expect: { kind: "always_pass" } }))).toContain("unknown expectation");
    expect(why(withStep({ headers: { Cookie: "session=abc" } }))).toContain("not allowed");
    expect(why(withStep({ headers: { Authorization: "Bearer real-token" } }))).toContain("not allowed");
    expect(why(withStep({ headers: { Authorization: "Bearer undefined" } }))).toBe("ok");   // the recorded broken-token probe
    expect(why(withStep({ repeat: 500 }))).toContain("repeat");
    expect(why(withStep({ leg: "anything" }))).toContain("unknown leg");
    expect(why({ ...good(), steps: Array.from({ length: 41 }, () => good().steps[1]) })).toContain("between 1 and 40");
    expect(why({ ...good(), vars: ["a b"] })).toContain("vars");
    expect(why("spec")).toContain("object");
  });
  it("finds the spec in a finding, a bundle or a report; a report with several findings needs one named", () => {
    expect(specFromFile({ ruleId: "attack.tenant_read", replay: good() }).ok).toBe(true);
    expect(specFromFile(good()).ok).toBe(true);
    const report = { findings: [{ replay: good() }, { replay: { ...good(), ruleId: "attack.tenant_write" } }] };
    expect(specFromFile(report)).toMatchObject({ ok: false, why: expect.stringContaining("--finding 1 to 2") });
    expect(specFromFile(report, 2)).toMatchObject({ ok: true, spec: { ruleId: "attack.tenant_write" } });
    expect(specFromFile(report, 3).ok).toBe(false);
    expect(specFromFile({ findings: [] })).toMatchObject({ ok: false });
  });
});

describe("3. the same spec through the governor's io", () => {
  it("gives the same answers as the generated test, owns what it creates and cleans up", async () => {
    const bad = notesApp({ leak: true });
    const r = await runSpec(SPEC, bad.io, { random: counterRandom });
    expect(r.failures).toEqual(["GET /api/notes/{{id}} as b returned another account's test record"]);
    expect(r.incomplete).toBeNull();
    expect(bad.owned).toEqual(["n1"]);
    expect(bad.notes.size).toBe(0);
    expect(r.steps.map((s) => [s.step, s.leg, s.statuses])).toEqual([[1, "plant", [201]], [2, "test", [200]], [3, "positive", [200]], [4, "cleanup", [204]]]);
    const good = await runSpec(SPEC, notesApp({}).io, { random: counterRandom });
    expect(good.failures).toEqual([]);
    const blind = await runSpec(SPEC, notesApp({ ownerBlind: true }).io, { random: counterRandom });
    expect(blind.failures).toEqual(["GET /api/notes/{{id}} as a did not return the account's own test record (HTTP 200), so the test shows nothing"]);
  });
  it("a missing account or a failed setup is incomplete, never a pass", async () => {
    const app = notesApp({ leak: true });
    const noB = await runSpec(SPEC, { ...app.io, send: (as, m, p, i) => (as === "b" ? Promise.resolve(null) : app.io.send(as, m, p, i)) }, { random: counterRandom });
    expect(noB.incomplete).toContain("account b is not set");
    expect(app.notes.size).toBe(0);
    const down = await runSpec(SPEC, { ...app.io, send: async () => ({ status: 500, body: "", headers: new Headers(), location: null }) }, { random: counterRandom });
    expect(down.incomplete).toBe("Setup step POST /api/notes as a answered HTTP 500.");
    const canary: ReplaySpec = { ruleId: "attack.ssrf", title: "t", vars: ["canary"], accounts: {}, steps: [{ as: "a", method: "GET", path: "/", expect: { kind: "canary_hit", token: "{{canary}}" } }] };
    expect((await runSpec(canary, app.io, { random: counterRandom })).failures).toEqual(["GET / as a could not be checked: no canary address is set"]);
    expect((await runSpec(canary, app.io, { random: counterRandom, canaryHits: async () => 1 })).failures).toEqual(["GET / as a made the app call the canary address"]);
    expect((await runSpec(canary, app.io, { random: counterRandom, canaryHits: async () => 0 })).failures).toEqual([]);
  });
});

describe("4. the evidence bundle", () => {
  it("masks what is not the run's own, keeps the marker ids whole, and never keeps an answer's text", async () => {
    const app = notesApp({ leak: true });
    app.handle("b", "POST", "/api/notes", '{"title":"Dinner with Jo Example, call +44 20 7946 0958"}');
    const rec = recordingIo(app.io);
    const reg = new MarkerRegistry("QWHRTPLKXZMB");
    const key = ["sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2"].join("_");
    const planted = await plantMarker(rec.io, reg, "a", { ...NOTE_OBJECT, create: { path: "/api/notes", body: `{"title":"{{marker}}","owner":"dee@example.com","phone":"+44 20 7946 0958","key":"${key}"}` } }, readId);
    expect(planted.ok).toBe(true);
    await rec.io.send("b", "GET", "/api/notes/n1", { leg: "test" });   // account B's own real note
    await rec.io.send("b", "GET", "/api/notes/n2", { headers: { Authorization: "Bearer b", "X-Workspace-Id": "ws_1" }, leg: "test" });   // A's planted record
    const [create, other, own] = rec.exchanges;
    expect(create).toMatchObject({ n: 1, as: "a", method: "POST", path: "/api/notes", leg: "plant", status: 201 });
    expect(create!.request.body).toContain("YOF-MRK-QWHRTPLKXZMB-A-1");
    expect(create!.request.body).toContain("d•••@example.com");
    expect(create!.request.body).not.toMatch(/dee@example\.com|7946 0958|A1b2C3d4E5f6G7h8I9j0K1l2/);
    expect(own!.request).toEqual({ headers: ["authorization", "x-workspace-id"], body: null });
    expect(own!.answer).toEqual({ shape: expect.stringMatching(/^a JSON object with 2 fields \(id, title\), \d+ characters$/), markers: ["YOF-MRK-QWHRTPLKXZMB-A-1"], headers: {} });
    // account B's own real note went through the recorder: nothing of its text is kept
    expect(other!.answer.markers).toEqual([]);
    const text = JSON.stringify(rec.exchanges);
    expect(text).not.toMatch(/Dinner|Jo Example|7946|Bearer b|ws_1/);
  });
  it("the bundle carries the markers, the spec and a hash over all of it", async () => {
    const app = notesApp({ leak: true });
    const rec = recordingIo(app.io);
    await rec.io.send("b", "GET", "/api/notes/n1", { leg: "test" });
    const input = { ruleId: "attack.tenant_read", reportedBy: "owner_run" as const, runNonce: "QWHRTPLKXZMB", createdAt: "2026-11-12T02:00:00.000Z", markers: ["YOF-MRK-QWHRTPLKXZMB-A-1"], exchanges: rec.exchanges, replay: SPEC };
    const b = buildEvidenceBundle(input);
    expect(b).toMatchObject({ schema: 1, rule_id: "attack.tenant_read", reported_by: "owner_run", run_nonce: "QWHRTPLKXZMB", markers: ["YOF-MRK-QWHRTPLKXZMB-A-1"], replay: SPEC, verifier: null });
    expect(b.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(buildEvidenceBundle(input).hash).toBe(b.hash);
    expect(bundleIntact(b)).toBe(true);
    expect(bundleIntact({ ...b, exchanges: [{ ...b.exchanges[0]!, status: 200 }] })).toBe(false);
    expect(bundleIntact({ ...b, markers: [] })).toBe(false);
    expect(bundleHash({ ...b, verifier: { stands: true, refuted_by: null, undecided: null, notes: [] } })).not.toBe(b.hash);
    expect(JSON.stringify(b)).not.toMatch(/Bearer|password/i);
  });
  it("maskKeepingMarkers: emails, long numbers and keys go, markers stay", () => {
    const m = "YOF-MRK-QWHRTPLKXZMB-ADMIN-12";
    expect(maskKeepingMarkers(`to dee@example.com ${m} card 4111 1111 1111 1111 ${m}`)).toBe(`to d•••@example.com ${m} card •••11 ${m}`);
    expect(maskKeepingMarkers("word ".repeat(300))).toHaveLength(500);
  });
});

describe("5. the commands", () => {
  let bad: FakeApp, good: FakeApp, dir: string, finding: string;
  const signals = { on() {}, off() {}, exit() {}, err() {} };
  const cli = async (argv: string[], extra: Record<string, unknown> = {}) => {
    const out: string[] = [], err: string[] = [];
    const code = await main(argv, { cwd: dir, out: (s) => out.push(s), err: (s) => err.push(s), env: fakeEnv(), sleep: async () => {}, signals, ...extra });
    return { code, out: out.join("\n"), err: err.join("\n") };
  };
  beforeAll(async () => {
    bad = await startFakeApp(true); good = await startFakeApp(false);
    dir = mkdtempSync(join(tmpdir(), "yof-engage-"));
    mkdirSync(join(dir, ".yof"));
    writeFileSync(join(dir, ".yof/attack.json"), fakeConfig({ ai: [] }));
    const cfg = parseAttackConfig(fakeConfig({ ai: [] }));
    const proof = await proveTarget(bad.url, cfg, "full", { env: {} });
    if (!proof.ok) throw new Error(proof.message);
    const res = await runAttack({ cfg, proof, mode: "full", env: fakeEnv(), sleep: async () => {}, groups: ["tenant"] });
    const f = res.findings.find((x) => x.ruleId === "attack.tenant_read" && x.route === "/api/notes/{id}")!;
    finding = "finding.json";
    writeFileSync(join(dir, finding), JSON.stringify(f, null, 2));
  });
  afterAll(async () => { await bad.close(); await good.close(); });

  it("--roe prints the record and sends nothing", async () => {
    const r = await cli(["attack", "--roe"], { http: async (u: string) => { throw new Error(`unexpected request: ${u}`); } });
    expect(r.code).toBe(0);
    expect(r.out).toContain("# Rules of engagement: 127.0.0.1");
    expect(r.out).toContain('"forbidden_actions"');
    expect(r.out).toContain("not checked for this document");
    const light = await cli(["attack", "--roe", "--mode", "light"]);
    expect(light.out).toContain("| read |");
    expect(light.out).not.toMatch(/\| read, write_own_test_records/);
  });
  it("--engage says plainly that it is not available, and sends nothing", async () => {
    const r = await cli(["attack", "--engage", bad.url], { http: async (u: string) => { throw new Error(`unexpected request: ${u}`); } });
    expect(r.code).toBe(2);
    expect(r.err).toBe(ENGAGE_NOT_AVAILABLE);
    expect(r.err).toContain("not available yet");
    expect(r.err).toContain("Nothing was sent.");
  });
  it("replay: exit 1 while the attack still works, 0 once it is refused; the result is the owner's own run", async () => {
    const before = bad.notes.size;
    const r = await cli(["attack", "replay", finding, bad.url]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("The attack still works:");
    expect(r.out).toContain("reported by the owner (owner_run)");
    expect(r.out).toContain("Measured the app first: 20 reads");
    expect(bad.notes.size).toBe(before);
    const fixed = await cli(["attack", "replay", finding, good.url]);
    expect(fixed.code).toBe(0);
    expect(fixed.out).toContain("The attack no longer works");
    const j = await cli(["attack", "replay", finding, bad.url, "--json"]);
    const o = JSON.parse(j.out) as { reported_by: string; still_works: boolean; evidence: { reported_by: string; hash: string; exchanges: unknown[] }; governor: { baseline: { samples: number }; requests: number } };
    expect(o).toMatchObject({ reported_by: "owner_run", still_works: true, evidence: { reported_by: "owner_run" }, governor: { baseline: { samples: 20 } } });
    expect(o.evidence.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(o.governor.requests).toBeGreaterThanOrEqual(23);
    expect(j.out).not.toMatch(/tok-(a|b|admin|viewer)-123456/);
    expect(j.out).not.toContain("yof_run");
  });
  it("verify: exit 1 when the finding stands, 0 when it is refuted, with a new marker each time", async () => {
    const r = await cli(["attack", "verify", finding, bad.url, "--json"]);
    expect(r.code).toBe(1);
    const o = JSON.parse(r.out) as { verdict: string; reported_by: string; result: { marker: string; stands: boolean }; evidence: { markers: string[]; verifier: { stands: boolean } }; cleanup: { planted: number; deleted: number; left: unknown[] } };
    expect(o).toMatchObject({ verdict: "stands", reported_by: "owner_run", result: { stands: true }, evidence: { verifier: { stands: true } }, cleanup: { planted: 1, deleted: 1, left: [] } });
    expect(o.result.marker).toMatch(/^YOF-MRK-[A-Z]{12}-A-1$/);
    expect(o.evidence.markers).toEqual([o.result.marker]);
    const again = JSON.parse((await cli(["attack", "verify", finding, bad.url, "--json"])).out) as { result: { marker: string } };
    expect(again.result.marker).not.toBe(o.result.marker);
    expect(bad.notes.size).toBe(0);
    const fixed = await cli(["attack", "verify", finding, good.url]);
    expect(fixed.code).toBe(0);
    expect(fixed.out).toContain("The finding is refuted: it did not show again with a new record and a new marker.");
    expect(good.notes.size).toBe(0);
  });
  it("a read-only run cannot plant, so nothing is tested, and it says so (exit 2)", async () => {
    const before = bad.requests.length;
    const r = await cli(["attack", "verify", finding, bad.url, "--mode", "light"]);
    expect(r.code).toBe(2);
    expect(r.out).toContain("Not tested:");
    expect(bad.requests.slice(before).every((q) => q.method === "GET")).toBe(true);
  });
  it("a bad file or a wrong use is an error a person can act on", async () => {
    writeFileSync(join(dir, "broken.json"), "{ not json");
    expect((await cli(["attack", "replay", "broken.json", bad.url])).err).toBe("broken.json is not valid JSON.");
    expect((await cli(["attack", "replay", "missing.json", bad.url])).err).toBe("Could not read missing.json.");
    expect((await cli(["attack", "replay"])).err).toBe("Usage: yof attack replay <finding.json> [url]");
    expect((await cli(["attack", "verify", finding, bad.url, "--finding", "0"])).code).toBe(2);
    expect((await cli(["attack", "stop", "now"])).err).toBe("Usage: yof attack stop");
  });
  it("stop: asks the runs under way in this folder to stop; a run started later is not affected", async () => {
    const started = Date.now() - 5000;
    expect(stopAskedAt(dir)).toBeNull();
    expect(stopWatch(dir, started)()).toBe(false);
    const r = await cli(["attack", "stop"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Stop asked for");
    expect(JSON.parse(readFileSync(join(dir, STOP_FILE), "utf8"))).toMatchObject({ stop: true });
    expect(stopAskedAt(dir)).toBeGreaterThan(started);
    expect(stopWatch(dir, started)()).toBe(true);
    expect(stopWatch(dir, Date.now() + 60_000)()).toBe(false);
    expect(attackStop({ cwd: dir, now: () => Date.parse("2026-01-01T00:00:00Z") })).toContain("A run you start after this is not affected.");
    // a run started after the stop goes ahead
    expect((await cli(["attack", "replay", finding, good.url])).code).toBe(0);
  });
});
