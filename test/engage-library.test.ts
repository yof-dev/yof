/**
 * The attack library against a deliberately vulnerable fixture app and its safe twin (test/fixtures/vuln-app.ts).
 * Every technique here is run twice: a TRUE HIT on the vulnerable app, and SILENCE on the twin. A hit is a result
 * the oracle demonstrated or that needs validation; silence is a held, not-testable or not-tested result. This is the
 * seed of the benchmark (benchmark/targets.ts marks the same expectations "not yet run").
 *
 * The session-bound techniques (csrf, the JWT and sign-out checks, the token-shape crypto observations) need a cookie
 * or signed-token session the in-memory fixture does not model; they keep their own unit tests in the engage core and
 * are covered there, so they are not re-run here. SSRF is asserted to refuse the fixture's local http canary, which is
 * the correct safety behaviour (a real run uses the public https canary).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MarkerRegistry } from "../src/attack/engage/markers";
import { ACCESS_TECHNIQUES } from "../src/attack/engage/library/access";
import { MASS_ASSIGN_TECHNIQUES } from "../src/attack/engage/library/mass-assign";
import { INJECTION_TECHNIQUES } from "../src/attack/engage/library/injection";
import { LOGIC_TECHNIQUES } from "../src/attack/engage/library/logic";
import { RACE_TECHNIQUES } from "../src/attack/engage/library/race";
import { FILE_TECHNIQUES } from "../src/attack/engage/library/files";
import { SSRF_TECHNIQUES } from "../src/attack/engage/library/ssrf";
import { DESERIALIZATION_TECHNIQUES } from "../src/attack/engage/library/deserialization";
import { CRYPTO_TECHNIQUES } from "../src/attack/engage/library/crypto";
import { AI_TECHNIQUES } from "../src/attack/engage/library/ai";
import { ALL_TECHNIQUES, TECHNIQUE_BY_ID, techniquesFor, techniqueAllowed, runTechnique } from "../src/attack/engage/library";
import type { Outcome, Technique, TechniqueTarget } from "../src/attack/engage/library/types";
import { contextFor, ioFor, startVulnApp, type VulnServer } from "./fixtures/vuln-app";
import { roe } from "./engage-helpers";

const byId = (arr: readonly Technique[], id: string): Technique => arr.find((t) => t.id === id)!;

function target(): TechniqueTarget {
  return {
    object: {
      create: { path: "/api/notes", body: '{"title":"{{marker}}"}' },
      idPath: "id",
      read: "/api/notes/{id}",
      update: { method: "PATCH", path: "/api/notes/{id}", body: '{"title":"{{marker}}"}' },
      delete: "/api/notes/{id}",
      lockedFields: ["role", "is_admin"],
    },
    adminRoute: "/api/admin/notes",
    input: { request: { method: "GET", path: "/api/search?q={{value}}" }, searchesObject: true, as: "a" },
    numeric: { name: "quantity", request: { method: "PATCH", path: "/api/notes/{id}", body: '{"quantity":{{n}}}' }, readPath: "quantity", ok: 1, min: 1 },
    singleUse: { request: { method: "POST", path: "/api/notes/{id}/apply" }, bound: 1, effect: { readPath: "refunds", perUse: 1 } },
    upload: { path: "/api/upload", field: "file", idPath: "id", served: "/files/{id}", delete: "/api/uploads/{id}" },
    fetch: { request: { method: "POST", path: "/api/fetch", body: '{"url":"{{url}}"}' }, restricted: true, as: "a", canaryBase: "https://yof-canary.example.com" },
    ai: { path: "/api/assistant", body: '{"message":"{{message}}"}', replyPath: "reply", account: "a" },
  };
}

const HIT: Outcome[] = ["violated", "needs_validation"];
const SILENT: Outcome[] = ["held", "not_testable", "not_tested", "not_allowed", "blocked_not_tested"];

const run = async (t: Technique, v: VulnServer, tgt: TechniqueTarget, input?: TechniqueTarget["input"]) => {
  const io = ioFor(v.base);
  const registry = new MarkerRegistry();
  const ctx = contextFor(v, io, registry);
  return t.run(ctx, input ? { ...tgt, input } : tgt);
};

describe("the attack library on a vulnerable fixture and its twin", () => {
  let vuln: VulnServer;
  let twin: VulnServer;
  beforeAll(async () => { vuln = await startVulnApp(true); twin = await startVulnApp(false); });
  afterAll(async () => { await vuln.close(); await twin.close(); });

  const cases: { name: string; t: () => Technique; input?: TechniqueTarget["input"]; direct?: boolean }[] = [
    { name: "access.id_swap", t: () => byId(ACCESS_TECHNIQUES, "access.id_swap") },
    { name: "access.anon_read", t: () => byId(ACCESS_TECHNIQUES, "access.anon_read") },
    { name: "access.role_swap", t: () => byId(ACCESS_TECHNIQUES, "access.role_swap") },
    { name: "access.sequential_id", t: () => byId(ACCESS_TECHNIQUES, "access.sequential_id") },
    { name: "access.cross_write", t: () => byId(ACCESS_TECHNIQUES, "access.cross_write") },
    { name: "mass_assign.update", t: () => byId(MASS_ASSIGN_TECHNIQUES, "mass_assign.update") },
    { name: "mass_assign.create", t: () => byId(MASS_ASSIGN_TECHNIQUES, "mass_assign.create") },
    { name: "injection.sql_boolean", t: () => byId(INJECTION_TECHNIQUES, "injection.sql_boolean") },
    { name: "injection.sql_error", t: () => byId(INJECTION_TECHNIQUES, "injection.sql_error") },
    { name: "injection.template", t: () => byId(INJECTION_TECHNIQUES, "injection.template"), input: { request: { method: "POST", path: "/api/render", body: '{"value":"{{value}}"}' }, as: "a" } },
    { name: "injection.xss_reflected", t: () => byId(INJECTION_TECHNIQUES, "injection.xss_reflected"), input: { request: { method: "POST", path: "/api/render", body: '{"value":"{{value}}"}' }, as: "a" } },
    { name: "injection.command", t: () => byId(INJECTION_TECHNIQUES, "injection.command"), input: { request: { method: "POST", path: "/api/ping", body: '{"value":"{{value}}"}' }, as: "a" }, direct: true },
    { name: "logic.numeric_bound", t: () => byId(LOGIC_TECHNIQUES, "logic.numeric_bound") },
    { name: "logic.single_use", t: () => byId(LOGIC_TECHNIQUES, "logic.single_use") },
    { name: "race.parallel_use", t: () => byId(RACE_TECHNIQUES, "race.parallel_use") },
    { name: "files.content_mismatch", t: () => byId(FILE_TECHNIQUES, "files.content_mismatch") },
    { name: "deserial.object_stream", t: () => byId(DESERIALIZATION_TECHNIQUES, "deserial.object_stream"), input: { request: { method: "POST", path: "/api/import" }, as: "a" } },
    { name: "crypto.sequential_ids", t: () => byId(CRYPTO_TECHNIQUES, "crypto.sequential_ids") },
    { name: "ai.prompt_injection", t: () => byId(AI_TECHNIQUES, "ai.prompt_injection") },
    { name: "ai.prompt_extraction", t: () => byId(AI_TECHNIQUES, "ai.prompt_extraction") },
  ];

  for (const c of cases) {
    it(`${c.name}: hits the vulnerable app and stays silent on the twin`, async () => {
      const t = c.t();
      const onVuln = await run(t, vuln, target(), c.input);
      const onTwin = await run(t, twin, target(), c.input);
      expect(HIT, `${c.name} vulnerable -> ${onVuln.outcome} (${onVuln.reason})`).toContain(onVuln.outcome);
      expect(SILENT, `${c.name} twin -> ${onTwin.outcome} (${onTwin.reason})`).toContain(onTwin.outcome);
    });
  }

  it("ssrf refuses the fixture's local http canary (a real run uses the public https canary)", async () => {
    const t = byId(SSRF_TECHNIQUES, "ssrf.canary");
    const onVuln = await run(t, vuln, target());
    expect(onVuln.outcome).toBe("not_testable");
  });
});

describe("the registry", () => {
  it("has unique technique ids and a result for techniquesFor", () => {
    expect(new Set(ALL_TECHNIQUES.map((t) => t.id)).size).toBe(ALL_TECHNIQUES.length);
    expect(Object.keys(TECHNIQUE_BY_ID).length).toBe(ALL_TECHNIQUES.length);
    const { run, refused } = techniquesFor("tenant_read", roe({ host: "127.0.0.1", environment: "preview" }), "127.0.0.1");
    expect(run.length).toBeGreaterThan(0);
    expect(run.every((t) => t.invariants.includes("tenant_read"))).toBe(true);
    void refused;
  });

  it("refuses a race technique on a production host (owner decision D8)", () => {
    const prod = roe({ host: "127.0.0.1", environment: "production", windows: ["01:00-05:00"], classes: ["read", "write_own_test_records"] });
    const race = byId(RACE_TECHNIQUES, "race.parallel_use");
    const a = techniqueAllowed(race, prod, "127.0.0.1");
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toMatch(/not allowed by your rules|never run on a production host/);
  });

  it("refuses the command technique by its forbidden action, so runTechnique never runs it", async () => {
    const v = await startVulnApp(true);
    try {
      const io = ioFor(v.base);
      const registry = new MarkerRegistry();
      const ctx = contextFor(v, io, registry);
      const cmd = byId(INJECTION_TECHNIQUES, "injection.command");
      const out = await runTechnique(ctx, cmd, { ...target(), input: { request: { method: "POST", path: "/api/ping", body: '{"value":"{{value}}"}' }, as: "a" } });
      expect(out.outcome).toBe("not_allowed");
    } finally { await v.close(); }
  });
});
