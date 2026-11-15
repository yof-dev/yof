/**
 * The hosted attack runner's harness (packages/yof-engage/src/run.ts), driven locally with an injected fetch. It proves
 * the SAFETY the runner leans on the open core for:
 *   - a worked chain becomes a finding tagged yof_run, with an intact evidence bundle; a held chain becomes none;
 *   - a timing or race unit is NEVER run against a production host (the door guard), even if a plan lists it;
 *   - the slice keeps a tamper-evident, hash-chained log of its unit outcomes;
 *   - a record whose target host is not in scope runs nothing (fatal), never a pretend pass.
 *
 * Nothing here touches a network: every request is the injected fetch.
 */
import { describe, expect, it, vi } from "vitest";
import { runEngagementSlice, type EngageRunRequest, type RunUnit } from "../../../packages/yof-engage/src/run";
import { bundleIntact } from "../src/attack/engage/evidence";
import { FORBIDDEN_ACTIONS, ROE_SCHEMA_VERSION, SEED_FORBIDDEN_PATHS, type SafetyClass } from "../src/attack/engage/roe";

const HOST = "app.test";
const roe = (classes: SafetyClass[], environment: "preview" | "production" = "preview") => ({
  schema: ROE_SCHEMA_VERSION,
  hosts: [{ host: HOST, environment, proof: "dns", classes, windows: environment === "production" ? ["00:00-23:59"] : [], requests_per_second: 2 }],
  budgets: { total_requests: 200, max_minutes: 5 },
  forbidden_paths: [...SEED_FORBIDDEN_PATHS],
  forbidden_actions: [...FORBIDDEN_ACTIONS],
  data: { marker_only: true as const, retention_days: 180, after_retention: "hashes_and_replay_steps" as const },
  stop_contact: { email: null },
});

const unit = (route: string, over: Partial<RunUnit> = {}): RunUnit => ({
  unitKey: `k:${route}`, ruleId: "attack.auth_bypass", technique: "access.signed_out", safetyClass: "read",
  group: "auth", as: "anon", method: "GET", route,
  spec: { ruleId: "attack.auth_bypass", title: "signed-out read", vars: [], accounts: {}, steps: [{ as: "anon", method: "GET", path: route, expect: { kind: "denied" } }] },
  ...over,
});

/** A fetch that answers 200 for the health baseline and a chosen status for each route. */
function stubFetch(routeStatus: Record<string, number>) {
  const seen: string[] = [];
  const fn = vi.fn(async (url: string) => {
    const path = new URL(url).pathname;
    seen.push(path);
    const status = path === "/" ? 200 : (routeStatus[path] ?? 200);
    return new Response(status === 200 ? "{\"ok\":true}" : "no", { status, headers: { "content-type": "application/json" } });
  });
  return { fn: fn as unknown as EngageRunRequest["fetch"], seen };
}

const base = (over: Partial<EngageRunRequest>): EngageRunRequest => ({
  engagementId: "eng-1234", appHost: HOST, consentText: "roe:abc@v1",
  target: { origin: `https://${HOST}`, host: HOST, kind: "preview", proof: "dns" },
  roe: roe(["read"]) as unknown as EngageRunRequest["roe"],
  units: [], runNonce: "ABCDEFGHJKLM",
  ...over,
});

describe("hosted runner harness: safety", () => {
  it("a worked chain becomes a yof_run finding with an intact evidence bundle; a held chain becomes none", async () => {
    const { fn } = stubFetch({ "/open": 200, "/locked": 403 });
    const res = await runEngagementSlice(base({ units: [unit("/open"), unit("/locked")], fetch: fn }));
    expect(res.fatal).toBeNull();
    expect(res.reported_by).toBe("yof_run");
    const open = res.units.find((u) => u.unitKey === "k:/open")!;
    const locked = res.units.find((u) => u.unitKey === "k:/locked")!;
    expect(open.verdict).toBe("needs_validation"); // worked, not verified in this unit
    expect(locked.verdict).toBe("held");
    expect(res.upload.findings.map((f) => f.route)).toEqual(["/open"]);
    expect(res.upload.consent.text).toBe("roe:abc@v1");
    // the finding carries an evidence bundle whose hash matches its contents
    expect(open.evidence).not.toBeNull();
    expect(bundleIntact(open.evidence!)).toBe(true);
    expect(open.evidence!.reported_by).toBe("yof_run");
  });

  it("never runs a timing or race unit against a production host (the door guard)", async () => {
    const { fn, seen } = stubFetch({ "/slow": 200 });
    const res = await runEngagementSlice(base({
      target: { origin: `https://${HOST}`, host: HOST, kind: "production", proof: "dns" },
      roe: roe(["read"], "production") as unknown as EngageRunRequest["roe"],
      units: [unit("/slow", { safetyClass: "timing", technique: "injection.time_based" })],
      fetch: fn,
    }));
    const u = res.units.find((x) => x.unitKey === "k:/slow")!;
    expect(u.verdict).toBe("skipped");
    expect(u.reason).toBe("not_allowed_by_rules:never_on_production");
    expect(seen).not.toContain("/slow"); // not a single request was sent for it
    expect(res.upload.findings).toHaveLength(0);
  });

  it("keeps a tamper-evident, hash-chained log of the slice", async () => {
    const { fn } = stubFetch({ "/a": 200, "/b": 403 });
    const res = await runEngagementSlice(base({ units: [unit("/a"), unit("/b")], fetch: fn }));
    expect(res.log).toHaveLength(2);
    expect(res.log[0]!.prevHash).toBeNull();
    expect(res.log[1]!.prevHash).toBe(res.log[0]!.hash); // each row carries the previous row's hash
    expect(res.logHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("runs nothing when the target host is not in the rules of engagement", async () => {
    const { fn, seen } = stubFetch({});
    const res = await runEngagementSlice(base({
      target: { origin: "https://other.test", host: "other.test", kind: "preview", proof: "dns" },
      units: [unit("/x")], fetch: fn,
    }));
    expect(res.ok).toBe(false);
    expect(res.fatal).toMatch(/not in the rules of engagement/);
    expect(seen).toHaveLength(0);
  });
});
