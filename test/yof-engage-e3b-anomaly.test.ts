/**
 * E3b (board Y24/OA4): the behaviour baseline and the anomaly detectors (docs/YOF_ENGAGEMENT_DESIGN.md addendum).
 * Each detector is shown on a VULNERABLE set of observations (it fires) and on a CLEAN twin set (it is silent), the
 * same hit-and-silence shape as the attack library. An anomaly is never a finding here: it only names the invariant a
 * work unit would test.
 */
import { describe, expect, it } from "vitest";
import { buildBaseline, fieldSet, median, sizeBucket, type Observation } from "../src/attack/engage/baseline";
import { findAnomalies, objectStem, type Anomaly } from "../src/attack/engage/anomaly";

const o = (p: Partial<Observation> & Pick<Observation, "role" | "route" | "status">): Observation =>
  ({ method: "GET", body: "{}", ms: 20, ...p });
const kinds = (a: Anomaly[]): string[] => [...new Set(a.map((x) => x.kind))].sort();

describe("the baseline", () => {
  it("reads field names and a size bucket, never values", () => {
    expect(fieldSet('{"id":"1","title":"x","owner_id":"u2"}')).toEqual(["id", "owner_id", "title"]);
    expect(fieldSet('[{"id":1},{"id":2,"role":"admin"}]')).toEqual(["id", "role"]);
    expect(fieldSet("not json")).toEqual([]);
    expect([sizeBucket(0), sizeBucket(10), sizeBucket(1000), sizeBucket(9000)]).toEqual(["empty", "small", "medium", "large"]);
    expect(median([30, 10, 20])).toBe(20);
  });
  it("collapses ids so a route and its id form share one object", () => {
    expect(objectStem("/api/notes/{id}")).toBe("/api/notes");
    expect(objectStem("/api/notes")).toBe("/api/notes");
  });
  it("summarises per role and route", () => {
    const b = buildBaseline([
      o({ role: "a", route: "/api/me", status: 200, body: '{"user":"a"}', ms: 10 }),
      o({ role: "a", route: "/api/me", status: 200, body: '{"user":"a"}', ms: 30 }),
      o({ role: "anon", route: "/api/me", status: 401, body: '{"error":"no"}' }),
    ]);
    const me = b.find((x) => x.route === "/api/me")!;
    expect(me.roles.find((r) => r.role === "a")!.fields).toEqual(["user"]);
    expect(me.roles.find((r) => r.role === "a")!.medianMs).toBe(20);
    expect(me.roles.find((r) => r.role === "anon")!.status).toBe(401);
  });
});

describe("field_exposed: a field a sibling route reserves for a higher role", () => {
  const sibling = (memberFields: string): Observation[] => [
    o({ role: "a", route: "/api/notes/{id}", status: 200, body: memberFields }),
    o({ role: "admin", route: "/api/notes", status: 200, body: '{"id":"1","title":"x","owner_id":"u1"}' }),
    o({ role: "a", route: "/api/notes", status: 200, body: '{"id":"1","title":"x"}' }),
  ];
  it("fires when the id route leaks owner_id to a member", () => {
    expect(kinds(findAnomalies(sibling('{"id":"1","title":"x","owner_id":"u1"}')))).toContain("field_exposed");
  });
  it("is silent on the twin that keeps owner_id for admin", () => {
    expect(kinds(findAnomalies(sibling('{"id":"1","title":"x"}')))).not.toContain("field_exposed");
  });
});

describe("sibling_open: one route answers a role its siblings refuse", () => {
  const admin = (statsStatus: number): Observation[] => [
    o({ role: "a", route: "/api/admin/users", status: 403 }),
    o({ role: "a", route: "/api/admin/reports", status: 403 }),
    o({ role: "a", route: "/api/admin/stats", status: statsStatus, body: '{"n":1}' }),
  ];
  it("fires when a member gets 200 where siblings refuse", () => {
    expect(kinds(findAnomalies(admin(200)))).toContain("sibling_open");
  });
  it("is silent on the twin that refuses the member everywhere", () => {
    expect(kinds(findAnomalies(admin(403)))).not.toContain("sibling_open");
  });
});

describe("existence_oracle: an id that exists is refused differently from one that does not", () => {
  const read = (existsStatus: number): Observation[] => [
    o({ role: "a", route: "/api/orders/{id}", status: existsStatus, subject: "exists", body: existsStatus === 200 ? '{"id":"1"}' : '{"error":"no"}' }),
    o({ role: "a", route: "/api/orders/{id}", status: 404, subject: "missing", body: '{"error":"not found"}' }),
  ];
  it("fires on 403-here-404-there", () => {
    expect(kinds(findAnomalies(read(403)))).toContain("existence_oracle");
  });
  it("is silent when both are a plain 404", () => {
    expect(kinds(findAnomalies(read(404)))).not.toContain("existence_oracle");
  });
});

describe("account_enumeration: a sign-in route answers a real account differently", () => {
  const login = (missingStatus: number, missingBody: string): Observation[] => [
    o({ role: "anon", method: "POST", route: "/api/login", status: 401, subject: "exists", body: '{"error":"wrong password"}' }),
    o({ role: "anon", method: "POST", route: "/api/login", status: missingStatus, subject: "missing", body: missingBody }),
  ];
  it("fires when the made-up account gets a different answer", () => {
    expect(kinds(findAnomalies(login(404, '{"error":"no such user"}')))).toContain("account_enumeration");
  });
  it("is silent when both answers are the same", () => {
    expect(kinds(findAnomalies(login(401, '{"error":"wrong password"}')))).not.toContain("account_enumeration");
  });
});

describe("timing_gap: two kinds of request answer at different speeds (off production)", () => {
  const samples = (existsMs: number): Observation[] => {
    const rows: Observation[] = [];
    for (let i = 0; i < 20; i++) {
      rows.push(o({ role: "anon", method: "POST", route: "/api/login", status: 401, subject: "exists", ms: existsMs, body: '{"error":"x"}' }));
      rows.push(o({ role: "anon", method: "POST", route: "/api/login", status: 401, subject: "missing", ms: 100, body: '{"error":"x"}' }));
    }
    return rows;
  };
  it("fires on a wide, repeated gap", () => {
    expect(kinds(findAnomalies(samples(600)))).toContain("timing_gap");
  });
  it("is silent when the two are close", () => {
    expect(kinds(findAnomalies(samples(120)))).not.toContain("timing_gap");
  });
  it("is off on a production host", () => {
    expect(kinds(findAnomalies(samples(600), { production: true }))).not.toContain("timing_gap");
  });
});
