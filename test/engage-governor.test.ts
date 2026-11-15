/**
 * yof engagement, open core: the governor (src/attack/engage/governor.ts) and the record's check on every request
 * (src/attack/engage/roe.ts). A fake clock and a scripted client: no network, no real waiting.
 *   1. the baseline comes first: 20 harmless GETs, and nothing else is sent before it exists;
 *   2. a health probe every 25 requests; the record's pace is kept;
 *   3. 429 or 503: the pace is halved, then a 10 minute pause, then a stop;
 *   4. server errors over the last 50 requests: the larger of baseline plus 5 points, or 2%;
 *   5. slow answers: over 3 times the baseline in three windows running;
 *   6. a bot wall or a challenge page is "blocked, not tested", never "passed";
 *   7. the record is enforced on every request: host, proof, class, window, method, path, action, budgets;
 *   8. a read-only (light) record never sends anything but GET and HEAD, whatever is asked;
 *   9. after a stop only clean-up still goes; a person's stop is noticed, also during a pause.
 */
import { describe, expect, it } from "vitest";
import { parseAttackConfig } from "../src/attack/config";
import { AttackClient } from "../src/attack/http";
import {
  BASELINE_REQUESTS, ERROR_WINDOW, Governor, GovernorStopped, LATENCY_WINDOW, PAUSE_MS, PROBE_EVERY, RoeRefused, budgetStop, classOf, computeBaseline, errorLimit, latencyLimit,
  looksBlocked, newState, onAnswer, outcomeOfStop, paceWait, percentile, type GovernorState,
} from "../src/attack/engage/governor";
import { METHODS_OF_CLASS, parseRoe, roeCheckRequest, roeDocument, roeFromConfig, SAFETY_CLASSES } from "../src/attack/engage/roe";
import { fakeConfig } from "./fake-app";
import { HOST, NIGHT, answer, fakeClock, roe, scriptedClient } from "./engage-helpers";

const gov = (record = roe(), script?: Parameters<typeof scriptedClient>[1], shouldStop?: () => boolean) => {
  const clock = fakeClock();
  const c = scriptedClient(clock, script);
  const g = new Governor({ client: c.client, roe: record, now: clock.now, sleep: clock.sleep, shouldStop });
  return { clock, g, ...c };
};
const stopOf = async (p: Promise<unknown>) => { try { await p; } catch (e) { if (e instanceof GovernorStopped) return e; throw e; } throw new Error("the governor did not stop"); };
const refusalOf = async (p: Promise<unknown>) => { try { await p; } catch (e) { if (e instanceof RoeRefused) return e.code; throw e; } throw new Error("the request was not refused"); };
const ready = (base = { p95Ms: 100, medianMs: 60, errorRate: 0, samples: 20 }): GovernorState => ({ ...newState(2, 0), baseline: base });
const view = (status: number, body = "", headers: Record<string, string> = {}) => ({ status, body, header: (n: string) => headers[n.toLowerCase()] ?? null });

describe("1. the baseline comes first", () => {
  it("measures 20 harmless GETs with no sign-in: median, 95th percentile, share of server errors", async () => {
    const { g, sent } = gov(roe(), (_s, n) => ({ ms: n === 20 ? 400 : n * 10, answer: n <= 2 ? answer(500) : answer(200) }));
    const b = await g.measureBaseline();
    expect(sent).toHaveLength(BASELINE_REQUESTS);
    expect(sent.every((s) => s.method === "GET" && s.as === "anon" && s.path === "/")).toBe(true);
    expect(b).toEqual({ samples: 20, medianMs: 100, p95Ms: 190, errorRate: 0.1 });
    expect(g.events.map((e) => e.kind)).toEqual(["baseline"]);
    expect(await g.measureBaseline()).toBe(b);   // measured once
    expect(sent).toHaveLength(20);
  });
  it("nothing else is sent before the baseline exists", async () => {
    const { g, sent } = gov();
    await expect(g.send("a", "GET", "/api/me")).rejects.toThrow(/no baseline yet/);
    expect(sent).toEqual([]);
  });
  it("an app that is already failing, or a bot wall, stops the run before it starts", async () => {
    const failing = gov(roe(), () => ({ answer: answer(500) }));
    expect((await stopOf(failing.g.measureBaseline())).stop.reason).toBe("unhealthy_before_start");
    const wall = gov(roe(), () => ({ answer: answer(403, "<html>challenge</html>", { "cf-mitigated": "challenge" }) }));
    const e = await stopOf(wall.g.measureBaseline());
    expect(e.stop.reason).toBe("blocked");
    expect(wall.sent).toHaveLength(1);
  });
  it("percentiles are nearest-rank, and the numbers are plain", () => {
    expect(percentile([], 0.95)).toBe(0);
    expect(percentile([5], 0.5)).toBe(5);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.5)).toBe(5);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95)).toBe(10);
    expect(computeBaseline([{ status: 200, ms: 10 }, { status: 0, ms: 30 }, { status: 503, ms: 20 }, { status: 404, ms: 40 }]).errorRate).toBe(0.5);
  });
});

describe("2. the health probe and the pace", () => {
  it("one more harmless GET every 25 requests", async () => {
    const { g, sent } = gov();
    await g.measureBaseline();
    for (let i = 0; i < 60; i++) await g.send("a", "GET", "/api/me");
    const after = sent.slice(BASELINE_REQUESTS);
    const probes = after.map((s, i) => ({ s, i })).filter((x) => x.s.path === "/" && x.s.as === "anon");
    expect(probes.map((x) => x.i)).toEqual([PROBE_EVERY, PROBE_EVERY * 2 + 1]);
    expect(after).toHaveLength(62);
    expect(g.state.sent).toBe(82);
  });
  it("keeps the record's requests a second", async () => {
    const { g, sent } = gov(roe({ requests_per_second: 2 }), () => ({ ms: 10 }));
    await g.measureBaseline();
    await g.send("a", "GET", "/api/me");
    await g.send("a", "GET", "/api/me");
    const [x, y] = sent.slice(-2);
    expect(y!.at - x!.at).toBe(500);
    expect(paceWait({ rate: 2 }, null, 0)).toBe(0);
    expect(paceWait({ rate: 2 }, 1000, 1100)).toBe(400);
    expect(paceWait({ rate: 0.5 }, 1000, 1100)).toBe(1900);
  });
  it("the health check with no answer twice in a row stops the run", () => {
    const s = ready();
    expect(onAnswer(s, { status: 0, ms: 10_000, blocked: null, probe: true }, 1).action).toBe("continue");
    expect(onAnswer(s, { status: 0, ms: 10_000, blocked: null, probe: true }, 2)).toMatchObject({ action: "stop", stop: { reason: "no_answer" } });
  });
});

describe("3. 429 or 503: halve, pause, stop", () => {
  it("the pure ladder", () => {
    const s = ready();
    expect(onAnswer(s, { status: 429, ms: 20, blocked: null }, 1000)).toEqual({ action: "halve", rate: 1 });
    expect(onAnswer(s, { status: 200, ms: 20, blocked: null }, 2000)).toEqual({ action: "continue" });
    expect(onAnswer(s, { status: 503, ms: 20, blocked: null }, 3000)).toEqual({ action: "pause", until: 3000 + PAUSE_MS });
    expect(PAUSE_MS).toBe(600_000);
    expect(onAnswer(s, { status: 429, ms: 20, blocked: null }, 4000)).toMatchObject({ action: "stop", stop: { reason: "too_many_slow_down_answers" } });
    expect(s.stop?.reason).toBe("too_many_slow_down_answers");
  });
  it("through the governor: half the pace, then ten minutes of silence, then nothing more", async () => {
    let slow = new Set<number>();
    const { g, sent, clock } = gov(roe(), (_s, n) => ({ answer: slow.has(n) ? answer(429, { error: "slow down" }) : answer(200), ms: 10 }));
    await g.measureBaseline();
    slow = new Set([21, 23, 25]);
    expect((await g.send("a", "GET", "/api/me")).status).toBe(429);          // 21: first
    expect(g.state.rate).toBe(1);
    await g.send("a", "GET", "/api/me");                                     // 22: one second later
    expect(sent[21]!.at - sent[20]!.at).toBe(1000);
    await g.send("a", "GET", "/api/me");                                     // 23: second 429 -> pause
    const before = clock.now();
    await g.send("a", "GET", "/api/me");                                     // 24: only after the pause
    expect(sent[23]!.at - before).toBeGreaterThanOrEqual(PAUSE_MS - 20);
    const e = await stopOf(g.send("a", "GET", "/api/me"));                   // 25: third -> stop
    expect(e.stop.reason).toBe("too_many_slow_down_answers");
    expect(e.outcome).toBe("not_tested");
    expect(g.events.map((x) => x.kind)).toEqual(["baseline", "pace_halved", "paused", "resumed", "stopped"]);
    const n = sent.length;
    await expect(g.send("a", "GET", "/api/me")).rejects.toBeInstanceOf(GovernorStopped);
    expect(sent).toHaveLength(n);
  });
});

describe("4. server errors over the last 50 requests", () => {
  it("the limit is the larger of baseline plus 5 points, or 2%", () => {
    expect(errorLimit({ samples: 20, medianMs: 1, p95Ms: 1, errorRate: 0 })).toBe(0.05);
    expect(errorLimit({ samples: 20, medianMs: 1, p95Ms: 1, errorRate: 0.1 })).toBeCloseTo(0.15);
    expect(ERROR_WINDOW).toBe(50);
  });
  it("a clean baseline: two server errors in 50 requests go on, the third stops", () => {
    const s = ready();
    for (let i = 0; i < 20; i++) expect(onAnswer(s, { status: 200, ms: 20, blocked: null }, i).action).toBe("continue");
    expect(onAnswer(s, { status: 500, ms: 20, blocked: null }, 30).action).toBe("continue");
    expect(onAnswer(s, { status: 0, ms: 20, blocked: null }, 31).action).toBe("continue");
    expect(onAnswer(s, { status: 502, ms: 20, blocked: null }, 32)).toMatchObject({ action: "stop", stop: { reason: "server_errors" } });
  });
  it("a baseline with 10% errors allows 7 in 50 and stops at the 8th; errors older than 50 requests no longer count", () => {
    const s = ready({ p95Ms: 100, medianMs: 60, errorRate: 0.1, samples: 20 });
    for (let i = 0; i < 7; i++) expect(onAnswer(s, { status: 500, ms: 20, blocked: null }, i).action).toBe("continue");
    for (let i = 0; i < 50; i++) expect(onAnswer(s, { status: 200, ms: 20, blocked: null }, 100 + i).action).toBe("continue");
    expect(s.recent.filter((x) => x >= 500)).toHaveLength(0);
    for (let i = 0; i < 7; i++) expect(onAnswer(s, { status: 500, ms: 20, blocked: null }, 200 + i).action).toBe("continue");
    expect(onAnswer(s, { status: 500, ms: 20, blocked: null }, 300)).toMatchObject({ action: "stop", stop: { reason: "server_errors" } });
  });
  it("a 404 or a 403 is not a server error", () => {
    const s = ready();
    for (let i = 0; i < 60; i++) expect(onAnswer(s, { status: i % 2 ? 404 : 403, ms: 20, blocked: null }, i).action).toBe("continue");
  });
});

describe("5. slow answers: three slow windows running", () => {
  const feed = (s: GovernorState, ms: number, n = LATENCY_WINDOW) => { let last = onAnswer(s, { status: 200, ms, blocked: null }, 0); for (let i = 1; i < n; i++) last = onAnswer(s, { status: 200, ms, blocked: null }, i); return last; };
  it("the limit is 3 times the baseline's 95th percentile (a very fast baseline counts as 50 ms)", () => {
    expect(latencyLimit({ samples: 20, medianMs: 60, p95Ms: 100, errorRate: 0 })).toBe(300);
    expect(latencyLimit({ samples: 20, medianMs: 2, p95Ms: 5, errorRate: 0 })).toBe(150);
  });
  it("stops at the end of the third slow window, not before", () => {
    const s = ready();
    expect(feed(s, 400).action).toBe("continue");
    expect(feed(s, 400).action).toBe("continue");
    expect(s.slowWindows).toBe(2);
    expect(feed(s, 400, LATENCY_WINDOW - 1).action).toBe("continue");
    expect(onAnswer(s, { status: 200, ms: 400, blocked: null }, 99)).toMatchObject({ action: "stop", stop: { reason: "slow_answers" } });
  });
  it("one normal window in between starts the count again; exactly 3 times is not over", () => {
    const s = ready();
    feed(s, 400); feed(s, 400);
    expect(feed(s, 80).action).toBe("continue");
    expect(s.slowWindows).toBe(0);
    feed(s, 300); feed(s, 300);
    expect(feed(s, 300).action).toBe("continue");
    expect(s.slowWindows).toBe(0);
  });
});

describe("6. a bot wall is blocked, not tested", () => {
  it("knows a challenge page by its headers or its text", () => {
    expect(looksBlocked(view(403, "", { "cf-mitigated": "challenge" }))).toBe("a Cloudflare challenge");
    expect(looksBlocked(view(200, "<html><title>Just a moment...</title></html>"))).toBe("a Cloudflare challenge");
    expect(looksBlocked(view(405, "", { "x-amzn-waf-action": "captcha" }))).toBe("an AWS WAF challenge");
    expect(looksBlocked(view(429, "", { "x-vercel-mitigated": "challenge" }))).toBe("a Vercel challenge");
    expect(looksBlocked(view(403, '<div class="g-recaptcha"></div>'))).toBe("a CAPTCHA page");
    expect(looksBlocked(view(403, "Please verify you are human to continue"))).toBe("a bot wall");
    expect(looksBlocked(view(403, "Request unsuccessful. Incapsula incident ID: 1-2"))).toBe("an Imperva block");
  });
  it("an ordinary refusal, or a sign-in page with a CAPTCHA widget, is not a wall", () => {
    expect(looksBlocked(view(403, '{"error":"forbidden"}'))).toBeNull();
    expect(looksBlocked(view(401, '{"error":"unauthorized"}'))).toBeNull();
    expect(looksBlocked(view(404, "not found"))).toBeNull();
    expect(looksBlocked(view(200, '<form><div class="g-recaptcha"></div></form>'))).toBeNull();
    expect(looksBlocked(view(429, '{"error":"slow down"}'))).toBeNull();
  });
  it("stops the run, and what was being tested is never called passed or held", async () => {
    const { g } = gov(roe(), (_s, n) => (n === 21 ? { answer: answer(403, "<html>Verify you are human</html>") } : {}));
    await g.measureBaseline();
    const e = await stopOf(g.send("b", "GET", "/api/notes/n1"));
    expect(e.stop.reason).toBe("blocked");
    expect(e.outcome).toBe("blocked_not_tested");
    expect(e.stop.detail).toContain("blocked, not tested");
    for (const reason of ["blocked", "too_many_slow_down_answers", "server_errors", "slow_answers", "no_answer", "request_budget", "time_budget", "stopped_by_person", "unhealthy_before_start"] as const) {
      expect(["blocked_not_tested", "not_tested"]).toContain(outcomeOfStop({ reason, detail: "", at: 0 }));
    }
    expect(outcomeOfStop({ reason: "server_errors", detail: "", at: 0 })).toBe("not_tested");
  });
});

describe("7. the record is enforced on every request", () => {
  const at = new Date(NIGHT);
  const noon = new Date("2026-11-12T12:00:00Z");
  const prod = roe({ environment: "production", proof: "dns", windows: ["01:00-05:00"], classes: ["read", "write_own_test_records"] });
  const req = (over: Partial<Parameters<typeof roeCheckRequest>[1]> = {}) => ({ host: HOST, method: "GET" as const, path: "/api/me", cls: "read" as const, ...over });
  const code = (record: ReturnType<typeof roe>, r: ReturnType<typeof req>, when = at) => { const d = roeCheckRequest(record, r, when); return d.ok ? "ok" : d.code; };
  it("the pure check: host, proof, class, window, method, path, action", () => {
    expect(code(prod, req())).toBe("ok");
    expect(code(prod, req({ host: "other.example.com" }))).toBe("host_not_in_scope");
    expect(code(roe({ proof: null }), req())).toBe("not_proven");
    expect(code(prod, req({ cls: "ai_messages", method: "POST" }))).toBe("class_not_allowed");
    expect(code(prod, req(), noon)).toBe("outside_window");
    expect(code(roe({ windows: ["23:00-01:00"] }), req(), new Date("2026-11-12T00:30:00Z"))).toBe("ok");
    expect(code(prod, req({ method: "POST" }))).toBe("method_not_allowed");
    expect(code(prod, req({ method: "DELETE", cls: "write_own_test_records", path: "/api/notes/n1" }))).toBe("ok");
    for (const p of ["/api/logout", "/account/DELETE-me", "/api/orders?action=cancel", "/billing/pay"]) expect(code(prod, req({ path: p })), p).toBe("forbidden_path");
    expect(code(prod, req({ path: "/api/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest" }))).toBe("forbidden_action");
    expect(code(prod, req({ method: "POST", cls: "write_own_test_records", path: "/api/import", body: JSON.stringify({ url: ["metadata", "google", "internal"].join(".") }) }))).toBe("forbidden_action");
    expect(code(prod, req({ actions: ["password_guessing_on_real_accounts"] }))).toBe("forbidden_action");
    expect(code(prod, req({ actions: ["something_else"] }))).toBe("ok");
  });
  it("timing and race tests never go to a production host, even if a record said so", () => {
    const forged = roe({ environment: "production", proof: "dns", windows: ["01:00-05:00"], classes: ["read", "timing", "race"] });
    expect(parseRoe(forged).ok).toBe(false);
    expect(code(forged, req({ cls: "timing" }))).toBe("class_not_allowed");
    expect(code(forged, req({ cls: "race" }))).toBe("class_not_allowed");
  });
  it("a refused request is not sent: the client never sees it", async () => {
    const { g, sent } = gov(roe({ classes: ["read"] }));
    await g.measureBaseline();
    const n = sent.length;
    expect(await refusalOf(g.send("a", "POST", "/api/notes", { body: "{}", purpose: "create" }))).toBe("class_not_allowed");
    expect(await refusalOf(g.send("a", "GET", "/api/signout"))).toBe("forbidden_path");
    expect(await refusalOf(g.send("a", "POST", "/api/notes", { cls: "read" }))).toBe("method_not_allowed");
    expect(sent).toHaveLength(n);
    expect(g.events.filter((e) => e.kind === "refused").map((e) => e.detail.code)).toEqual(["class_not_allowed", "forbidden_path", "method_not_allowed"]);
    // a host that is not in the record gets nothing at all, not even the baseline
    const other = fakeClock();
    const c = scriptedClient(other, undefined, "https://elsewhere.example.com");
    const g2 = new Governor({ client: c.client, roe: roe(), now: other.now, sleep: other.sleep });
    expect(await refusalOf(g2.measureBaseline())).toBe("host_not_in_scope");
    expect(c.sent).toEqual([]);
  });
  it("outside the window nothing goes, the baseline included", async () => {
    const clock = fakeClock(Date.parse("2026-11-12T12:00:00Z"));
    const c = scriptedClient(clock);
    const g = new Governor({ client: c.client, roe: roe({ environment: "production", windows: ["01:00-05:00"], classes: ["read"] }), now: clock.now, sleep: clock.sleep });
    expect(await refusalOf(g.measureBaseline())).toBe("outside_window");
    expect(c.sent).toEqual([]);
  });
  it("the total budget and the time budget stop the run", async () => {
    const few = gov(roe({}, { total_requests: 23, max_minutes: 60 }));
    await few.g.measureBaseline();
    for (let i = 0; i < 3; i++) await few.g.send("a", "GET", "/api/me");
    expect((await stopOf(few.g.send("a", "GET", "/api/me"))).stop.reason).toBe("request_budget");
    expect(few.sent).toHaveLength(23);
    const short = gov(roe({}, { total_requests: 2000, max_minutes: 1 }));
    await short.g.measureBaseline();
    short.clock.advance(60_000);
    expect((await stopOf(short.g.send("a", "GET", "/api/me"))).stop.reason).toBe("time_budget");
    expect(budgetStop({ ...newState(2, 0), sent: 5 }, { budgets: { total_requests: 5, max_minutes: 1 } }, 10)?.reason).toBe("request_budget");
    expect(budgetStop({ ...newState(2, 0), sent: 4 }, { budgets: { total_requests: 5, max_minutes: 1 } }, 59_999)).toBeNull();
  });
});

describe("8. a read-only record never sends anything but GET and HEAD", () => {
  const cfg = parseAttackConfig(fakeConfig());
  it("a light run's record allows reads only, and a read is GET or HEAD", () => {
    const light = roeFromConfig({ cfg, host: "127.0.0.1", kind: "local", proof: "local", mode: "light" });
    expect(light.hosts[0]!.classes).toEqual(["read"]);
    expect(METHODS_OF_CLASS.read).toEqual(["GET", "HEAD"]);
    expect(parseRoe(light, { allowLocal: true }).ok).toBe(true);
    expect(parseRoe(light).ok).toBe(false);   // the hosted service never accepts the tester's own machine
  });
  it("every write, under every purpose and every class, is refused before the client; the real client is read-only too", async () => {
    const clock = fakeClock();
    const urls: string[] = [];
    const client = new AttackClient({
      origin: "http://127.0.0.1:4010", budget: { requests: 500, seconds: 600, perSecond: 1000 }, postPaths: ["/api/notes", "/api/chat"], readOnly: true, now: clock.now, sleep: clock.sleep,
      fetch: async (url, init) => { urls.push(`${init.method} ${new URL(url).pathname}`); return new Response("{}", { status: 200 }); },
    });
    const light = roeFromConfig({ cfg, host: "127.0.0.1", kind: "local", proof: "local", mode: "light" });
    const g = new Governor({ client, roe: light, now: clock.now, sleep: clock.sleep });
    await g.measureBaseline();
    client.own("n1");
    for (const method of ["POST", "PATCH", "PUT", "DELETE"] as const) {
      for (const purpose of ["read", "login", "create", "ai", "owned", "cleanup"] as const) {
        for (const cls of [undefined, ...SAFETY_CLASSES]) {
          await expect(g.send("a", method, method === "POST" ? "/api/notes" : "/api/notes/n1", { purpose, cls, body: "{}" }), `${method} ${purpose} ${cls}`).rejects.toThrow();
        }
      }
    }
    await g.send("a", "GET", "/api/notes");
    await g.send("a", "HEAD", "/api/notes");
    expect(urls.every((u) => u.startsWith("GET ") || u.startsWith("HEAD "))).toBe(true);
    expect(urls).toHaveLength(22);
    expect(classOf("GET", "cleanup")).toBe("read");
    expect(classOf("POST", "ai")).toBe("ai_messages");
    expect(classOf("DELETE", "cleanup")).toBe("write_own_test_records");
  });
  it("on production the record is read-only unless the host is proven by DNS and has a window (D6)", () => {
    const base = { cfg: parseAttackConfig(fakeConfig({ app: "shop.example.com", consent: "I own shop.example.com and allow yof attack to test it and its preview builds with my own test accounts.", production: { enabled: true, window: "02:00-04:00" } })), host: "shop.example.com", kind: "production" as const, mode: "full" as const };
    expect(roeFromConfig({ ...base, proof: "meta" }).hosts[0]).toMatchObject({ environment: "production", classes: ["read"], windows: ["02:00-04:00"], requests_per_second: 2 });
    expect(roeFromConfig({ ...base, proof: "dns" }).hosts[0]!.classes).toEqual(["read", "write_own_test_records", "write_cross_account_test_records", "ai_messages"]);
    for (const proof of ["meta", "file", "dns", null] as const) expect(parseRoe(roeFromConfig({ ...base, proof })).ok, String(proof)).toBe(true);
  });
  it("the record prints in the scope-document form, in plain words", () => {
    const doc = roeDocument({ roe: roe({ environment: "production", proof: "dns", windows: ["01:00-05:00"] }), date: "2026-11-12", version: "0.0.0", source: ".yof/attack.json", ownerRun: true });
    expect(doc).toContain("# Rules of engagement: shop.example.com");
    expect(doc).toContain("Nothing was sent to any host to make this document.");
    expect(doc).toContain("A read test sends only GET and HEAD.");
    expect(doc).toContain("blocked, not tested, never as passed");
    expect(doc).toContain("yof did not see them");
    expect(doc).not.toMatch(/[—–]|\b(secure|certified|compliant|independent|CRM)\b/i);
  });
});

describe("9. after a stop, and a person's stop", () => {
  it("only clean-up still goes after a stop, and it is still checked against the record", async () => {
    const { g, sent } = gov(roe(), (_s, n) => (n === 21 ? { answer: answer(403, "", { "cf-mitigated": "challenge" }) } : {}));
    await g.measureBaseline();
    await stopOf(g.send("a", "GET", "/api/me"));
    const n = sent.length;
    await expect(g.send("a", "GET", "/api/me")).rejects.toBeInstanceOf(GovernorStopped);
    expect((await g.send("a", "DELETE", "/api/notes/n1", { purpose: "cleanup" })).status).toBe(200);
    expect(sent).toHaveLength(n + 1);
    expect(sent.at(-1)).toMatchObject({ method: "DELETE", path: "/api/notes/n1", purpose: "cleanup" });
    expect(await refusalOf(g.send("a", "DELETE", "/api/notes/remove/n1", { purpose: "cleanup" }))).toBe("forbidden_path");
  });
  it("a person's stop is noticed before the next request and during a pause", async () => {
    let stop = false;
    const { g, sent } = gov(roe(), (_s, n) => (n === 21 || n === 22 ? { answer: answer(429) } : {}), () => stop);
    await g.measureBaseline();
    await g.send("a", "GET", "/api/me");
    await g.send("a", "GET", "/api/me");   // the second 429: the next request would wait ten minutes
    stop = true;
    const e = await stopOf(g.send("a", "GET", "/api/me"));
    expect(e.stop.reason).toBe("stopped_by_person");
    expect(sent).toHaveLength(22);
  });
  it("own() holds back two requests per record: the look before the delete, and the delete", () => {
    const { g, owned } = gov();
    g.own("n7");
    expect(owned).toEqual(["n7"]);
  });
});
