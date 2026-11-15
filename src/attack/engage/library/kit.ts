/**
 * yof engagement, open core: what every technique of the library shares. Small and pure where it can be.
 *
 *   fillRequest      a request of the app model with its values filled in
 *   sendRequest      one request through the engagement io (the governor), with its safety class said out loud
 *   readDifferential the marker differential for a READ (../differential.ts decides it: both controls and a repeat)
 *   writeDifferential another account's WRITE to the owner's test record, seen when the owner reads it again, with
 *                    its own two controls (the direct request is refused; the same write with no sign-in is refused)
 *   result           one technique result in the library's shape
 *
 * Nothing here decides whether a request may be sent: the io does (the record and the governor). A technique only
 * says which kind of test each request is.
 */
import type { As, HttpAnswer, Method, Purpose } from "../../http";
import { answerShape } from "../../mask";
import { readPath } from "../../probes";
import type { ReplaySpec, ReplayStep } from "../../replay";
import { decideDifferential, DIFFERENTIAL_REASON_WORDS, missingIdLike } from "../differential";
import { findMarkers, plantMarker, type MarkerRole, type PlantedRecord } from "../markers";
import type { SafetyClass } from "../roe";
import type { ImpactFacts, Outcome, RequestSpec, Technique, TechniqueContext, TechniqueResult, TestObject } from "./types";

export const ok = (s: number): boolean => s >= 200 && s < 300;
/** An answer that says nothing about the app's rule: none, or "slow down". */
export const unusable = (r: HttpAnswer | null): boolean => !r || r.status === 0 || r.status === 429 || r.status === 503;
const J = (s: string) => JSON.stringify(s).slice(1, -1);

export interface Filled { method: Method; path: string; body?: string; headers?: Record<string, string> }
/** Fill {id} and {{name}} values into a request. In a path a value is URL-encoded; in a body it is JSON string content. */
export function fillRequest(r: RequestSpec, vars: Record<string, string>): Filled {
  const inPath = (s: string) => s.replace(/\{\{(\w+)\}\}|\{(\w+)\}/g, (m, a: string | undefined, b: string | undefined) => { const k = a ?? b ?? ""; return k in vars ? encodeURIComponent(vars[k]!) : m; });
  const inBody = (s: string) => s.replace(/\{\{(\w+)\}\}/g, (m, k: string) => (k in vars ? J(vars[k]!) : m));
  return { method: r.method, path: inPath(r.path), ...(r.body !== undefined ? { body: inBody(r.body) } : {}), ...(r.headers ? { headers: { ...r.headers } } : {}) };
}
/** The route of a request as it may be shown: no query, placeholders kept. */
export const routeOf = (path: string): string => path.split("?")[0]!;
/** A request spec as a replay step path and body ({id} becomes {{id}}). */
export const replayPath = (p: string): string => p.replace(/\{(\w+)\}/g, (m, k: string, at: number, all: string) => (all[at - 1] === "{" || all[at + m.length] === "}" ? m : `{{${k}}}`));

export interface SendInit { cls: SafetyClass; leg?: "plant" | "positive" | "test" | "negative" | "cleanup"; purpose?: Purpose; headers?: Record<string, string>; actions?: readonly string[] }
/** The purpose of a request for the HTTP client: a read, a write to a record this run created, or a POST the session names. */
export const purposeOf = (method: Method, path: string, ids: readonly string[]): Purpose =>
  method === "GET" || method === "HEAD" ? "read" : ids.some((id) => id && path.split("?")[0]!.split("/").includes(encodeURIComponent(id))) ? "owned" : method === "POST" ? "create" : "owned";

/** Send one filled request. null = the role has no usable account. */
export function sendRequest(ctx: TechniqueContext, as: As, f: Filled, init: SendInit, ids: readonly string[] = []): Promise<HttpAnswer | null> {
  return ctx.io.send(as, f.method, f.path, {
    ...(f.body !== undefined ? { body: f.body } : {}), ...((f.headers || init.headers) ? { headers: { ...(f.headers ?? {}), ...(init.headers ?? {}) } } : {}),
    purpose: init.purpose ?? purposeOf(f.method, f.path, ids), cls: init.cls, ...(init.leg ? { leg: init.leg } : {}), ...(init.actions ? { actions: init.actions } : {}),
  });
}
/** The kind of test a request of this method is, when the technique itself only reads or only writes its own record. */
export const classFor = (method: Method, write: SafetyClass = "write_own_test_records"): SafetyClass => (method === "GET" || method === "HEAD" ? "read" : write);

export const readId = (body: string, path: string): string => { const v = readPath(body, path); return v.length <= 200 ? v : ""; };
/** The value at a JSON path, as the JSON text it is ("" when it is not there). */
export function jsonAt(body: string, path: string): string {
  let v: unknown;
  try { v = JSON.parse(body); } catch { return ""; }
  for (const part of path.split(".")) {
    if (v === null || v === undefined) return "";
    if (Array.isArray(v) && /^\d+$/.test(part)) v = v[Number(part)];
    else if (typeof v === "object") v = (v as Record<string, unknown>)[part];
    else return "";
  }
  return v === undefined ? "" : JSON.stringify(v);
}
export const numberAt = (body: string, path: string): number | null => { const t = jsonAt(body, path); const n = t === "" || t === "null" ? NaN : Number(JSON.parse(t) as unknown); return Number.isFinite(n) ? n : null; };

const NONE: ImpactFacts = { what: "none", position: "same_tenant_member", reach: "one_object", data: "ordinary" };

export interface ResultFields {
  reason: string; demonstrated?: boolean; method?: Method; route?: string; as?: As; status?: number; evidence?: string; meta?: Record<string, string>;
  payload?: string | null; marker?: string | null; replay?: ReplaySpec | null; impact?: ImpactFacts | null;
}
/** One result. A result is "demonstrated" only when it is "violated": nothing else may claim it. */
export function result(t: Pick<Technique, "id" | "ruleId" | "impact">, outcome: Outcome, f: ResultFields): TechniqueResult {
  const shown = outcome === "violated" || outcome === "needs_validation";
  return {
    technique: t.id, ruleId: t.ruleId, outcome, demonstrated: outcome === "violated" && f.demonstrated !== false, reason: f.reason,
    method: f.method ?? "GET", route: f.route ?? "/", as: f.as ?? "anon", status: f.status ?? 0, evidence: shown ? f.evidence ?? "" : "",
    meta: { technique: t.id, ...(f.meta ?? {}) }, payload: f.payload ?? null, marker: f.marker ?? null, replay: shown ? f.replay ?? null : null,
    impact: shown ? f.impact ?? (outcome === "violated" ? t.impact : NONE) : null,
  };
}
export const notTestable = (t: Pick<Technique, "id" | "ruleId" | "impact">, reason: string): TechniqueResult => result(t, "not_testable", { reason });
export const PLANT_WHY: Record<string, string> = {
  no_account: "a test account this needs is not set, or its sign-in failed",
  forbidden_path: "the rules forbid a path this needs",
  create_failed: "the test record could not be created",
  no_id: "the new test record's id could not be read",
};
export const roleOf = (as: As): MarkerRole | null => (as === "anon" ? null : as);

/** Create the owner's test record with a fresh marker in it. `suffix` is appended to the marker in the record (a payload). */
export async function plant(ctx: TechniqueContext, role: MarkerRole, object: TestObject, suffix = ""): Promise<{ ok: true; record: PlantedRecord } | { ok: false; why: string }> {
  const spec = suffix ? { ...object, create: { path: object.create.path, body: object.create.body.split("{{marker}}").join(`{{marker}}${J(suffix).replace(/\{\{/g, "{\\u007b")}`) } } : object;
  const p = await plantMarker(ctx.io, ctx.registry, role, spec, readId);
  return p.ok ? p : { ok: false, why: PLANT_WHY[(p as { why: string }).why] ?? "the test record could not be created" };
}

/**
 * A record whose marker a test replaced can no longer be deleted by the ordinary clean-up (it deletes only a record
 * that still holds the marker it planted). This deletes it when it holds ANY marker of this run, and only then.
 */
export async function removeChanged(ctx: TechniqueContext, rec: PlantedRecord): Promise<void> {
  if (rec.state !== "planted" || !rec.readRoute) return;
  const path = rec.readRoute.split("{id}").join(encodeURIComponent(rec.id));
  const seen = await ctx.io.send(rec.role, "GET", path, { purpose: "cleanup", cls: "read", leg: "cleanup" });
  if (!seen || !ok(seen.status) || seen.body.includes(rec.marker) || !findMarkers(seen.body).some((m) => ctx.registry.mine(m))) return;
  const d = await ctx.io.send(rec.role, "DELETE", rec.deleteRoute.split("{id}").join(encodeURIComponent(rec.id)), { purpose: "cleanup", cls: "write_own_test_records", leg: "cleanup" });
  if (d && (ok(d.status) || d.status === 404 || d.status === 410)) rec.state = "deleted";
}

/** Run a test that replaces the record's marker, then delete the record whatever happened. */
export async function withChanged<T>(ctx: TechniqueContext, rec: PlantedRecord, fn: () => Promise<T>): Promise<T> {
  try { return await fn(); } finally { await removeChanged(ctx, rec).catch(() => undefined); }
}

export interface ReadPlan {
  owner: MarkerRole;
  other: As;
  object: TestObject;
  /** The request both roles send (default: GET the record). */
  request?: RequestSpec;
  /** Extra headers on the other role's request only (a method-override header, a content type). */
  otherHeaders?: Record<string, string>;
  /** The kind of test the other role's request is. Default: a read. */
  cls?: SafetyClass;
  /** Use this record instead of planting a new one. */
  record?: PlantedRecord;
}
export interface ReadSeen { outcome: Outcome; demonstrated: boolean; reason: string; status: number; marker: string | null; record: PlantedRecord | null; route: string; method: Method; /** The shape of the other role's answer, never its text. */ shape: string }

/** The marker differential for a read: plant, the owner's read, the other role's identical request, an id that does not exist, the test again. */
export async function readDifferential(ctx: TechniqueContext, p: ReadPlan): Promise<ReadSeen> {
  const req = p.request ?? { method: "GET" as Method, path: p.object.read };
  const route = routeOf(req.path);
  const none = (reason: string): ReadSeen => ({ outcome: "not_testable", demonstrated: false, reason, status: 0, marker: null, record: null, route, method: req.method, shape: "" });
  let rec = p.record ?? null;
  if (!rec) { const planted = await plant(ctx, p.owner, p.object); if (!planted.ok) return none((planted as { why: string }).why); rec = planted.record; }
  const vars = { id: rec.id, marker: rec.marker };
  const mine = fillRequest(req, vars);
  const cls = p.cls ?? classFor(req.method, "write_cross_account_test_records");
  const positive = await sendRequest(ctx, p.owner, mine, { cls: classFor(req.method), leg: "positive" }, [rec.id]);
  const test = await sendRequest(ctx, p.other, mine, { cls, leg: "test", headers: p.otherHeaders }, [rec.id]);
  const leg = (r: HttpAnswer | null) => (r ? { status: r.status, body: r.body } : null);
  const first = decideDifferential({ marker: rec.marker, positive: leg(positive), test: leg(test), negative: null, repeat: null });
  if (!first.exposed) {
    return { outcome: first.outcome === "held" ? "held" : "not_testable", demonstrated: false, reason: first.outcome === "held" ? "the other account did not get the owner's test record" : DIFFERENTIAL_REASON_WORDS[first.reasons[0] ?? "no_answer"], status: test?.status ?? 0, marker: rec.marker, record: rec, route, method: req.method, shape: "" };
  }
  const gone = missingIdLike(rec.id, ctx.random);
  const negative = await sendRequest(ctx, p.other, req.path.includes("{id}") || (req.body ?? "").includes("{{id}}") ? fillRequest(req, { ...vars, id: gone }) : { ...mine, path: `${mine.path.split("?")[0]!.replace(/\/$/, "")}/${gone}` }, { cls, leg: "negative", headers: p.otherHeaders });
  const repeat = await sendRequest(ctx, p.other, mine, { cls, leg: "test", headers: p.otherHeaders }, [rec.id]);
  const d = decideDifferential({ marker: rec.marker, positive: leg(positive), test: leg(test), negative: leg(negative), repeat: leg(repeat) });
  return {
    outcome: d.outcome === "proven" ? "violated" : "needs_validation", demonstrated: d.outcome === "proven",
    reason: d.outcome === "proven" ? "the other account got the owner's planted marker, both controls worked, and it showed twice" : d.reasons.map((r) => DIFFERENTIAL_REASON_WORDS[r]).join("; "),
    status: test?.status ?? 0, marker: rec.marker, record: rec, route, method: req.method, shape: test ? answerShape(test.body) : "",
  };
}

export interface WritePlan {
  owner: MarkerRole;
  other: As;
  object: TestObject;
  /** The other role's write: carries {{marker}} (the new value) and the record's {id}. */
  write: RequestSpec;
  writeHeaders?: Record<string, string>;
  /** The plain request that must be refused first (the control): without it, the test shows nothing about the bypass. */
  direct?: RequestSpec;
  /** Turn a filled request into the one that is sent (another content type, for example). */
  shape?: (f: Filled) => Filled;
}
export interface WriteSeen { outcome: Outcome; demonstrated: boolean; reason: string; status: number; marker: string | null; route: string; method: Method; controls: string }

/**
 * Another account's write to the owner's test record. Shown only by what the OWNER reads afterwards: the other
 * account's own new marker in the owner's record. Controls: the plain request is refused (when one is given), and the
 * same write sent with no sign-in is refused and leaves the record alone (an app that accepts a write from anyone is a
 * different finding). The record is deleted here, whatever it holds by then.
 */
export async function writeDifferential(ctx: TechniqueContext, p: WritePlan): Promise<WriteSeen> {
  const route = routeOf(p.write.path);
  const base = { status: 0, marker: null as string | null, route, method: p.write.method, controls: "" };
  const planted = await plant(ctx, p.owner, p.object);
  if (!planted.ok) return { ...base, outcome: "not_testable", demonstrated: false, reason: (planted as { why: string }).why };
  const rec = planted.record;
  const cls: SafetyClass = "write_cross_account_test_records";
  const shape = p.shape ?? ((f: Filled) => f);
  const marks = (): string => ctx.registry.next(roleOf(p.other) ?? p.owner);
  const ownerSees = async (m: string): Promise<boolean | null> => {
    const r = await ctx.io.send(p.owner, "GET", p.object.read.split("{id}").join(encodeURIComponent(rec.id)), { purpose: "read", cls: "read", leg: "positive" });
    return unusable(r) ? null : ok(r!.status) && r!.body.includes(m);
  };
  try {
    if (p.direct) {
      const plain = await sendRequest(ctx, p.other, fillRequest(p.direct, { id: rec.id, marker: marks() }), { cls, leg: "negative" }, [rec.id]);
      if (plain === null) return { ...base, outcome: "not_testable", demonstrated: false, reason: PLANT_WHY.no_account! };
      if (unusable(plain)) return { ...base, outcome: "not_testable", demonstrated: false, reason: "the control request got no usable answer" };
      if (ok(plain.status)) return { ...base, outcome: "not_testable", demonstrated: false, status: plain.status, reason: "the plain request is not refused either, so this shows nothing about the way around it (see the cross-account write test)" };
    }
    const m1 = marks();
    const w1 = await sendRequest(ctx, p.other, shape(fillRequest(p.write, { id: rec.id, marker: m1 })), { cls, leg: "test", headers: p.writeHeaders }, [rec.id]);
    if (w1 === null) return { ...base, outcome: "not_testable", demonstrated: false, reason: PLANT_WHY.no_account! };
    const seen1 = await ownerSees(m1);
    if (seen1 === null) return { ...base, outcome: "not_testable", demonstrated: false, status: w1.status, reason: "the owner's own read got no usable answer" };
    if (!seen1) return { ...base, outcome: "held", demonstrated: false, status: w1.status, marker: rec.marker, reason: "the owner's record did not change" };
    // The control: nobody signed in sends the same write. It must be refused, and the owner must not see its marker.
    const mN = ctx.registry.next(p.owner);
    const neg = p.other === "anon" ? null : await sendRequest(ctx, "anon", shape(fillRequest(p.write, { id: rec.id, marker: mN })), { cls, leg: "negative", headers: p.writeHeaders }, [rec.id]);
    const negSeen = neg ? await ownerSees(mN) : null;
    const m2 = marks();
    await sendRequest(ctx, p.other, shape(fillRequest(p.write, { id: rec.id, marker: m2 })), { cls, leg: "test", headers: p.writeHeaders }, [rec.id]);
    const seen2 = await ownerSees(m2);
    const negOk = !!neg && !unusable(neg) && !ok(neg.status) && negSeen === false;
    const missing = [...(negOk ? [] : ["the same write with no sign-in was not refused, so the app may accept this from anyone"]), ...(seen2 ? [] : ["it did not show a second time"])];
    return {
      ...base, status: w1.status, marker: m1, controls: `${p.direct ? "plain request refused; " : ""}${negOk ? "refused with no sign-in" : "not refused with no sign-in"}`,
      outcome: missing.length ? "needs_validation" : "violated", demonstrated: !missing.length,
      reason: missing.length ? missing.join("; ") : "the owner read the other account's new marker in its own record, the controls worked, and it showed twice",
    };
  } finally {
    await removeChanged(ctx, rec).catch(() => undefined);
  }
}

/** Replay steps shared by the chains: the plant and its clean-up. */
export const plantStep = (owner: MarkerRole, o: TestObject): ReplayStep => ({ as: owner, method: "POST", path: o.create.path, body: o.create.body, save: { name: "id", from: o.idPath }, setup: true, leg: "plant" });
export const deleteStep = (owner: MarkerRole, o: TestObject): ReplayStep => ({ as: owner, method: "DELETE", path: replayPath(o.delete), cleanup: true });
export const stepOf = (as: As, r: RequestSpec, extra: Partial<ReplayStep> = {}): ReplayStep => ({ as, method: r.method, path: replayPath(r.path), ...(r.body !== undefined ? { body: r.body } : {}), ...(r.headers ? { headers: r.headers } : {}), ...extra });
export const specOf = (t: Pick<Technique, "ruleId" | "title">, vars: string[], accounts: ReplaySpec["accounts"] | undefined, steps: ReplaySpec["steps"]): ReplaySpec => ({ ruleId: t.ruleId, title: t.title, vars, accounts: accounts ?? {}, steps });
