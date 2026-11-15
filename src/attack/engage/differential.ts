/**
 * yof engagement, open core: the differential. One question, three requests, one rule.
 *
 *   positive control   the owner (role A) asks for its own test record and SEES ITS MARKER. Without this the test
 *                      shows nothing: the app may not return the field at all.
 *   the test           another role (B, or nobody signed in) sends the IDENTICAL request and sees A's marker.
 *   negative control   the same other role asks for an id that does not exist and is refused in a recognisably
 *                      different way. This catches apps that answer 200 to everything (an app shell, a soft 404).
 *
 * THE RULE (owner decision D7 and the audit note of 11 Nov 2026): a result is PROVEN only with a planted marker AND
 * both controls AND a second look that shows the same. Anything less is "needs validation", never confirmed:
 *
 *   no marker was planted (a read-only run compares answers, and "the same data" is a guess)
 *   the positive control failed (the owner did not see its own marker)
 *   the negative control is missing, or failed (the app answers the same way for an id that does not exist)
 *   the result did not show a second time
 *
 * And "proven" here is the FINDER's word only. A result is "confirmed" when the verifier (./verifier.ts), in its own
 * separate run with new sessions and new markers, could not refute it: finalVerdict below.
 *
 * decideDifferential is PURE. runDifferential does the requests through the governor.
 */
import type { As, HttpAnswer, Method } from "../http";
import type { ReplaySpec, ReplayStep } from "../replay";
import { plantMarker, type EngageIo, type MarkerRegistry, type MarkerRole, type PlantSpec } from "./markers";

/** One request's answer, as the rule needs it. null = no answer was obtained (no account, or the request was not sent). */
export interface Leg { status: number; body: string }

export type DifferentialOutcome = "proven" | "needs_validation" | "held" | "not_testable";
export type DifferentialReason =
  | "no_marker" | "positive_control_missing" | "positive_control_failed" | "negative_control_missing" | "negative_control_failed" | "not_reproduced"
  | "no_answer" | "answers_everything";

export interface DifferentialInput {
  /** The planted marker text, or null when none was planted (a read-only run). */
  marker: string | null;
  positive: Leg | null;
  test: Leg | null;
  negative: Leg | null;
  /** The test request sent a second time. null = not sent. */
  repeat?: Leg | null;
}
export interface DifferentialDecision {
  outcome: DifferentialOutcome;
  /** What is missing for "proven" (empty when proven or held). */
  reasons: DifferentialReason[];
  /** Did the test request show the owner's data (the marker, or without a marker: shared values)? */
  exposed: boolean;
}

const ok = (s: number) => s >= 200 && s < 300;
/** An answer that says nothing about the app's rule: no answer, or "slow down". Never read as a refusal. */
const unusable = (l: Leg | null): boolean => !l || l.status === 0 || l.status === 429 || l.status === 503;
const REFUSAL_TEXT = /\b(not found|no such|does not exist|doesn't exist|unknown|forbidden|unauthori[sz]ed|not allowed|access denied|permission denied|no permission|sign ?in|log ?in)\b/i;
const EMPTY_VALUE = /^(?:|null|\{\s*\}|\[\s*\]|""|false|0)$/;

function leaves(text: string): string[] {
  let v: unknown;
  try { v = JSON.parse(text); } catch { return []; }
  const out: string[] = [];
  const walk = (x: unknown) => {
    if (out.length > 500) return;
    if (typeof x === "string" && x.length >= 6 && x.length <= 120) out.push(x);
    else if (typeof x === "number" && String(x).length >= 4) out.push(String(x));
    else if (x && typeof x === "object") for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k]);
  };
  walk(v);
  return out;
}
/**
 * Without a marker: does `other` hold a distinctive value of `base`? This is the old guess. It can only ever make a
 * result "needs validation": it never decides a finding. Pure.
 */
export function sharesValues(base: string, other: string): boolean {
  if (!other.trim()) return false;
  if (REFUSAL_TEXT.test(other.slice(0, 2000)) && other.length < 2000) return false;
  if (base.trim() === other.trim()) return leaves(base).length > 0 || base.trim().length >= 40;
  const mine = new Set(leaves(base));
  return leaves(other).some((x) => mine.has(x));
}

/**
 * Was the request for an id that does not exist refused in a recognisably different way? Yes when the answer does not
 * hold the marker and is not a success, or is a success that plainly says "nothing here" (an empty value, or a short
 * refusal text) while the test answer is not like that. Pure.
 */
export function refusedDifferently(negative: Leg, test: Leg, marker: string | null): boolean {
  if (marker && negative.body.includes(marker)) return false;
  if (!ok(negative.status)) return true;
  const n = negative.body.trim(), t = test.body.trim();
  if (n === t) return false;
  if (EMPTY_VALUE.test(n) && !EMPTY_VALUE.test(t)) return true;
  return n.length < 600 && REFUSAL_TEXT.test(n) && !REFUSAL_TEXT.test(t.slice(0, 2000));
}

/** THE RULE. Pure: the same legs always give the same decision. */
export function decideDifferential(i: DifferentialInput): DifferentialDecision {
  const { marker, positive, test, negative } = i;
  if (unusable(test)) return { outcome: "not_testable", reasons: ["no_answer"], exposed: false };
  const t = test!;
  // What "shows the owner's data" means: the marker when one was planted; without one, values shared with the owner's
  // answer; and with no owner answer at all, only that an answer with content came back (the weakest sign there is).
  const sees = (l: Leg) => ok(l.status) && (marker ? l.body.includes(marker)
    : positive ? ok(positive.status) && sharesValues(positive.body, l.body)
      : leaves(l.body).length > 0 && !(REFUSAL_TEXT.test(l.body.slice(0, 2000)) && l.body.length < 2000));
  const exposed = sees(t);
  const positiveOk = !!positive && ok(positive.status) && (marker ? positive.body.includes(marker) : true);
  if (!exposed) {
    // A plain refusal of the other role is the rule holding. A success that does not show the owner's data says so
    // only when the positive control worked: otherwise the app may simply not return the data to anyone.
    if (!ok(t.status)) return { outcome: "held", reasons: [], exposed: false };
    if ((marker || positive) && !positiveOk) return { outcome: "not_testable", reasons: [unusable(positive) ? "positive_control_missing" : "positive_control_failed"], exposed: false };
    return { outcome: "held", reasons: [], exposed: false };
  }
  // No marker, and the app answers the same for an id that does not exist: nothing was shown at all.
  if (!marker && negative && !unusable(negative) && ok(negative.status) && (negative.body.trim() === t.body.trim() || sharesValues(t.body, negative.body))) {
    return { outcome: "not_testable", reasons: ["answers_everything"], exposed: false };
  }
  const reasons: DifferentialReason[] = [];
  if (!marker) reasons.push("no_marker");
  if (unusable(positive)) reasons.push("positive_control_missing");
  else if (!positiveOk) reasons.push("positive_control_failed");
  if (unusable(negative)) reasons.push("negative_control_missing");
  else if (!refusedDifferently(negative!, t, marker)) reasons.push("negative_control_failed");
  if (i.repeat === undefined || unusable(i.repeat) || !sees(i.repeat!)) reasons.push("not_reproduced");
  return { outcome: reasons.length ? "needs_validation" : "proven", reasons, exposed: true };
}

/** What each missing piece means, in plain words (for a report line). */
export const DIFFERENTIAL_REASON_WORDS: Record<DifferentialReason, string> = {
  no_marker: "no marker was planted, so it is not shown whose data this is",
  positive_control_missing: "the owner's own request got no answer to compare with",
  positive_control_failed: "the owner did not see its own marker, so the test shows nothing",
  negative_control_missing: "a request for a record that does not exist got no answer",
  negative_control_failed: "the app answers the same way for a record that does not exist",
  not_reproduced: "it did not show a second time",
  no_answer: "the test request got no usable answer",
  answers_everything: "the app gives the same answer for a record that does not exist, so nothing was shown",
};

export type FinalVerdict = "confirmed" | "needs_validation" | "rejected";
/**
 * The verdict of a result: the finder's outcome plus the verifier's. Confirmed only when the finder proved it AND the
 * verifier, in its own run, could not refute it. Refuted is rejected (kept for the record). Everything else, a finder
 * alone included, is "needs validation". Pure.
 */
export function finalVerdict(finder: DifferentialOutcome, verifier: { stands: boolean | null } | null): FinalVerdict | null {
  if (finder === "held" || finder === "not_testable") return null;
  if (verifier && verifier.stands === false) return "rejected";
  return finder === "proven" && verifier?.stands === true ? "confirmed" : "needs_validation";
}

// ── I/O ──────────────────────────────────────────────────────────────────────────────────────────────────────────
const withId = (p: string, id: string) => p.split("{id}").join(encodeURIComponent(id));
const idVar = (p: string) => p.split("{id}").join("{{id}}");

/** An id that does not exist, shaped like the real one (digits stay digits, a UUID stays a UUID). */
export function missingIdLike(id: string, random: () => string): string {
  const r = random().replace(/[^0-9a-f]/gi, "").toLowerCase().padEnd(12, "0");
  if (/^\d+$/.test(id)) return `9${String(parseInt(r.slice(0, 10), 16)).padStart(Math.max(8, id.length + 2), "0").slice(0, 14)}`;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return `${r.slice(0, 8)}-0000-4000-8000-${r.slice(0, 12)}`;
  return `yofnone${r}`;
}

export interface DifferentialPlan {
  ruleId: string;
  title: string;
  /** The role that owns the record (plants the marker). */
  owner: MarkerRole;
  /** The role that must not see it: another tenant's account, or nobody signed in. */
  other: As;
  object: PlantSpec & { read: string };
  /** The request both roles send. Default: GET the record by id. `{id}` is the planted record's id. */
  request?: { method: Extract<Method, "GET" | "HEAD">; path: string };
  /** false = plant nothing (a read-only run): the result can be "needs validation" at most. */
  plant: boolean;
  /** For a read-only run: the path both roles read (no {id}). */
  readOnlyPath?: string;
}
export interface LegRecord { as: As; method: Method; route: string; status: number | null; sawMarker: boolean }
export interface DifferentialResult extends DifferentialDecision {
  ruleId: string;
  marker: string | null;
  legs: { positive: LegRecord | null; test: LegRecord | null; negative: LegRecord | null };
  /** Why nothing could be run, when nothing could. */
  setup?: "no_account" | "forbidden_path" | "create_failed" | "no_id";
  /** The chain as data: the verifier and the regression test run exactly this. null when nothing was planted. */
  replay: ReplaySpec | null;
}

const toLeg = (r: HttpAnswer | null): Leg | null => (r ? { status: r.status, body: r.body } : null);
const record = (as: As, method: Method, route: string, r: HttpAnswer | null, marker: string | null): LegRecord => ({ as, method, route, status: r ? r.status : null, sawMarker: !!r && !!marker && r.body.includes(marker) });

/** The chain of a marker differential as a replay spec, each step tagged with the leg it is. Pure. */
export function differentialSpec(p: Pick<DifferentialPlan, "ruleId" | "title" | "owner" | "other" | "object" | "request">, accounts: ReplaySpec["accounts"]): ReplaySpec {
  const method = p.request?.method ?? "GET";
  const path = idVar(p.request?.path ?? p.object.read);
  const steps: ReplayStep[] = [
    { as: p.owner, method: "POST", path: p.object.create.path, body: p.object.create.body, save: { name: "id", from: p.object.idPath }, setup: true, leg: "plant" },
    { as: p.other, method, path, leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } },
    { as: p.owner, method, path, leg: "positive", expect: { kind: "marker_present", value: "{{marker}}" } },
    { as: p.owner, method: "DELETE", path: idVar(p.object.delete), cleanup: true },
  ];
  return { ruleId: p.ruleId, title: p.title, vars: ["marker"], accounts, steps };
}

/**
 * Run one differential through the governor. Order: plant, positive control, the test, the negative control, the
 * test once more. The record is registered for clean-up the moment it exists; the caller runs the clean-up at the end
 * (cleanUpMarkers), also after a stop.
 */
export async function runDifferential(io: EngageIo, registry: MarkerRegistry, plan: DifferentialPlan, deps: { readId: (body: string, path: string) => string; random: () => string; accounts?: ReplaySpec["accounts"] }): Promise<DifferentialResult> {
  const none = (setup: DifferentialResult["setup"]): DifferentialResult => ({ outcome: "not_testable", reasons: ["no_answer"], exposed: false, ruleId: plan.ruleId, marker: null, legs: { positive: null, test: null, negative: null }, setup, replay: null });
  const method = plan.request?.method ?? "GET";
  if (!plan.plant) {
    // Read only: both roles read the same path, and the other role asks for a sibling that does not exist.
    const route = plan.readOnlyPath ?? plan.object.read;
    if (route.includes("{id}")) return none("no_id");
    const positive = await io.send(plan.owner, method, route, { cls: "read", leg: "positive" });
    if (positive === null) return none("no_account");
    const test = await io.send(plan.other, method, route, { cls: "read", leg: "test" });
    const d0 = decideDifferential({ marker: null, positive: toLeg(positive), test: toLeg(test), negative: null, repeat: null });
    const negative = d0.exposed ? await io.send(plan.other, method, `${route.replace(/\/$/, "")}/${missingIdLike("", deps.random)}`, { cls: "read", leg: "negative" }) : null;
    const repeat = d0.exposed ? await io.send(plan.other, method, route, { cls: "read", leg: "test" }) : null;
    const d = decideDifferential({ marker: null, positive: toLeg(positive), test: toLeg(test), negative: toLeg(negative), repeat: d0.exposed ? toLeg(repeat) : undefined });
    return { ...d, ruleId: plan.ruleId, marker: null, legs: { positive: record(plan.owner, method, route, positive, null), test: record(plan.other, method, route, test, null), negative: negative ? record(plan.other, method, `${route}/{id}`, negative, null) : null }, replay: null };
  }
  const planted = await plantMarker(io, registry, plan.owner, plan.object, deps.readId);
  if (!planted.ok) return none((planted as { why: DifferentialResult["setup"] }).why);
  const { marker, id } = planted.record;
  const route = plan.request?.path ?? plan.object.read;
  const path = withId(route, id);
  const positive = await io.send(plan.owner, method, path, { cls: "read", leg: "positive" });
  const test = await io.send(plan.other, method, path, { cls: "read", leg: "test" });
  const first = decideDifferential({ marker, positive: toLeg(positive), test: toLeg(test), negative: null, repeat: null });
  // The controls cost requests: they are sent only when the test showed the marker.
  const negative = first.exposed ? await io.send(plan.other, method, route.includes("{id}") ? withId(route, missingIdLike(id, deps.random)) : `${route.replace(/\/$/, "")}/${missingIdLike(id, deps.random)}`, { cls: "read", leg: "negative" }) : null;
  const repeat = first.exposed ? await io.send(plan.other, method, path, { cls: "read", leg: "test" }) : null;
  const d = first.exposed ? decideDifferential({ marker, positive: toLeg(positive), test: toLeg(test), negative: toLeg(negative), repeat: toLeg(repeat) }) : first;
  return {
    ...d, ruleId: plan.ruleId, marker,
    legs: { positive: record(plan.owner, method, route, positive, marker), test: record(plan.other, method, route, test, marker), negative: negative ? record(plan.other, method, route, negative, marker) : null },
    replay: differentialSpec(plan, deps.accounts ?? {}),
  };
}
