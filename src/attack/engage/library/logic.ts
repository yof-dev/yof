/**
 * yof engagement, attack library: BUSINESS RULES on the run's own test records.
 *
 *   logic.numeric_bound   a number the app must keep in bounds: a negative or zero quantity, a refund above the
 *                         payment (the bound is another field of the same record), a price only the server may set
 *   logic.state_skip      a later step sent before the step it needs (step 3 before step 2)
 *   logic.single_use      a coupon, a code or a one-time action sent again
 *
 * THE ORACLE is always a re-read of the test record by its owner: the number the record shows, the state it reached,
 * how often the action counted. An answer that says "ok" proves nothing by itself: an app may answer 200 and ignore
 * the request. Each test first shows that the ordinary request works (the control), or it reports "not testable".
 *
 * The bounds, the order of the steps and what is single-use come from the app model (confirmed or assumed rules);
 * the library only knows how to test them. What this cannot show: a rule nobody wrote down or derived.
 */
import type { ReplaySpec } from "../../replay";
import type { PlantedRecord } from "../markers";
import { deleteStep, fillRequest, jsonAt, notTestable, numberAt, ok, plant, plantStep, result, routeOf, sendRequest, specOf, stepOf, unusable } from "./kit";
import type { ImpactFacts, NumericRule, RequestSpec, SingleUse, Technique, TechniqueContext, TechniqueResult, TestObject } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" };
type Head = Omit<Technique, "run" | "chain">;
export const MAX_USES = 5;

export interface NumberTry { payload: string; value: number }
/** Which numbers to send for a rule, given what the record shows now. Pure. */
export function numbersToTry(rule: NumericRule, record: string): NumberTry[] {
  if (rule.serverSet) { const now = numberAt(record, rule.readPath); return now === null ? [] : [{ payload: "num.other", value: now + 7 }]; }
  const out: NumberTry[] = [];
  if (rule.min !== undefined) { if (-1 < rule.min) out.push({ payload: "num.negative", value: -1 }); if (0 < rule.min) out.push({ payload: "num.zero", value: 0 }); }
  const max = rule.max ?? (rule.maxFromPath ? numberAt(record, rule.maxFromPath) : null);
  if (max !== null && max !== undefined) out.push({ payload: "num.above", value: max + 1 });
  return out;
}
const outOfBounds = (rule: NumericRule, record: string, v: number): boolean => {
  const max = rule.max ?? (rule.maxFromPath ? numberAt(record, rule.maxFromPath) : null);
  return (rule.min !== undefined && v < rule.min) || (max !== null && max !== undefined && v > max);
};

const NUMERIC: Head = {
  id: "logic.numeric_bound", ruleId: "attack.number_out_of_bounds", title: "The app accepts a number outside its allowed range",
  invariants: ["numeric_bound"], prerequisites: ["account_a", "test_object", "numeric_rule"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"],
  payloads: ["num.negative", "num.zero", "num.above", "num.other"],
  oracle: "A number inside the bounds is stored and read back (the control); a number outside them is sent and the owner's re-read shows it, twice.",
  shows: "that the server stores a number its own rule forbids", cannotShow: "what the number leads to later (a payout, a stock count): nothing is done with it",
  best: "confirmed", impact: IMPACT, owasp: "A04 / API6",
  chainLimit: "The replay expects the out-of-bounds request to be refused. An app that accepts it and stores a corrected number fails the replay although it is fixed: run the technique again to re-test.",
};
const STATE: Head = {
  id: "logic.state_skip", ruleId: "attack.step_skipped", title: "A later step works before the step it depends on",
  invariants: ["state_order"], prerequisites: ["account_a", "test_object", "ordered_steps"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: ["order.skip"],
  oracle: "On one test record the steps work in order (the control); on a new one, a later step sent without the step before it is accepted and the owner's re-read shows the later state, twice.",
  shows: "that the server does not check the state a step needs", cannotShow: "steps the app model does not list",
  best: "confirmed", impact: IMPACT, owasp: "A04 / API6",
};
const ONCE: Head = {
  id: "logic.single_use", ruleId: "attack.single_use_reuse", title: "A single-use link or code works more than once",
  invariants: ["single_use"], prerequisites: ["account_a", "single_use_action"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: ["use.twice"],
  oracle: "The action works once (the control); sent again it is accepted, and the owner's re-read shows it counted more often than its limit.",
  shows: "that a used code or action is not marked as used", cannotShow: "whether it counted, where the app model names no number to read back: that case needs validation",
  best: "confirmed", impact: IMPACT, owasp: "A04 / API6",
};

const withN = (r: RequestSpec, n: number): RequestSpec => ({ ...r, path: r.path.split("{{n}}").join(String(n)), ...(r.body !== undefined ? { body: r.body.split("{{n}}").join(String(n)) } : {}) });
export async function readRecord(ctx: TechniqueContext, o: TestObject, rec: PlantedRecord): Promise<string | null> {
  const r = await ctx.io.send("a", "GET", o.read.split("{id}").join(encodeURIComponent(rec.id)), { purpose: "read", cls: "read", leg: "positive" });
  return r && ok(r.status) ? r.body : null;
}
export const act = (ctx: TechniqueContext, r: RequestSpec, rec: PlantedRecord | null, cls: "write_own_test_records" | "race" = "write_own_test_records") =>
  sendRequest(ctx, "a", fillRequest(r, rec ? { id: rec.id, marker: rec.marker } : {}), { cls, leg: "test" }, rec ? [rec.id] : []);

/** How often a single-use action counted, from the number the record shows before and after. null = it cannot be read. Pure. */
export function timesCounted(before: string | null, after: string | null, rule: SingleUse): number | null {
  if (!rule.effect || before === null || after === null || !rule.effect.perUse) return null;
  const a = numberAt(before, rule.effect.readPath), b = numberAt(after, rule.effect.readPath);
  return a === null || b === null ? null : Math.round((b - a) / rule.effect.perUse);
}
export const useChain = (t: Pick<Technique, "ruleId" | "title">, o: TestObject | undefined, rule: SingleUse, times: number, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, o ? ["marker"] : [], accounts, [
    ...(o ? [plantStep("a", o)] : []),
    stepOf("a", rule.request, { repeat: times, expect: { kind: "count_at_most", max: rule.bound ?? 1 } }),
    ...(o ? [deleteStep("a", o)] : []),
  ]);

export const LOGIC_TECHNIQUES: readonly Technique[] = [
  {
    ...NUMERIC,
    chain: (target, accounts) => (target.object && target.numeric ? specOf(NUMERIC, ["marker"], accounts, [
      plantStep("a", target.object), stepOf("a", withN(target.numeric.request, target.numeric.min !== undefined ? -1 : (target.numeric.max ?? 0) + 1), { expect: { kind: "denied" } }), deleteStep("a", target.object),
    ]) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = NUMERIC, o = target.object, rule = target.numeric;
      if (!o || !rule) return notTestable(t, "the app model names no number with bounds on the test record");
      const planted = await plant(ctx, "a", o);
      if (!planted.ok) return notTestable(t, (planted as { why: string }).why);
      const rec = planted.record, route = routeOf(rule.request.path), method = rule.request.method;
      const set = async (n: number): Promise<{ status: number; shown: number | null; record: string | null } | null> => {
        const r = await act(ctx, withN(rule.request, n), rec);
        if (r === null || unusable(r)) return null;
        const body = await readRecord(ctx, o, rec);
        return { status: r.status, shown: body === null ? null : numberAt(body, rule.readPath), record: body };
      };
      const control = await set(rule.ok);
      if (!control || control.record === null || control.shown !== rule.ok) return notTestable(t, "a number inside the bounds was not stored and read back, so the test would show nothing");
      const tries = numbersToTry(rule, control.record);
      if (!tries.length) return notTestable(t, "the rule names no bound that a number could be sent beyond");
      for (const x of tries) {
        const first = await set(x.value);
        if (!first || first.shown === null || first.record === null) continue;
        const broken = rule.serverSet ? first.shown === x.value : first.shown === x.value && outOfBounds(rule, first.record, first.shown);
        if (!broken) continue;
        await set(rule.ok);
        const again = await set(x.value);
        const twice = !!again && again.shown === x.value;
        return result(t, twice ? "violated" : "needs_validation", {
          reason: twice ? "the owner's re-read showed the out-of-bounds number twice, after a number inside the bounds was shown to work" : "it showed once and not a second time",
          method, route, as: "a", status: first.status, marker: rec.marker, payload: x.payload, evidence: EVIDENCE.numberOutOfBounds(rule.name, x.payload),
          meta: { field: rule.name, payload: x.payload, bound: rule.serverSet ? "set by the server" : `${rule.min ?? "none"} to ${rule.max ?? (rule.maxFromPath ? `the record's ${rule.maxFromPath}` : "none")}` },
          replay: specOf(t, ["marker"], ctx.accounts, [plantStep("a", o), stepOf("a", withN(rule.request, x.value), { expect: { kind: "denied" } }), deleteStep("a", o)]),
        });
      }
      return result(t, "held", { reason: "every number outside the bounds was refused, or was not stored", method, route, as: "a", status: control.status });
    },
  },
  {
    ...STATE,
    chain: (target, accounts) => {
      const o = target.object, s = target.ordered;
      if (!o || !s || s.steps.length < 2) return null;
      const k = s.steps.length - 1;
      return specOf(STATE, ["marker"], accounts, [plantStep("a", o), ...s.steps.slice(0, k - 1).map((x) => stepOf("a", x.request, { setup: true })), stepOf("a", s.steps[k]!.request, { expect: { kind: "denied" } }), deleteStep("a", o)]);
    },
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = STATE, o = target.object, s = target.ordered;
      if (!o || !s || s.steps.length < 2) return notTestable(t, "the app model names no steps that must run in order on the test record");
      const k = s.steps.length - 1, later = s.steps[k]!;
      const route = routeOf(later.request.path), method = later.request.method;
      const stateOf = async (rec: PlantedRecord): Promise<string | null> => { const body = await readRecord(ctx, o, rec); if (body === null) return null; const v = jsonAt(body, s.statePath); try { return String(JSON.parse(v) as unknown); } catch { return null; } };
      // The control: on one record, every step in order, each reaching its state.
      const inOrder = await plant(ctx, "a", o);
      if (!inOrder.ok) return notTestable(t, (inOrder as { why: string }).why);
      for (const step of s.steps) {
        const r = await act(ctx, step.request, inOrder.record);
        if (!r || !ok(r.status) || (await stateOf(inOrder.record)) !== step.state) return notTestable(t, `the step ${step.name} did not work in order, so the test would show nothing`);
      }
      // The test: a new record, the steps before the skipped one, then the later step.
      const skip = async (): Promise<{ status: number; reached: boolean; marker: string } | string> => {
        const fresh = await plant(ctx, "a", o);
        if (!fresh.ok) return (fresh as { why: string }).why;
        for (const step of s.steps.slice(0, k - 1)) { const r = await act(ctx, step.request, fresh.record); if (!r || !ok(r.status)) return `the step ${step.name} did not work on a new record`; }
        const r = await act(ctx, later.request, fresh.record);
        if (!r || unusable(r)) return "the later step got no usable answer";
        return { status: r.status, reached: ok(r.status) && (await stateOf(fresh.record)) === later.state, marker: fresh.record.marker };
      };
      const first = await skip();
      if (typeof first === "string") return notTestable(t, first);
      if (!first.reached) return result(t, "held", { reason: "the later step was refused without the step before it, or the record did not reach its state", method, route, as: "a", status: first.status });
      const second = await skip();
      const twice = typeof second !== "string" && second.reached;
      return result(t, twice ? "violated" : "needs_validation", {
        reason: twice ? "two new records reached the later state without the step before it, after the steps were shown to work in order" : "it showed once and not a second time",
        method, route, as: "a", status: first.status, marker: first.marker, payload: "order.skip", evidence: EVIDENCE.stepSkipped(later.name), meta: { kind: `${later.name} without ${s.steps[k - 1]!.name}`.slice(0, 120), payload: "order.skip" },
        replay: LOGIC_TECHNIQUES[1]!.chain(target, ctx.accounts),
      });
    },
  },
  {
    ...ONCE,
    chain: (target, accounts) => (target.singleUse ? useChain(ONCE, target.object, target.singleUse, Math.min(MAX_USES, (target.singleUse.bound ?? 1) + 1), accounts) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = ONCE, o = target.object, rule = target.singleUse;
      if (!rule) return notTestable(t, "the app model names no single-use action");
      const bound = Math.max(1, Math.min(MAX_USES - 1, rule.bound ?? 1));
      const route = routeOf(rule.request.path), method = rule.request.method;
      let rec: PlantedRecord | null = null;
      if (o) { const planted = await plant(ctx, "a", o); if (!planted.ok) return notTestable(t, (planted as { why: string }).why); rec = planted.record; }
      const before = o && rec ? await readRecord(ctx, o, rec) : null;
      let wins = 0, status = 0;
      for (let i = 0; i < bound; i++) { const r = await act(ctx, rule.request, rec); if (!r || !ok(r.status)) return notTestable(t, "the action did not work the first time, so the test would show nothing"); wins++; status = r.status; }
      const extra = await act(ctx, rule.request, rec);
      if (!extra || unusable(extra)) return notTestable(t, "the repeated request got no usable answer");
      if (!ok(extra.status)) return result(t, "held", { reason: "the action was refused once its limit was used", method, route, as: "a", status: extra.status });
      wins++;
      const counted = timesCounted(before, o && rec ? await readRecord(ctx, o, rec) : null, rule);
      if (counted !== null && counted <= bound) return result(t, "held", { reason: "the repeated request was answered, but the record shows it did not count again", method, route, as: "a", status: extra.status });
      return result(t, counted !== null ? "violated" : "needs_validation", {
        reason: counted !== null ? "the record shows the action counted more often than its limit, after it was shown to work once" : "the repeated request was accepted; the app model names no number to read back, so it is not shown that it counted twice",
        method, route, as: "a", status: extra.status, marker: rec?.marker ?? null, payload: "use.twice", evidence: EVIDENCE.usedTwice(counted ?? wins, bound),
        meta: { count: String(counted ?? wins), bound: String(bound), payload: "use.twice" }, replay: useChain(t, o, rule, bound + 1, ctx.accounts),
      });
    },
  },
];
