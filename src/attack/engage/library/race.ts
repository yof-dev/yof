/**
 * yof engagement, attack library: RACES. The same request sent several times AT ONCE against something that should
 * work once, or a bounded number of times, on the run's own test record.
 *
 *   race.parallel_use   N identical requests in one burst (N is 6, never more than 10)
 *
 * ONLY where the record allows race tests, which it never does on a production host (owner decision D8): the class
 * is "race", and the record's own check refuses it there by name.
 *
 * THE ORACLE counts: more requests succeeded than the limit allows, AND the owner's re-read shows the action counted
 * more often than its limit. Without a number to read back, successes alone need validation: an app may answer "ok"
 * to a repeat and count it once. A race is a matter of timing, so a second pass may not show it again: then it stays
 * "needs validation", and the report says it showed once.
 */
import type { PlantedRecord } from "../markers";
import { notTestable, ok, plant, result, routeOf } from "./kit";
import { act, readRecord, timesCounted, useChain } from "./logic";
import { DEFAULT_PARALLEL, MAX_PARALLEL } from "./payloads";
import type { Technique, TechniqueResult } from "./types";
import { EVIDENCE } from "./words";

type Head = Omit<Technique, "run" | "chain">;
/** How many requests go at once: the default, or what the caller asks for, never more than 10 and never fewer than 2. Pure. */
export const parallelCount = (wanted: number = DEFAULT_PARALLEL): number => Math.max(2, Math.min(MAX_PARALLEL, Math.floor(wanted)));

const PARALLEL: Head = {
  id: "race.parallel_use", ruleId: "attack.race_condition", title: "Sending the same request several times at once gets past a limit",
  invariants: ["single_use", "numeric_bound"], prerequisites: ["account_a", "single_use_action"], safetyClass: "race", classes: ["read", "write_own_test_records", "race"], payloads: ["race.parallel"],
  oracle: `${DEFAULT_PARALLEL} identical requests are sent at once; more of them succeed than the limit allows, and the owner's re-read shows the action counted more often than its limit.`,
  shows: "that the limit is checked before it is recorded, so requests that arrive together all pass", cannotShow: "anything on a production host (race tests are never run there), or how wide the window is",
  best: "confirmed", impact: { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" }, owasp: "A04 / API6",
  chainLimit: "A replay sends the requests one after another, not at once: it re-tests the limit, not the race. Run the technique again to re-test the race.",
};

export const RACE_TECHNIQUES: readonly Technique[] = [
  {
    ...PARALLEL,
    chain: (target, accounts) => (target.singleUse ? useChain(PARALLEL, target.object, target.singleUse, parallelCount(), accounts) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = PARALLEL, o = target.object, rule = target.singleUse;
      if (!rule) return notTestable(t, "the app model names no single-use or bounded action");
      const bound = Math.max(1, rule.bound ?? 1), n = parallelCount();
      if (bound >= n) return notTestable(t, "the limit is as high as the number of requests this test sends at once");
      const route = routeOf(rule.request.path), method = rule.request.method;
      let rec: PlantedRecord | null = null;
      if (o) { const planted = await plant(ctx, "a", o); if (!planted.ok) return notTestable(t, (planted as { why: string }).why); rec = planted.record; }
      const before = o && rec ? await readRecord(ctx, o, rec) : null;
      // Every request is waited for, also when one of them is refused or the run is stopped: none is left in flight.
      const settled = await Promise.allSettled(Array.from({ length: n }, () => act(ctx, rule.request, rec, "race")));
      const failed = settled.find((x): x is PromiseRejectedResult => x.status === "rejected");
      if (failed) throw failed.reason;
      const answers = settled.map((x) => (x.status === "fulfilled" ? x.value : null));
      if (answers.some((r) => r === null)) return notTestable(t, "the test account is not set, or its sign-in failed");
      const wins = answers.filter((r) => r && ok(r.status)).length;
      if (!wins) return notTestable(t, "none of the requests worked, so the test would show nothing");
      if (wins <= bound) return result(t, "held", { reason: `${wins} of ${n} requests sent at once succeeded, within the limit`, method, route, as: "a", status: 200 });
      const counted = timesCounted(before, o && rec ? await readRecord(ctx, o, rec) : null, rule);
      if (counted !== null && counted <= bound) return result(t, "held", { reason: "more requests were answered than the limit, but the record shows the action counted within its limit", method, route, as: "a", status: 200 });
      return result(t, counted !== null ? "violated" : "needs_validation", {
        reason: counted !== null ? "the record shows the action counted more often than its limit after one burst" : "more requests succeeded than the limit; the app model names no number to read back, so it is not shown that each one counted",
        method, route, as: "a", status: 200, marker: rec?.marker ?? null, payload: "race.parallel", evidence: EVIDENCE.race(counted ?? wins, n, bound),
        meta: { count: String(counted ?? wins), bound: String(bound), burst: String(n), payload: "race.parallel" }, replay: useChain(t, o, rule, n, ctx.accounts),
      });
    },
  },
];
