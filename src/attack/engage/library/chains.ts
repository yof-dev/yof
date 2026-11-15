/**
 * yof engagement, attack library: CHAIN TEMPLATES. A few named multi-step flows, each a ReplaySpec (../../replay.ts)
 * with state carried from step to step (an id saved at creation, a marker carried through). The planner fills a
 * template from the app model; the same object is the proof, the `yof attack replay` script and the generated
 * regression test.
 *
 *   createPayRefundTwice   create a test record, take it through its "paid" step, then refund it twice; the record's
 *                          own re-read must show the refund counted at most once (a single-use / bound test)
 *   inviteAcceptOtherTenant account A creates a record and invites by a token; account B in another tenant accepts it
 *                          and must NOT read A's planted marker (a tenant-crossing test)
 *   skipAStep              create a record, run the steps before the last-but-one, then the last step, which must be
 *                          refused without the step it depends on (a state-order test)
 *
 * Every template plants in account A's OWN test record and cleans it up. Nothing reads more than the run's own marker,
 * and nothing is sent that the record's safety classes do not allow (the governor still checks each request).
 */
import type { ReplaySpec, ReplayStep } from "../../replay";
import { deleteStep, plantStep, replayPath, specOf, stepOf } from "./kit";
import type { OrderedSteps, RequestSpec, SingleUse, Technique, TestObject } from "./types";

/** The id and marker of the planted record are {{id}} and {{marker}} in every step below. */
const RULE = (ruleId: string, title: string): Pick<Technique, "ruleId" | "title"> => ({ ruleId, title });

export interface PayRefund {
  object: TestObject;
  /** The step that takes the record to its "paid" state. */
  pay: RequestSpec;
  /** The refund, sent more than once. */
  refund: RequestSpec;
  /** How many refunds the record allows (default 1). */
  bound?: number;
}

/** "create, pay, refund twice": the refund must count at most `bound` times however often it is sent. */
export function createPayRefundTwice(p: PayRefund, accounts?: ReplaySpec["accounts"]): ReplaySpec {
  const bound = Math.max(1, p.bound ?? 1);
  return specOf(RULE("attack.single_use_reuse", "A refund can be taken more than once"), ["marker"], accounts, [
    plantStep("a", p.object),
    stepOf("a", p.pay, { setup: true }),
    stepOf("a", p.refund, { repeat: bound + 1, expect: { kind: "count_at_most", max: bound } }),
    deleteStep("a", p.object),
  ]);
}

export interface InviteAccept {
  object: TestObject;
  /** Account A's invite: it hands back a token saved as {{token}} (its JSON path). */
  invite: { request: RequestSpec; tokenPath: string };
  /** Account B accepts with the token: the request carries {{token}}. */
  accept: RequestSpec;
  /** Where account B would then read what it should not: carries {{id}}; B must not see A's marker. */
  read: string;
}

/** "invite, accept as another tenant": B in another tenant accepts A's invite and must not read A's planted marker. */
export function inviteAcceptOtherTenant(p: InviteAccept, accounts?: ReplaySpec["accounts"]): ReplaySpec {
  const steps: ReplayStep[] = [
    plantStep("a", p.object),
    stepOf("a", p.invite.request, { save: { name: "token", from: p.invite.tokenPath }, setup: true }),
    stepOf("b", p.accept),
    { as: "b", method: "GET", path: replayPath(p.read), leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } },
    stepOf("a", { method: "GET", path: p.object.read }, { leg: "positive", expect: { kind: "marker_present", value: "{{marker}}" } }),
    deleteStep("a", p.object),
  ];
  return specOf(RULE("attack.tenant_read", "An invite lets another tenant read the record"), ["marker", "token"], accounts, steps);
}

export interface SkipStep {
  object: TestObject;
  ordered: OrderedSteps;
}

/** "skip a step": run every step before the last-but-one, then the last step, which must be refused without its predecessor. */
export function skipAStep(p: SkipStep, accounts?: ReplaySpec["accounts"]): ReplaySpec | null {
  const s = p.ordered.steps;
  if (s.length < 2) return null;
  const k = s.length - 1;
  return specOf(RULE("attack.step_skipped", "A later step works before the step it depends on"), ["marker"], accounts, [
    plantStep("a", p.object),
    ...s.slice(0, k - 1).map((x) => stepOf("a", x.request, { setup: true })),
    stepOf("a", s[k]!.request, { leg: "test", expect: { kind: "denied" } }),
    deleteStep("a", p.object),
  ]);
}

/** The single-use shape of a refund, for a planner that reaches the logic group's technique from a chain. Pure. */
export const refundAsSingleUse = (p: PayRefund): SingleUse => ({ request: p.refund, bound: p.bound ?? 1 });

export const CHAIN_TEMPLATES = { createPayRefundTwice, inviteAcceptOtherTenant, skipAStep } as const;
