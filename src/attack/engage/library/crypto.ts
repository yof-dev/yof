/**
 * yof engagement, attack library: OBSERVABLE WEAK CRYPTOGRAPHY. Only what can be seen in the run's OWN values, with
 * nothing guessed about anyone else's. Three observations, each a sign, never a demonstration (so each stays "needs
 * validation"):
 *
 *   crypto.sequential_ids   two test records the run created get ids that follow each other (a short, fixed gap)
 *   crypto.short_token      a session value of the run's own test account is shorter than a safe floor
 *   crypto.predictable_token two sign-ins of the same test account hand out session values that share a long prefix
 *
 * NOT DUPLICATED HERE (owner: do not duplicate the existing outside checks). TLS and transport are the outside checks
 * `api.plain_http`, `headers.hsts` and `headers.https_redirect`; the sign-in cookie's flags are `session.cookie_flags`
 * (./auth-session.ts) and the outside check `api.private_cacheable`. This file references those rule ids and adds only
 * what they do not cover: how guessable the run's own ids and tokens are. It reads nothing but the run's own values and
 * stores only counts, never a token.
 */
import { notTestable, plant, result } from "./kit";
import type { ImpactFacts, SessionAccess, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";
import { EVIDENCE } from "./words";

/** Rule ids of the existing outside checks this file does not repeat. A report lists them beside this group. */
export const REFERENCED_CHECKS: readonly string[] = ["api.plain_http", "headers.hsts", "headers.https_redirect", "api.private_cacheable"];
/** A session value shorter than this many characters is too short to resist guessing. */
export const TOKEN_FLOOR = 20;
/** Two tokens that share at least this many leading characters look like they were not made at random. */
export const SHARED_PREFIX = 24;

const IMPACT: ImpactFacts = { what: "none", position: "self_registered", reach: "any_object_by_id", data: "ordinary" };
type Head = Omit<Technique, "run" | "chain">;

/** The length of the longest leading run of characters two strings share. Pure. */
export function sharedPrefix(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}
/** The session value among a role's sign-in headers (the cookie value, or a bearer token), or null. Pure. */
export function sessionValue(headers: Record<string, string> | null): string | null {
  if (!headers) return null;
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key === "cookie") { const m = /=([^;]{8,})/.exec(v); if (m) return m[1]!; }
    if (key === "authorization") { const m = /\s([A-Za-z0-9._~+/-]{8,}=*)\s*$/.exec(v); if (m) return m[1]!; }
  }
  return null;
}

const SEQUENTIAL: Head = {
  id: "crypto.sequential_ids", ruleId: "attack.predictable_token", title: "Record ids can be guessed by counting",
  invariants: ["tenant_read"], prerequisites: ["account_a", "test_object"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: [],
  oracle: "Two test records the run creates one after another get ids a fixed, small step apart, so the id of a record can be worked out from another.",
  shows: "that ids are handed out in order, so an id can be guessed", cannotShow: "that a guessed id is answered to another account: that is the access group's id-swap test, with a planted marker",
  best: "needs_validation", impact: { ...IMPACT, what: "read" }, owasp: "A04 / API1",
};
const SHORT_TOKEN: Head = {
  id: "crypto.short_token", ruleId: "attack.predictable_token", title: "A sign-in token is shorter than it should be",
  invariants: ["session"], prerequisites: ["account_a"], safetyClass: "read", classes: ["read"], payloads: ["observe.own_values"],
  oracle: `A session value of the run's own test account is fewer than ${TOKEN_FLOOR} characters, too short to resist guessing.`,
  shows: "that the session value is short enough to be worth guessing", cannotShow: "that it was actually guessed: nothing is tried",
  best: "needs_validation", impact: IMPACT, owasp: "A02 / API8",
};
const PREDICTABLE: Head = {
  id: "crypto.predictable_token", ruleId: "attack.predictable_token", title: "Sign-in tokens look alike across requests",
  invariants: ["session"], prerequisites: ["account_a", "own_test_account"], safetyClass: "read", classes: ["read"], payloads: ["observe.own_values"],
  oracle: `Two sign-ins of the run's own test account hand out session values that share at least ${SHARED_PREFIX} leading characters, a sign they are not made at random.`,
  shows: "that session values carry a long shared, predictable part", cannotShow: "that another account's token was worked out: nothing of anyone else's is read",
  best: "needs_validation", impact: IMPACT, owasp: "A02 / API8",
};

const session = (ctx: TechniqueContext): SessionAccess | null => ctx.session ?? null;

export const CRYPTO_TECHNIQUES: readonly Technique[] = [
  {
    ...SEQUENTIAL,
    chain: () => null,
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = SEQUENTIAL, o = target.object;
      if (!o) return notTestable(t, "the app model names no test record whose ids could be compared");
      const first = await plant(ctx, "a", o);
      if (!first.ok) return notTestable(t, (first as { why: string }).why);
      const second = await plant(ctx, "a", o);
      if (!second.ok) return notTestable(t, (second as { why: string }).why);
      const a = first.record.id, b = second.record.id;
      if (!/^\d{1,15}$/.test(a) || !/^\d{1,15}$/.test(b)) return result(t, "held", { reason: "the two new records got ids that are not plain numbers in order", route: o.create.path, as: "a" });
      const gap = Number(b) - Number(a);
      if (!(gap >= 1 && gap <= 3)) return result(t, "held", { reason: "the ids of two new records do not follow each other, so counting does not reach them", route: o.create.path, as: "a" });
      return result(t, "needs_validation", {
        reason: "two records created one after another got ids a small, fixed step apart; whether a counted id is answered to another account is the access group's test", method: "POST", route: o.create.path, as: "a", status: 201,
        payload: null, evidence: EVIDENCE.idsInOrder(gap), meta: { gap: String(gap), kind: "sequential ids", references: "see access.sequential_id for the marker-proven read" },
      });
    },
  },
  {
    ...SHORT_TOKEN,
    chain: () => null,
    run: async (ctx): Promise<TechniqueResult> => {
      const t = SHORT_TOKEN, s = session(ctx);
      if (!s) return notTestable(t, "this run cannot tell how the test account is signed in");
      const cred = await s.credential("a");
      if (!cred) return notTestable(t, "the test account is not set, or its sign-in failed");
      const value = sessionValue(cred);
      if (value === null) return notTestable(t, "the test account's session is not a cookie or bearer value this can measure");
      if (value.length >= TOKEN_FLOOR) return result(t, "held", { reason: `the session value is ${value.length} characters, at or above the floor of ${TOKEN_FLOOR}`, as: "a" });
      return result(t, "needs_validation", {
        reason: "an observation: the session value is short enough to be worth guessing. Nothing was guessed", as: "a", status: 200,
        payload: "observe.own_values", evidence: EVIDENCE.shortToken(value.length, TOKEN_FLOOR), meta: { chars: String(value.length), floor: String(TOKEN_FLOOR), kind: "observation" },
      });
    },
  },
  {
    ...PREDICTABLE,
    chain: () => null,
    run: async (ctx): Promise<TechniqueResult> => {
      const t = PREDICTABLE, s = session(ctx);
      if (!s) return notTestable(t, "this run cannot tell how the test account is signed in");
      if (!s.testAccount("a")) return notTestable(t, "account a is not marked as a test account of this run, so it is not signed in again");
      const first = sessionValue(await s.credential("a"));
      if (first === null) return notTestable(t, "the test account's session is not a cookie or bearer value this can measure");
      await s.fresh();
      const second = sessionValue(await s.credential("a"));
      if (second === null) return notTestable(t, "the second sign-in gave no session value to compare");
      if (first === second) return notTestable(t, "both sign-ins returned the same session value, so this run cannot tell whether it is fixed or cached, not random");
      const shared = sharedPrefix(first, second);
      if (shared < SHARED_PREFIX) return result(t, "held", { reason: `two sign-ins shared only ${shared} leading characters, below ${SHARED_PREFIX}`, as: "a" });
      return result(t, "needs_validation", {
        reason: "an observation: two session values of the same account share a long leading part, a sign they are not made at random. Nothing was worked out from it", as: "a", status: 200,
        payload: "observe.own_values", evidence: EVIDENCE.tokensAlike(shared), meta: { shared: String(shared), kind: "observation" },
      });
    },
  },
];
