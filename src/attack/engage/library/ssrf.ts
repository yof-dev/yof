/**
 * yof engagement, attack library: SERVER-SIDE FETCHES (SSRF). A parameter the server fetches is given ONE address:
 * the yof canary, with a token of this request. The canary is a public yof address that counts calls per token and
 * keeps nothing else (never a body).
 *
 *   ssrf.canary   the request names the canary; afterwards the canary is asked whether it was called
 *
 * NEVER SENT, in any spelling: a cloud metadata address, a private or loopback address, a link-local address, the
 * app's own host. The library holds no such address and refuses a canary address that is one (canaryAllowed). The
 * record's own check refuses a metadata address again, on every request.
 *
 * FAIL CLOSED. Without a canary address and a way to ask it, the test is "not testable". It never passes unchecked.
 *
 * WHAT A HIT MEANS. The server fetched an address the request chose. Where the app model says the parameter may only
 * fetch listed hosts, that is the finding. Where fetching any address is the feature (a link preview, an importer),
 * a hit is only what the feature does: it "needs validation", and the report says that internal addresses were not
 * tried, because yof never sends one.
 */
import type { ReplaySpec } from "../../replay";
import { METADATA_ADDRESS } from "../roe";
import { classFor, fillRequest, notTestable, replayPath, result, routeOf, sendRequest, specOf, unusable } from "./kit";
import type { FetchSpec, ImpactFacts, Technique, TechniqueResult } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" };
const PRIVATE_NAME = /(?:^|\.)(?:localhost|local|localdomain|internal|intranet|lan|corp|home|test|invalid|example)$/;

/**
 * May this address be used as the canary? Only https, a public host NAME (never a number in any form), not the app
 * under test, and not a name of a private or reserved zone. Returns the address without a trailing slash, or null. Pure.
 */
export function canaryAllowed(base: string, targetHost: string): string | null {
  let u: URL;
  try { u = new URL(base); } catch { return null; }
  const host = u.hostname.toLowerCase();
  if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return null;
  if (!/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return null;   // a name with a letters-only last part: never an IPv4, IPv6, decimal or hex address
  if (PRIVATE_NAME.test(host) || METADATA_ADDRESS.test(base) || METADATA_ADDRESS.test(host)) return null;
  const target = targetHost.toLowerCase();
  if (host === target || host.endsWith(`.${target}`) || target.endsWith(`.${host}`)) return null;
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}
export const canaryUrl = (base: string, token: string): string => `${base}/${token}`;

type Head = Omit<Technique, "run" | "chain">;
const CANARY: Head = {
  id: "ssrf.canary", ruleId: "attack.server_fetch", title: "The server fetches any address a request names",
  invariants: ["fetch_restricted"], prerequisites: ["account_a", "fetch_parameter", "canary_address"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: ["ssrf.canary"],
  oracle: "The canary reports no call for a fresh token; the request names the canary address with that token; the canary then reports a call. Shown twice, with two tokens.",
  shows: "that the server fetched an address the request chose", cannotShow: "that internal addresses can be reached: none is ever sent",
  best: "confirmed", impact: IMPACT, owasp: "A10 / API7",
};
const chain = (f: FetchSpec, accounts?: ReplaySpec["accounts"]): ReplaySpec | null => {
  const base = f.canaryBase ? canaryAllowed(f.canaryBase, "") : null;
  if (!base) return null;
  const r = f.request;
  // The address is fixed text in the step; only the token is a variable.
  const put = (s: string, enc: (x: string) => string) => s.split("{{url}}").join(`${enc(`${base}/`)}{{canary}}`);
  return specOf(CANARY, ["canary"], accounts, [{
    as: f.as ?? "a", method: r.method, path: replayPath(put(r.path, encodeURIComponent)), ...(r.body !== undefined ? { body: put(r.body, (x) => JSON.stringify(x).slice(1, -1)) } : {}),
    expect: { kind: "canary_hit", token: "{{canary}}" },
  }]);
};

export const SSRF_TECHNIQUES: readonly Technique[] = [
  {
    ...CANARY,
    chain: (target, accounts) => (target.fetch ? chain(target.fetch, accounts) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = CANARY, f = target.fetch;
      if (!f) return notTestable(t, "the app model names no parameter the server fetches");
      if (!ctx.canary) return notTestable(t, "no canary address is set for this run, so a call could not be checked");
      const base = canaryAllowed(ctx.canary.base, ctx.host);
      if (!base) return notTestable(t, "the canary address of this run is not a public https address of its own, so it is not used");
      const route = routeOf(f.request.path), method = f.request.method, as = f.as ?? "a";
      const once = async (): Promise<{ hit: boolean; status: number } | string> => {
        const token = `yof${ctx.random()}${ctx.random()}`;
        const before = await ctx.canary!.hits(token);
        if (before === null) return "the canary did not answer, so a call could not be checked";
        if (before > 0) return "the canary already reports a call for a token that was never sent";
        const r = await sendRequest(ctx, as, fillRequest(f.request, { url: canaryUrl(base, token) }), { cls: classFor(method), leg: "test", purpose: method === "GET" || method === "HEAD" ? "read" : "create" });
        if (r === null) return "the test account is not set, or its sign-in failed";
        if (unusable(r)) return "the request got no usable answer";
        const after = await ctx.canary!.hits(token);
        if (after === null) return "the canary did not answer, so a call could not be checked";
        return { hit: after > 0, status: r.status };
      };
      const first = await once();
      if (typeof first === "string") return notTestable(t, first);
      if (!first.hit) return result(t, "held", { reason: "the canary was not called", method, route, as, status: first.status });
      const second = await once();
      const twice = typeof second !== "string" && second.hit;
      const finding = f.restricted && twice;
      return result(t, finding ? "violated" : "needs_validation", {
        reason: finding ? "the canary was called twice, with two tokens, through a parameter the app model says may only fetch listed hosts"
          : !twice ? "it showed once and not a second time" : "the server fetched the canary, which is what this feature does unless it is meant to be limited to listed hosts; internal addresses were not tried, because none is ever sent",
        method, route, as, status: first.status, payload: "ssrf.canary", evidence: EVIDENCE.canaryCalled(f.restricted), meta: { payload: "ssrf.canary", proof: "canary", kind: f.restricted ? "listed hosts only" : "any address" },
        replay: chain({ ...f, canaryBase: base }, ctx.accounts),
      });
    },
  },
];
