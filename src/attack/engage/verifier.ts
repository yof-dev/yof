/**
 * yof engagement, open core: the verifier. A second, separate pass that tries to REFUTE a result.
 *
 * It is given the replay spec and nothing else: not the finder's conclusion, not its verdict, not its evidence. It
 * signs the test accounts in again, plants a NEW marker in a NEW record, and runs the chain in its own order:
 *
 *   1. the other role sends the test request BEFORE the owner has read the new record;
 *   2. the owner sends the identical request (positive control);
 *   3. the other role asks for an id that does not exist (negative control);
 *   4. the other role sends the test request once more.
 *
 * REFUTATION RULES, plain code, in this order. One that applies decides, and the result is rejected:
 *
 *   marker_reflected        the test request itself carries the marker, so an answer that shows it proves nothing
 *   same_tenant             the two accounts are in the same tenant: one may read the other's record
 *   marked_public           the customer marked this object as public on purpose
 *   cache_served            the other role saw the marker only after the owner had read the record, and a request
 *                           with a cache-buster did not show it (or the answer says it came from a cache: `age`,
 *                           `x-cache`, `cf-cache-status`): a cache gave out the owner's answer
 *   negative_control_failed the app answers the same way for an id that does not exist
 *   not_reproduced          the other role did not see the new marker
 *
 * When no rule refutes it, and both controls worked, the result STANDS. When the verifier cannot tell (the spec plants
 * no marker, the owner cannot read its own new record, an account is missing, the app did not answer) the result is
 * UNDECIDED: it stays "needs validation". Undecided is never worded as confirmed, and nothing waits for a person.
 *
 * This part is rules only. A model step for the undecided comes in a later stage; this file calls none.
 * What it verifies today: READ differentials (another role reads a planted marker). A spec of another shape is undecided.
 */
import type { As, HttpAnswer } from "../http";
import { readPath } from "../probes";
import { isDerive, type ReplaySpec, type ReplayStep } from "../replay";
import { missingIdLike, refusedDifferently, type Leg } from "./differential";
import { cleanUpMarkers, type EngageIo, type MarkerRegistry, type MarkerRole } from "./markers";
import { fillBody, fillPath } from "./spec";

export type RefutationRule = "marker_reflected" | "same_tenant" | "marked_public" | "cache_served" | "negative_control_failed" | "not_reproduced";
export const REFUTATION_RULES: readonly RefutationRule[] = ["marker_reflected", "same_tenant", "marked_public", "cache_served", "negative_control_failed", "not_reproduced"];
export type Undecided = "no_marker" | "not_supported" | "no_account" | "setup_failed" | "positive_control_failed" | "no_answer";

/** What is known about the accounts and the app from outside the spec (the config, the customer's own answers). */
export interface VerifierFacts {
  /** A tenant label per role. Two roles with the same label share a tenant. A role without a label is unknown. */
  tenants?: Partial<Record<As, string>>;
  /** Routes (with {id}) the customer marked as public on purpose. */
  publicRoutes?: readonly string[];
}

export interface VerifierResult {
  /** true = could not be refuted and both controls worked. false = refuted. null = undecided. */
  stands: boolean | null;
  refutedBy: RefutationRule | null;
  undecided: Undecided | null;
  notes: string[];
  /** The verifier's own marker (never the finder's). */
  marker: string | null;
  cleanup: { planted: number; deleted: number; left: { route: string; why: string }[] };
}

const ok = (s: number) => s >= 200 && s < 300;
const unusable = (l: { status: number } | null): boolean => !l || l.status === 0 || l.status === 429 || l.status === 503;
const routeOf = (path: string) => path.split("?")[0]!.replace(/\{\{(\w+)\}\}/g, "{$1}");

// ── Pure rules ───────────────────────────────────────────────────────────────────────────────────────────────────
export interface SpecLegs { markerVar: string; idVar: string; owner: MarkerRole; other: As; plant: ReplayStep; before: ReplayStep[]; test: ReplayStep; deleteRoute: string }

/** Find the parts of a read differential in a spec. A string = why it cannot be verified (or is refuted) as it stands. Pure. */
export function specLegs(spec: ReplaySpec): SpecLegs | { refuted: "marker_reflected" } | { undecided: Undecided } {
  const steps = spec.steps.filter((s): s is ReplayStep => !isDerive(s));
  const test = steps.find((s) => s.leg === "test") ?? steps.find((s) => !s.setup && !s.cleanup && (s.expect?.kind === "marker_absent" || s.expect?.kind === "not_contains") && /^\{\{\w+\}\}$/.test(s.expect.value));
  if (!test || !test.expect || (test.expect.kind !== "marker_absent" && test.expect.kind !== "not_contains")) return { undecided: "no_marker" };
  const markerVar = /^\{\{(\w+)\}\}$/.exec(test.expect.value)?.[1];
  if (!markerVar || !spec.vars.includes(markerVar)) return { undecided: "no_marker" };
  const carries = (s: string | undefined) => !!s && s.includes(`{{${markerVar}}}`);
  if (carries(test.path) || carries(test.body) || Object.values(test.headers ?? {}).some(carries)) return { refuted: "marker_reflected" };
  if (test.method !== "GET" && test.method !== "HEAD") return { undecided: "not_supported" };
  const at = steps.indexOf(test);
  const plant = steps.slice(0, at).find((s) => s.setup && s.method === "POST" && carries(s.body) && !!s.save);
  if (!plant || !plant.save) return { undecided: steps.some((s) => carries(s.body)) ? "not_supported" : "no_marker" };
  if (plant.as === "anon") return { undecided: "not_supported" };
  const idVar = plant.save.name;
  const del = steps.find((s) => s.cleanup && s.method === "DELETE" && s.as === plant.as && s.path.includes(`{{${idVar}}}`));
  // A record that could not be deleted again is never created.
  if (!del) return { undecided: "not_supported" };
  return { markerVar, idVar, owner: plant.as, other: test.as, plant, before: steps.slice(0, at).filter((s) => s.setup && s !== plant), test, deleteRoute: routeOf(del.path).split(`{${idVar}}`).join("{id}") };
}

export const sameTenant = (facts: VerifierFacts, a: As, b: As): boolean => { const x = facts.tenants?.[a], y = facts.tenants?.[b]; return !!x && !!y && x === y; };
export const markedPublic = (facts: VerifierFacts, step: Pick<ReplayStep, "path">, idVar: string): boolean => {
  const route = routeOf(step.path).split(`{${idVar}}`).join("{id}");
  return (facts.publicRoutes ?? []).some((p) => p.split("?")[0] === route);
};
/** Does the answer say it came from a cache? */
export function cacheSaysHit(header: (name: string) => string | null): boolean {
  const age = Number(header("age") ?? "");
  if (Number.isFinite(age) && age > 0) return true;
  return /\bhit\b/i.test(header("x-cache") ?? "") || /^(?:hit|revalidated|updating|stale)$/i.test((header("cf-cache-status") ?? "").trim());
}

export interface VerifierLeg extends Leg { cacheHit: boolean }
export interface Observations {
  marker: string;
  /** The other role's request, sent before the owner read the new record. */
  first: VerifierLeg | null;
  positive: VerifierLeg | null;
  negative: VerifierLeg | null;
  /** The other role's request, sent again after the owner's read. */
  second: VerifierLeg | null;
  /** Only when the marker showed in `second` and not in `first`: the same request with a cache-buster. */
  busted: VerifierLeg | null;
}
export type VerifierDecision = { stands: true; notes: string[] } | { stands: false; refutedBy: RefutationRule; notes: string[] } | { stands: null; undecided: Undecided; notes: string[] };

/** The verdict over what the verifier's own run saw. Pure. */
export function decideVerification(o: Observations): VerifierDecision {
  const sees = (l: Leg | null) => !!l && ok(l.status) && l.body.includes(o.marker);
  const notes: string[] = [];
  if (unusable(o.first)) return { stands: null, undecided: "no_answer", notes };
  if (!sees(o.positive)) {
    // The owner cannot read its own new record: nothing can be judged, in either direction.
    if (!sees(o.first)) return { stands: null, undecided: unusable(o.positive) ? "no_answer" : "positive_control_failed", notes };
    notes.push("the other role saw the marker although the owner's own request did not");
    return { stands: null, undecided: "positive_control_failed", notes };
  }
  if (!sees(o.first)) {
    if (!sees(o.second)) return { stands: false, refutedBy: "not_reproduced", notes };
    // Seen only after the owner read it: a cache, unless a cache-busted request shows it too.
    if (!sees(o.busted) || o.busted!.cacheHit || o.second!.cacheHit) return { stands: false, refutedBy: "cache_served", notes };
    notes.push("the other role saw the marker only after the owner had read the record; a request with a cache-buster showed it too");
  } else if (!sees(o.second)) {
    return { stands: false, refutedBy: "not_reproduced", notes };
  }
  if (unusable(o.negative)) return { stands: null, undecided: "no_answer", notes };
  const shown = sees(o.first) ? o.first! : o.second!;
  if (!refusedDifferently(o.negative!, shown, o.marker)) return { stands: false, refutedBy: "negative_control_failed", notes };
  if (o.first?.cacheHit) notes.push("the answer carried a cache header, but the record was new and the owner had not read it yet");
  return { stands: true, notes };
}

// ── I/O ──────────────────────────────────────────────────────────────────────────────────────────────────────────
export interface VerifierDeps {
  /** A registry with a NEW run nonce: the verifier's markers are never the finder's. */
  registry: MarkerRegistry;
  random: () => string;
  facts?: VerifierFacts;
  /** Sign every test account in again (new sessions) before the first request. */
  newSessions?: () => void | Promise<void>;
}

const NO_CACHE = { "Cache-Control": "no-cache", Pragma: "no-cache" };
const leg = (r: HttpAnswer | null): VerifierLeg | null => (r ? { status: r.status, body: r.body, cacheHit: cacheSaysHit((n) => r.headers.get(n)) } : null);

/** Try to refute the result this spec stands for. It never receives the finder's conclusion: the signature has no place for one. */
export async function verifySpec(spec: ReplaySpec, io: EngageIo, deps: VerifierDeps): Promise<VerifierResult> {
  const facts = deps.facts ?? {};
  const none = { planted: 0, deleted: 0, left: [] as { route: string; why: string }[] };
  const end = (d: VerifierDecision, marker: string | null, cleanup = none): VerifierResult => ({
    stands: d.stands, refutedBy: d.stands === false ? d.refutedBy : null, undecided: d.stands === null ? d.undecided : null, notes: d.notes, marker, cleanup,
  });
  const legs = specLegs(spec);
  if ("refuted" in legs) return end({ stands: false, refutedBy: legs.refuted, notes: [] }, null);
  if ("undecided" in legs) return end({ stands: null, undecided: legs.undecided, notes: [] }, null);
  if (sameTenant(facts, legs.owner, legs.other)) return end({ stands: false, refutedBy: "same_tenant", notes: [] }, null);
  if (markedPublic(facts, legs.test, legs.idVar)) return end({ stands: false, refutedBy: "marked_public", notes: [] }, null);

  await deps.newSessions?.();
  const marker = deps.registry.next(legs.owner);
  const vars: Record<string, string> = {};
  for (const v of spec.vars) vars[v] = v === legs.markerVar ? marker : `yof${v}${deps.random()}`;
  let decision: VerifierDecision;
  try {
    decision = await (async (): Promise<VerifierDecision> => {
      // Setup steps before the plant (rare), then the plant itself: a new record with the new marker.
      for (const st of [...legs.before, legs.plant]) {
        const isPlant = st === legs.plant;
        const allowed = io.pathAllowed ?? (() => true);
        if (isPlant && (!allowed(st.path) || !allowed(legs.deleteRoute))) return { stands: null, undecided: "not_supported", notes: ["the rules forbid a path this spec needs"] };
        const r = await io.send(st.as, st.method, fillPath(st.path, vars), { ...(st.body !== undefined ? { body: fillBody(st.body, vars) } : {}), purpose: st.method === "POST" ? "create" : "owned", cls: "write_own_test_records", leg: "plant" });
        if (r === null) return { stands: null, undecided: "no_account", notes: [] };
        if (!ok(r.status)) return { stands: null, undecided: "setup_failed", notes: [`a setup step answered HTTP ${r.status}`] };
        if (st.save) {
          const id = readPath(r.body, st.save.from);
          if (!id || id.length > 200) return { stands: null, undecided: "setup_failed", notes: ["the new record's id could not be read"] };
          vars[st.save.name] = id;
          io.own(id);
          if (isPlant) deps.registry.register(marker, { id, createRoute: st.path, readRoute: legs.test.path.includes(`{{${legs.idVar}}}`) ? routeOf(legs.test.path).split(`{${legs.idVar}}`).join("{id}") : null, deleteRoute: legs.deleteRoute });
        }
      }
      const t = legs.test;
      const path = fillPath(t.path, vars);
      const send = (as: As, p: string, tag: "test" | "positive" | "negative") => io.send(as, t.method, p, { headers: { ...(t.headers ?? {}), ...NO_CACHE }, cls: "read", leg: tag });
      const firstRaw = await send(legs.other, path, "test");
      if (firstRaw === null) return { stands: null, undecided: "no_account", notes: [] };
      const positive = await send(legs.owner, path, "positive");
      if (positive === null) return { stands: null, undecided: "no_account", notes: [] };
      const second = await send(legs.other, path, "test");
      const first = leg(firstRaw);
      const sees = (l: HttpAnswer | null) => !!l && ok(l.status) && l.body.includes(marker);
      // A cache-busted request only where it decides something: the marker showed after the owner's read, not before.
      const busted = !sees(firstRaw) && sees(second) ? await send(legs.other, `${path}${path.includes("?") ? "&" : "?"}yofcb=${deps.random()}`, "test") : null;
      const id = vars[legs.idVar] ?? "";
      const negative = sees(firstRaw) || sees(second)
        ? await send(legs.other, t.path.includes(`{{${legs.idVar}}}`) ? fillPath(t.path, { ...vars, [legs.idVar]: missingIdLike(id, deps.random) }) : `${path.split("?")[0]!.replace(/\/$/, "")}/${missingIdLike(id, deps.random)}`, "negative")
        : null;
      return decideVerification({ marker, first, positive: leg(positive), negative: leg(negative), second: leg(second), busted: leg(busted) });
    })();
  } finally {
    // Whatever happened: delete exactly what this pass planted.
    await cleanUpMarkers(io, deps.registry).catch(() => undefined);
  }
  return end(decision, marker, deps.registry.summary());
}
