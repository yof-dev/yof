/**
 * yof engagement, open core: the ANOMALY DETECTORS (docs/YOF_ENGAGEMENT_DESIGN.md addendum, "Anomaly discovery").
 *
 * Code only. Each detector reads the behaviour baseline and the raw observations (./baseline.ts) and asks a question:
 *
 *   field_exposed        a field one route returns to a lower role that a sibling route reserves for a higher one
 *   sibling_open         one route answers a role that its siblings of the same object refuse
 *   existence_oracle     an id that exists is refused differently from one that does not (403 here, 404 there)
 *   account_enumeration  a sign-in or reset route answers an existing account differently from a made-up one
 *   timing_gap           two kinds of request answer at measurably different speeds (a hypothesis, and never on a
 *                        production host, owner decision D8)
 *
 * AN ANOMALY IS NEVER A FINDING. It is a question the planner turns into a WORK UNIT (`suggests` names the invariant
 * kind to test), and only a planted-marker proof from the library makes it a finding. The report counts "anomalies
 * seen / tested / proven", nothing more. Pure: the same observations always give the same anomalies.
 */
import type { As, Method } from "../http";
import { buildBaseline, median, PRIVATE_FIELD, ROLE_RANK, fieldSet, type Observation, type RouteBaseline } from "./baseline";
import type { InvariantKind } from "./library/types";

export interface Anomaly {
  kind: "field_exposed" | "sibling_open" | "existence_oracle" | "account_enumeration" | "timing_gap";
  route: string;
  method: Method;
  /** The roles the anomaly is about. */
  roles: As[];
  /** The invariant kind a work unit would test this as. Never a finding until a marker proves it. */
  suggests: InvariantKind;
  /** yof's own fixed words. Never a value from any answer. */
  evidence: string;
}

const ok = (s: number) => s >= 200 && s < 300;
const refused = (s: number) => s === 401 || s === 403 || s === 404;
/** The static part of a route: id placeholders dropped, so `/api/notes` and `/api/notes/{id}` share one object. Pure. */
export const objectStem = (route: string): string =>
  "/" + route.split("?")[0]!.split("/").filter((s) => s && !/^\{.*\}$/.test(s)).join("/");
/** The parent section of a route: the static part with its last segment dropped, so `/api/admin/users` and `/api/admin/stats` are siblings. Pure. */
export const parentPath = (route: string): string => {
  const parts = objectStem(route).split("/").filter(Boolean);
  return "/" + parts.slice(0, -1).join("/");
};

export interface AnomalyOptions {
  /** On a production host the timing detector is turned off (owner decision D8). */
  production?: boolean;
  /** The timing detector needs at least this many samples on each side (default 15). */
  timingSamples?: number;
  /** A median gap of at least this many milliseconds is reported as a timing hypothesis (default 400). */
  timingGapMs?: number;
}

// ── field_exposed ────────────────────────────────────────────────────────────────────────────────────────────────
function fieldExposed(baselines: readonly RouteBaseline[]): Anomaly[] {
  const out: Anomaly[] = [];
  const groups = new Map<string, RouteBaseline[]>();
  for (const b of baselines) { const k = objectStem(b.route); (groups.get(k) ?? groups.set(k, []).get(k)!).push(b); }
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    // For each private field, the lowest rank each route grants it to.
    const perField = new Map<string, Map<string, { route: RouteBaseline; rank: number; roles: As[] }>>();
    for (const b of group) for (const r of b.roles) {
      if (!ok(r.status)) continue;
      for (const f of r.fields) {
        if (!PRIVATE_FIELD.test(f)) continue;
        const byRoute = perField.get(f) ?? perField.set(f, new Map()).get(f)!;
        const key = `${b.method} ${b.route}`;
        const cur = byRoute.get(key);
        if (!cur || ROLE_RANK[r.role] < cur.rank) byRoute.set(key, { route: b, rank: ROLE_RANK[r.role], roles: [r.role] });
        else if (ROLE_RANK[r.role] === cur.rank && !cur.roles.includes(r.role)) cur.roles.push(r.role);
      }
    }
    for (const [field, byRoute] of perField) {
      const grants = [...byRoute.values()];
      if (grants.length < 2) continue;
      const lowest = Math.min(...grants.map((g) => g.rank));
      const highest = Math.max(...grants.map((g) => g.rank));
      if (lowest >= highest) continue;   // every route grants it to the same rank: nothing reserved
      for (const g of grants) if (g.rank === lowest) {
        out.push({ kind: "field_exposed", route: g.route.route, method: g.route.method, roles: g.roles.sort(),
          suggests: "tenant_read", evidence: `the field "${field}" is returned to a lower role here than on sibling routes of the same object` });
      }
    }
  }
  return out;
}

// ── sibling_open ─────────────────────────────────────────────────────────────────────────────────────────────────
function siblingOpen(baselines: readonly RouteBaseline[]): Anomaly[] {
  const out: Anomaly[] = [];
  const groups = new Map<string, RouteBaseline[]>();
  for (const b of baselines) { const k = parentPath(b.route); (groups.get(k) ?? groups.set(k, []).get(k)!).push(b); }
  for (const group of groups.values()) {
    if (group.length < 3) continue;
    const roles = new Set<As>(group.flatMap((b) => b.roles.map((r) => r.role)));
    for (const role of roles) {
      const granted = group.filter((b) => b.roles.some((r) => r.role === role && ok(r.status)));
      const refusedOn = group.filter((b) => b.roles.some((r) => r.role === role && refused(r.status)));
      if (granted.length && refusedOn.length > granted.length && refusedOn.length >= 2) {
        for (const b of granted) out.push({ kind: "sibling_open", route: b.route, method: b.method, roles: [role],
          suggests: role === "anon" ? "auth_required" : "role_gate",
          evidence: `this route answers ${role === "anon" ? "a request with no sign-in" : `the ${role} role`} while ${refusedOn.length} sibling routes of the same object refuse it` });
      }
    }
  }
  return out;
}

// ── existence_oracle and account_enumeration (need subject-tagged observations) ──────────────────────────────────
function byRouteRole(observations: readonly Observation[]): Map<string, Observation[]> {
  const m = new Map<string, Observation[]>();
  for (const o of observations) { const k = `${o.method} ${o.route}\u0000${o.role}`; (m.get(k) ?? m.set(k, []).get(k)!).push(o); }
  return m;
}
function existenceAndEnum(observations: readonly Observation[]): Anomaly[] {
  const out: Anomaly[] = [];
  for (const obs of byRouteRole(observations).values()) {
    const exists = obs.filter((o) => o.subject === "exists");
    const missing = obs.filter((o) => o.subject === "missing");
    if (!exists.length || !missing.length) continue;
    const e = exists[0]!, m = missing[0]!;
    const method = e.method, route = e.route, roles = [e.role];
    const statusDiffers = e.status !== m.status;
    const fieldsDiffer = JSON.stringify(fieldSet(e.body)) !== JSON.stringify(fieldSet(m.body));
    if (method === "GET") {
      // An existing record is refused (it is there, you may not have it) but a missing one is a plain 404.
      if ((e.status === 401 || e.status === 403) && m.status === 404) {
        out.push({ kind: "existence_oracle", route, method, roles, suggests: "tenant_read",
          evidence: "a record that exists is refused with a different status than one that does not, which tells an outsider the record is there" });
      }
    } else if (statusDiffers || fieldsDiffer) {
      // A sign-in or reset route that answers an existing account differently from a made-up one.
      out.push({ kind: "account_enumeration", route, method, roles, suggests: "session",
        evidence: "this route answers an account that exists differently from one that does not, which lets an outsider learn which accounts are real" });
    }
  }
  return out;
}

// ── timing_gap ───────────────────────────────────────────────────────────────────────────────────────────────────
function timingGap(observations: readonly Observation[], opts: AnomalyOptions): Anomaly[] {
  const need = opts.timingSamples ?? 15, gap = opts.timingGapMs ?? 400;
  const out: Anomaly[] = [];
  for (const obs of byRouteRole(observations).values()) {
    const a = obs.filter((o) => o.subject === "exists").map((o) => o.ms);
    const b = obs.filter((o) => o.subject === "missing").map((o) => o.ms);
    if (a.length < need || b.length < need) continue;
    if (Math.abs(median(a) - median(b)) >= gap) {
      const first = obs[0]!;
      out.push({ kind: "timing_gap", route: first.route, method: first.method, roles: [first.role], suggests: "input_is_data",
        evidence: `two kinds of request answer about ${Math.abs(median(a) - median(b))} ms apart; a timing difference is only a hypothesis and is never tested on a production host` });
    }
  }
  return out;
}

/** Every anomaly the detectors see in the observations. Pure. The timing detector is off on a production host. */
export function findAnomalies(observations: readonly Observation[], opts: AnomalyOptions = {}): Anomaly[] {
  const baselines = buildBaseline(observations);
  return [
    ...fieldExposed(baselines),
    ...siblingOpen(baselines),
    ...existenceAndEnum(observations),
    ...(opts.production ? [] : timingGap(observations, opts)),
  ];
}
