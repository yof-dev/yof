/**
 * yof engagement, open core: the BEHAVIOUR BASELINE (docs/YOF_ENGAGEMENT_DESIGN.md addendum, "Anomaly discovery").
 *
 * A baseline is, per role and route, what an ordinary request gets back: the status, the field set (the top-level keys
 * of the answer, never its values), a coarse size bucket, and the median time of the samples. It is built from
 * observations the executor already recorded; it sends nothing itself and reads no value, only the shape.
 *
 * It is the quiet "before" the anomaly detectors (./anomaly.ts) compare against. Nothing here is a finding: a baseline
 * is a description, and an anomaly is a question, not an answer. Pure: the same observations always give the same
 * baseline.
 */
import type { As, Method } from "../http";

/** One recorded request/answer, as the baseline needs it (never a value, only status, the body's shape and the time). */
export interface Observation {
  role: As;
  method: Method;
  /** The route as written, with id placeholders kept (`/api/notes/{id}`), never a real id. */
  route: string;
  status: number;
  /** The answer body (read only for its field names and size; never stored by the baseline). */
  body: string;
  /** How long the request took, in milliseconds. */
  ms: number;
  /** For the account-enumeration and existence detectors: whether the thing asked for exists. */
  subject?: "exists" | "missing";
}

export type SizeBucket = "empty" | "small" | "medium" | "large";
export const sizeBucket = (length: number): SizeBucket =>
  length === 0 ? "empty" : length < 200 ? "small" : length < 4000 ? "medium" : "large";

/** The top-level field names of a JSON answer: an object's own keys, or the union of the keys of an array of objects. Pure. */
export function fieldSet(body: string): string[] {
  let v: unknown;
  try { v = JSON.parse(body); } catch { return []; }
  const keys = new Set<string>();
  const add = (x: unknown): void => { if (x && typeof x === "object" && !Array.isArray(x)) for (const k of Object.keys(x)) keys.add(k); };
  if (Array.isArray(v)) for (const el of v.slice(0, 50)) add(el);
  else add(v);
  return [...keys].sort();
}

/** The median of a list of numbers (0 for an empty list). Pure. */
export function median(ms: readonly number[]): number {
  if (!ms.length) return 0;
  const s = [...ms].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : Math.round((s[mid - 1]! + s[mid]!) / 2);
}

export interface RoleStat {
  role: As;
  /** The most common status for this role on this route. */
  status: number;
  fields: string[];
  size: SizeBucket;
  medianMs: number;
  samples: number;
}
export interface RouteBaseline { route: string; method: Method; roles: RoleStat[] }

const keyOf = (o: Observation): string => `${o.method} ${o.route}`;
const mode = <T>(xs: readonly T[]): T => {
  const count = new Map<T, number>();
  let best: T = xs[0]!, top = 0;
  for (const x of xs) { const n = (count.get(x) ?? 0) + 1; count.set(x, n); if (n > top) { top = n; best = x; } }
  return best;
};

/** Build the per-(role, route) baseline from observations. Only successful answers contribute a field set. Pure. */
export function buildBaseline(observations: readonly Observation[]): RouteBaseline[] {
  const byRoute = new Map<string, Observation[]>();
  for (const o of observations) { const k = keyOf(o); (byRoute.get(k) ?? byRoute.set(k, []).get(k)!).push(o); }
  const out: RouteBaseline[] = [];
  for (const group of byRoute.values()) {
    const first = group[0]!;
    const byRole = new Map<As, Observation[]>();
    for (const o of group) (byRole.get(o.role) ?? byRole.set(o.role, []).get(o.role)!).push(o);
    const roles: RoleStat[] = [];
    for (const [role, obs] of byRole) {
      const status = mode(obs.map((o) => o.status));
      const ok = obs.filter((o) => o.status >= 200 && o.status < 300);
      const fieldsFrom = (ok.length ? ok : obs);
      const fields = [...new Set(fieldsFrom.flatMap((o) => fieldSet(o.body)))].sort();
      roles.push({ role, status, fields, size: sizeBucket(median(fieldsFrom.map((o) => o.body.length))), medianMs: median(obs.map((o) => o.ms)), samples: obs.length });
    }
    out.push({ route: first.route, method: first.method, roles: roles.sort((a, b) => a.role.localeCompare(b.role)) });
  }
  return out.sort((a, b) => keyOf({ method: a.method, route: a.route } as Observation).localeCompare(keyOf({ method: b.method, route: b.route } as Observation)));
}

/** The rank of a role, lowest (nobody) to highest (admin). Two members share a rank. Pure. */
export const ROLE_RANK: Record<As, number> = { anon: 0, viewer: 1, a: 2, b: 2, admin: 3 };
/** Field names that usually belong to a higher role or to the owner only (reused from the checks' private-column list). */
export const PRIVATE_FIELD = /^(?:role|roles|is_admin|isadmin|admin|owner|owner_id|ownerid|user_id|userid|email|phone|ssn|token|secret|api_key|apikey|password|price|cost|salary|balance|workspace_id|org_id|tenant_id|internal|permissions|scopes)$/i;
