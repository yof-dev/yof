/**
 * yof engagement, attack library: THE REGISTRY. Every technique of every class, in one list, and a PURE function that
 * says, for an invariant kind and a confirmed rules-of-engagement record, which techniques may run against a host and
 * which are refused, with the reason.
 *
 * THE RULE (owner: a technique whose class the record does not allow is reported "not allowed by your rules", never
 * run). techniqueAllowed checks, against the record's entry for the host:
 *   - the host is in scope and proven;
 *   - every safety class the technique's requests carry is switched on for that host;
 *   - no class the technique needs is one the host's environment never allows (timing and race on production, D8);
 *   - the technique names no action the record forbids.
 * techniquesFor splits the techniques of a kind into those that may run and those that are refused. runTechnique makes
 * the same check before a technique runs, so a refused technique is a row with its reason and sends nothing.
 */
import { NEVER_ON_PRODUCTION, type EngageRoe, type EngageRoeHost } from "../roe";
import { ACCESS_TECHNIQUES } from "./access";
import { AI_TECHNIQUES } from "./ai";
import { AUTH_SESSION_TECHNIQUES } from "./auth-session";
import { CRYPTO_TECHNIQUES } from "./crypto";
import { CSRF_TECHNIQUES } from "./csrf";
import { DESERIALIZATION_TECHNIQUES } from "./deserialization";
import { FILE_TECHNIQUES } from "./files";
import { INJECTION_TECHNIQUES } from "./injection";
import { LOGIC_TECHNIQUES } from "./logic";
import { MASS_ASSIGN_TECHNIQUES } from "./mass-assign";
import { RACE_TECHNIQUES } from "./race";
import { SECRETS_CONFIG_TECHNIQUES } from "./secrets-config";
import { SSRF_TECHNIQUES } from "./ssrf";
import { SUPPLY_TECHNIQUES } from "./supply";
import { notTestable, result } from "./kit";
import type { InvariantKind, Technique, TechniqueContext, TechniqueInvariant, TechniqueResult, TechniqueTarget } from "./types";

/** Every technique, grouped by file, in a stable order. */
export const TECHNIQUES_BY_CLASS = {
  access: ACCESS_TECHNIQUES,
  mass_assign: MASS_ASSIGN_TECHNIQUES,
  injection: INJECTION_TECHNIQUES,
  csrf: CSRF_TECHNIQUES,
  auth_session: AUTH_SESSION_TECHNIQUES,
  logic: LOGIC_TECHNIQUES,
  race: RACE_TECHNIQUES,
  files: FILE_TECHNIQUES,
  ssrf: SSRF_TECHNIQUES,
  deserialization: DESERIALIZATION_TECHNIQUES,
  crypto: CRYPTO_TECHNIQUES,
  secrets_config: SECRETS_CONFIG_TECHNIQUES,
  supply: SUPPLY_TECHNIQUES,
  ai: AI_TECHNIQUES,
} as const;

export const ALL_TECHNIQUES: readonly Technique[] = Object.values(TECHNIQUES_BY_CLASS).flat();

/** A technique by its id. Ids are unique across the library (a test pins this). */
export const TECHNIQUE_BY_ID: Readonly<Record<string, Technique>> = Object.fromEntries(ALL_TECHNIQUES.map((t) => [t.id, t]));

/** The library version, bumped when a technique or payload changes (the report and the benchmark print it). */
export const LIBRARY_VERSION = "2026-12-14.1";

/** Does a technique test this invariant kind? "ai_*" matches every "ai_" kind; a kind matches a technique's exact kinds. */
export function testsKind(t: Technique, kind: InvariantKind): boolean {
  if (kind.startsWith("ai_")) return t.invariants.includes("ai_*");
  return (t.invariants as readonly string[]).includes(kind);
}

export type Allowance = { ok: true; host: EngageRoeHost } | { ok: false; reason: string };

/**
 * May this technique run against this host under this record? Pure. The reason is in the record's own words, always
 * ending "not allowed by your rules" when a class or an action is the cause, so the report wording is fixed.
 */
export function techniqueAllowed(t: Technique, roe: EngageRoe, host: string): Allowance {
  const h = roe.hosts.find((x) => x.host === host.toLowerCase());
  if (!h) return { ok: false, reason: `${host} is not a host of the confirmed rules, so nothing is sent to it` };
  if (!h.proof) return { ok: false, reason: `${h.host} is not proven, so nothing is sent to it` };
  const notOn = t.classes.find((c) => !h.classes.includes(c));
  if (notOn) return { ok: false, reason: `this needs the ${notOn} kind of test, which is not allowed by your rules for ${h.host}` };
  if (h.environment === "production") {
    const never = t.classes.find((c) => NEVER_ON_PRODUCTION.includes(c));
    if (never) return { ok: false, reason: `${never} tests are never run on a production host, so this is not allowed by your rules` };
  }
  const forbidden = (t.actions ?? []).find((a) => (roe.forbidden_actions as readonly string[]).includes(a));
  if (forbidden) return { ok: false, reason: `this does ${forbidden}, which your rules forbid, so it is not allowed by your rules` };
  return { ok: true, host: h };
}

export interface TechniqueFor {
  run: readonly Technique[];
  refused: readonly { technique: Technique; reason: string }[];
}

/** For one invariant kind: the techniques that test it, split into those the record allows and those it refuses. Pure. */
export function techniquesFor(kind: InvariantKind, roe: EngageRoe, host: string): TechniqueFor {
  const run: Technique[] = [];
  const refused: { technique: Technique; reason: string }[] = [];
  for (const t of ALL_TECHNIQUES) {
    if (!testsKind(t, kind)) continue;
    const a = techniqueAllowed(t, roe, host);
    if (a.ok) run.push(t);
    else refused.push({ technique: t, reason: a.reason });
  }
  return { run, refused };
}

/** Every kind a technique in the library tests (for the planner and the coverage ledger). */
export function kindsTested(): TechniqueInvariant[] {
  const out = new Set<TechniqueInvariant>();
  for (const t of ALL_TECHNIQUES) for (const k of t.invariants) out.add(k);
  return [...out];
}

/**
 * Run one technique, after the allowance check. A technique the record does not allow is a row with the reason and
 * sends nothing; otherwise t.run does the requests (each still checked by the governor).
 */
export async function runTechnique(ctx: TechniqueContext, t: Technique, target: TechniqueTarget): Promise<TechniqueResult> {
  const a = techniqueAllowed(t, ctx.roe, ctx.host);
  if (!a.ok) return result(t, "not_allowed", { reason: a.reason });
  try {
    return await t.run(ctx, target);
  } catch (e) {
    return notTestable(t, e instanceof Error ? e.message.slice(0, 160) : "the technique could not be run");
  }
}

export type { Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";
