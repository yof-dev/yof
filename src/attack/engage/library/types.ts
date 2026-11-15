/**
 * yof engagement, open core: the attack library's shared shapes.
 *
 * A TECHNIQUE is one fixed way to test one rule of the app (an invariant). It declares, as data anyone can read:
 *
 *   invariants     the kinds of rule it tests (the closed list below; the yof app holds the same names)
 *   prerequisites  what it needs before it can run (accounts, a test record, a route)
 *   safetyClass    the most cautious kind of test it needs from the rules-of-engagement record, and `classes`, every
 *                  kind one of its requests carries. A technique whose class the record does not allow is reported
 *                  "not allowed by your rules" and is never run (./index.ts techniquesFor, runTechnique)
 *   payloads       ids from the fixed payload list (./payloads.ts). Nothing writes a payload at run time
 *   chain          its steps as a replay spec (../../replay.ts): the proof, the replay and the regression test
 *   oracle         a DETERMINISTIC rule over what the run itself saw. No model reads an answer
 *
 * WHAT A RESULT MAY BE CALLED. "violated" is the finder's word: the oracle saw its demonstration, with its controls.
 * It becomes "confirmed" only when a second, separate pass shows the same (./index.ts techniqueVerdict). Everything
 * short of that is "needs_validation": shown apart, never counted. A technique whose `best` is "needs_validation" can
 * never be confirmed, whatever it sees.
 *
 * SEVERITY is not here. A technique states the four facts its demonstration shows (`impact`: what happened, who could
 * do it, how far it reaches, the data class); the yof app's impact table turns facts into a severity. The category of
 * a technique sets nothing.
 */
import type { AiSpec, Role } from "../../config";
import type { As, HttpAnswer, Method } from "../../http";
import type { ReplaySpec } from "../../replay";
import type { EngageIo, MarkerRegistry, PlantSpec } from "../markers";
import type { EngageRoe, SafetyClass } from "../roe";

/** The kinds of rule an engagement tests (docs: the invariant kinds). The assistant rules are every kind that starts "ai_". */
export const INVARIANT_KINDS = [
  "auth_required", "tenant_read", "tenant_write", "role_gate", "field_locked", "numeric_bound", "state_order", "single_use",
  "input_is_data", "fetch_restricted", "upload_safe", "session",
] as const;
export type InvariantKind = (typeof INVARIANT_KINDS)[number] | `ai_${string}`;
/** What a technique lists: a kind, or "ai_*" for every assistant rule. */
export type TechniqueInvariant = (typeof INVARIANT_KINDS)[number] | "ai_*";

export const PREREQUISITES = [
  "account_a", "account_b", "account_admin", "test_object", "object_update", "admin_route", "signed_in_route", "text_input", "render_route",
  "cookie_session", "state_change", "sign_out_route", "reset_flow", "token_session", "own_test_account", "numeric_rule", "ordered_steps",
  "single_use_action", "upload_route", "fetch_parameter", "canary_address", "assistant", "check_results",
] as const;
export type Prerequisite = (typeof PREREQUISITES)[number];

/** The four demonstrated facts (the same words as the yof app's impact table). */
export interface ImpactFacts {
  what: "none" | "read" | "write" | "privilege_gain" | "rule_broken" | "execution_marker";
  position: "anonymous" | "self_registered" | "same_tenant_member" | "admin";
  reach: "one_object" | "any_object_by_id" | "all_tenants";
  data: "private" | "ordinary" | "public";
}

/** One fixed payload. `value` may hold slots in single braces ({marker}, {id}, {url}) that a technique fills. */
export interface Payload { id: string; family: string; value: string; note: string }

/** A request as the app model describes it. The path may hold {id}; path and body may hold {{name}} values. */
export interface RequestSpec { method: Method; path: string; body?: string; headers?: Record<string, string> }

/** A test record the run can create, read and delete (the config's object, or the app model's). */
export interface TestObject extends PlantSpec {
  read: string;
  update?: { method: "PATCH" | "PUT"; path: string; body: string };
  /** Other places the id can travel: a query (`/api/notes?id={id}`) or a body (`{"id":"{{id}}"}`). */
  alternates?: RequestSpec[];
  /** Fields the app model says a member may not set on this record. */
  lockedFields?: string[];
}
/** Where text goes in, and where it comes back. `request` carries {{value}}. */
export interface InputSpec {
  request: RequestSpec;
  as?: Role;
  /** The request looks the test record up by its marked field: {{value}} is matched against it. */
  searchesObject?: boolean;
  /** Where a stored value is shown again (path may hold {id}), and to whom. Default: the request's own answer. */
  render?: { path: string; as?: As };
}
/** A request that changes the run's own test record, and how its effect is read back. */
export interface StateChange {
  /** Carries {{marker}}: the new value. Path may hold {id}. */
  request: RequestSpec;
  /** Where the app expects its anti-forgery token, and where a signed-in page gets it. */
  token?: { header: string; from: { path: string; jsonPath: string } };
}
export interface SessionSpec {
  /** A GET route that answers only to a signed-in account. */
  route: string;
  signOut?: RequestSpec;
  /** Redeeming a reset link: carries {{token}} and {{password}}. */
  reset?: RequestSpec;
}
/** A number the app must keep in bounds. `request` carries {{n}}; `readPath` is where the record shows it. */
export interface NumericRule {
  name: string;
  request: RequestSpec;
  readPath: string;
  /** A value inside the bounds (the control). */
  ok: number;
  min?: number;
  max?: number;
  /** The upper bound is another field of the record (a refund cannot exceed `paid`). */
  maxFromPath?: string;
  /** The server sets this number: any value the client sends must not stick. */
  serverSet?: boolean;
}
/** Steps that must run in order. `statePath` is where the record shows which step it reached. */
export interface OrderedSteps { statePath: string; steps: { name: string; request: RequestSpec; state: string }[] }
/** An action that works once (or `bound` times). */
export interface SingleUse {
  request: RequestSpec;
  bound?: number;
  /** A number the record shows that moves by `perUse` each time the action counts. */
  effect?: { readPath: string; perUse: number };
}
export interface UploadSpec {
  path: string;
  /** The form field that carries the file. */
  field: string;
  idPath: string;
  /** Where the file is served from (with {id}). */
  served: string;
  delete: string;
}
/** A parameter the server fetches. `request` carries {{url}}. `restricted`: the app says it only fetches listed hosts. */
export interface FetchSpec {
  request: RequestSpec;
  restricted: boolean;
  as?: Role;
  /** The yof canary address, when the planner knows it: only the chain template reads it (a run takes it from its context). */
  canaryBase?: string;
}

/** A stored result of an existing outside or inside check, as the yof app keeps it. */
export interface CheckRow { rule_id: string; status?: string; verdict?: string; place?: string }

/** What a technique is aimed at. Every part is optional: a technique that misses its part is "not testable". */
export interface TechniqueTarget {
  object?: TestObject;
  adminRoute?: string;
  input?: InputSpec;
  change?: StateChange;
  session?: SessionSpec;
  numeric?: NumericRule;
  ordered?: OrderedSteps;
  singleUse?: SingleUse;
  upload?: UploadSpec;
  fetch?: FetchSpec;
  ai?: AiSpec;
  checks?: CheckRow[];
}

/** What only the session knows: how each role is signed in. A header VALUE given here is never kept in any record. */
export interface SessionAccess {
  /** The headers a role is signed in with, for a test that must send them again or alter them. null = no account. */
  credential: (role: Role) => Promise<Record<string, string> | null>;
  /** The Set-Cookie lines seen when the role signed in (empty when it signs in with a header). */
  cookieFlags: (role: Role) => string[];
  /** A sign-in request (the real password, or a wrong one). */
  login?: (role: Role, wrong: boolean) => Promise<HttpAnswer | null>;
  /**
   * Redeem the reset link of the role's OWN test account (the same link each time it is called, keeping the account's
   * password as it is). The session sends it: the link and the password never reach the library or any evidence.
   */
  redeemReset?: (role: Role) => Promise<HttpAnswer | null>;
  /** Is this role an account made for testing (never a real person's)? */
  testAccount: (role: Role) => boolean;
  /** Forget every session: the next request signs in again. */
  fresh: () => void | Promise<void>;
}
/** The out-of-band canary. Without it, a test that needs one is not testable (it never passes unchecked). */
export interface CanaryAccess { base: string; hits: (token: string) => Promise<number | null> }

export interface TechniqueContext {
  /** Every request goes through this (the governor): the record's check, its pace and its budgets. */
  io: EngageIo;
  registry: MarkerRegistry;
  roe: EngageRoe;
  host: string;
  now: () => number;
  /** Twelve hex characters. */
  random: () => string;
  session?: SessionAccess;
  canary?: CanaryAccess;
  accounts?: ReplaySpec["accounts"];
  /** A tenant label per role: two roles with the same label share a tenant. */
  tenants?: Partial<Record<As, string>>;
}

export type Outcome = "violated" | "needs_validation" | "held" | "not_testable" | "not_allowed" | "not_tested" | "blocked_not_tested";

export interface TechniqueResult {
  technique: string;
  ruleId: string;
  outcome: Outcome;
  /** The oracle saw its whole demonstration (its controls included). Only then can a second pass confirm it. */
  demonstrated: boolean;
  /** Why, in plain words: what is missing, what was refused, what held. */
  reason: string;
  method: Method;
  /** The route as written in the target (with {id}), never a real id. */
  route: string;
  as: As;
  status: number;
  /** What was seen, in yof's own fixed words. Never a piece of an answer. */
  evidence: string;
  meta: Record<string, string>;
  payload: string | null;
  marker: string | null;
  replay: ReplaySpec | null;
  /** The demonstrated facts, when something was demonstrated. */
  impact: ImpactFacts | null;
}

export interface Technique {
  id: string;
  ruleId: string;
  title: string;
  invariants: readonly TechniqueInvariant[];
  prerequisites: readonly Prerequisite[];
  safetyClass: SafetyClass;
  classes: readonly SafetyClass[];
  payloads: readonly string[];
  /** The oracle, in one sentence. */
  oracle: string;
  shows: string;
  cannotShow: string;
  /** The most a finder plus a second pass can make of it. */
  best: "confirmed" | "needs_validation";
  /** The proof is another account, or nobody, reading a marker the owner planted (owner decision D7). */
  markerRead?: boolean;
  impact: ImpactFacts;
  /**
   * What its requests do, in the record's own words, when that is one of the record's forbidden actions. Every request
   * says so, and the record refuses it: such a technique is listed, and never run, until the record's wording allows it.
   */
  actions?: readonly string[];
  /** The OWASP Top 10 (2021) category, or the API or LLM list entry. */
  owasp: string;
  /** The replay spec cannot carry the whole test (it has no way to alter a token, a cookie or a file): what is left out. */
  chainLimit?: string;
  chain: (target: TechniqueTarget, accounts?: ReplaySpec["accounts"]) => ReplaySpec | null;
  run: (ctx: TechniqueContext, target: TechniqueTarget) => Promise<TechniqueResult>;
}
