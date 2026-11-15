/**
 * yof engagement, open core: the rules-of-engagement record as the runner reads it, and the check every request passes.
 *
 * The record is the same one the yof app stores and a customer confirms (its schema lives in the yof app; this file
 * holds the same lists and the same owner rules, and a test in the private repository keeps the two in step). It is
 * written again here, with no dependency, so anyone can read exactly what a run may and may not send:
 *
 *   hosts            each with its environment, how it was proven, the kinds of test allowed (safety classes), the
 *                    time windows (UTC) and the requests a second
 *   budgets          the total number of requests and the minutes a run may take
 *   forbidden_paths  path words that are never requested (a lower-case substring of path plus query)
 *   forbidden_actions what a run never does; the whole list is always in force
 *   data             only the marker is read from another account's record; evidence is kept a set number of days
 *
 * The owner's rules, checked by parseRoe: on a production host timing and race tests are never allowed (D8); tests
 * that write, and bursts, need the host proven by its DNS record and a time window (D6); a production host always has
 * a window and at most 2 requests a second; the seeded forbidden paths and the forbidden actions cannot be removed.
 *
 * roeCheckRequest is PURE: the record, one planned request and the time in, yes or a refusal with its reason out.
 * The governor (./governor.ts) calls it before every request and sends nothing it refuses.
 */
import { inWindow, type AttackConfig } from "../config";
import type { Method } from "../http";
import type { Mode, ProofMethod, TargetKind } from "../proof";

export const ROE_SCHEMA_VERSION = 1 as const;
export const ROE_ENVIRONMENTS = ["production", "staging", "preview"] as const;
export type RoeEnvironment = (typeof ROE_ENVIRONMENTS)[number];

/** What a test may do, in the order of caution. */
export const SAFETY_CLASSES = ["read", "write_own_test_records", "write_cross_account_test_records", "ai_messages", "burst", "timing", "race"] as const;
export type SafetyClass = (typeof SAFETY_CLASSES)[number];
/** On production these need DNS proof and a time window (owner decision D6). */
export const PRODUCTION_GUARDED: readonly SafetyClass[] = ["write_own_test_records", "write_cross_account_test_records", "burst"];
/** Never on production (owner decision D8). */
export const NEVER_ON_PRODUCTION: readonly SafetyClass[] = ["timing", "race"];

/** What yof never does in an engagement. Every record carries the whole list. */
export const FORBIDDEN_ACTIONS = [
  "change_or_delete_records_yof_did_not_create",
  "read_more_than_the_marker_from_another_account",
  "password_guessing_on_real_accounts",
  "lock_out_real_accounts",
  "write_files_or_run_commands",
  "cloud_metadata_addresses",
  "denial_of_service",
  "solve_a_captcha",
  "hosts_not_in_this_record",
] as const;
export type ForbiddenAction = (typeof FORBIDDEN_ACTIONS)[number];

/** Path words never requested: a path holding one could change something even with a GET. A customer adds their own. */
export const SEED_FORBIDDEN_PATHS = [
  "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy", "unsubscribe", "cancel", "deactivate", "revoke", "pay", "checkout", "confirm",
] as const;

export const RETENTION_DAYS = 180;
export const MIN_RETENTION_DAYS = 30;
export const PRODUCTION_MAX_RPS = 2;
export const MAX_RPS = 10;
export const DEFAULT_RPS = 2;
export const MAX_TOTAL_REQUESTS = 20_000;
export const MAX_MINUTES = 240;
export const MAX_HOSTS = 5;
export const NIGHT_WINDOW = "01:00-05:00";

const WINDOW = /^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
/** The tester's own machine: allowed as a host of a record the CLI derives for a local run, never production. */
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\])$/;

export interface EngageRoeHost {
  host: string;
  environment: RoeEnvironment;
  /** How the host was proven ("meta", "file", "dns"; the CLI also knows "local" and "github-deployment"). null = not proven: nothing is sent. */
  proof: string | null;
  classes: SafetyClass[];
  /** UTC windows "HH:MM-HH:MM"; one may wrap midnight. Empty = any time (never on production). */
  windows: string[];
  requests_per_second: number;
}
export interface EngageRoe {
  schema: typeof ROE_SCHEMA_VERSION;
  hosts: EngageRoeHost[];
  budgets: { total_requests: number; max_minutes: number };
  forbidden_paths: string[];
  forbidden_actions: ForbiddenAction[];
  data: { marker_only: true; retention_days: number; after_retention: "hashes_and_replay_steps" };
  stop_contact: { email: string | null };
}

export type RoeParse = { ok: true; roe: EngageRoe } | { ok: false; problems: string[] };

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const only = (o: Record<string, unknown>, keys: readonly string[], at: string, out: string[]) => { for (const k of Object.keys(o)) if (!keys.includes(k)) out.push(`${at}: unknown setting "${k.slice(0, 40)}"`); };

/**
 * Read a record strictly. Anything unknown, out of range or against the owner's rules is a problem, never a guess.
 * `allowLocal` lets a record name the tester's own machine (the CLI's local runs); the hosted service never passes it.
 */
export function parseRoe(input: unknown, opts: { allowLocal?: boolean } = {}): RoeParse {
  const p: string[] = [];
  if (!isObj(input)) return { ok: false, problems: ["the record must be an object"] };
  only(input, ["schema", "hosts", "budgets", "forbidden_paths", "forbidden_actions", "data", "stop_contact"], "record", p);
  if (input.schema !== ROE_SCHEMA_VERSION) p.push("schema: must be 1");
  const hosts: EngageRoeHost[] = [];
  if (!Array.isArray(input.hosts) || input.hosts.length < 1 || input.hosts.length > MAX_HOSTS) p.push(`hosts: between 1 and ${MAX_HOSTS} hosts`);
  else {
    const seen = new Set<string>();
    input.hosts.forEach((h, i) => {
      const at = `hosts.${i}`;
      if (!isObj(h)) { p.push(`${at}: must be an object`); return; }
      only(h, ["host", "environment", "proof", "classes", "windows", "requests_per_second"], at, p);
      const host = typeof h.host === "string" ? h.host.toLowerCase() : "";
      if (!HOSTNAME.test(host) && !(opts.allowLocal && LOCAL_HOST.test(host))) p.push(`${at}.host: not a host name`);
      if (seen.has(host)) p.push(`${at}.host: listed twice`);
      seen.add(host);
      const environment = (ROE_ENVIRONMENTS as readonly string[]).includes(String(h.environment)) ? (h.environment as RoeEnvironment) : null;
      if (!environment) p.push(`${at}.environment: must be production, staging or preview`);
      if (environment === "production" && LOCAL_HOST.test(host)) p.push(`${at}.environment: the tester's own machine is never production`);
      const proof = h.proof === null ? null : typeof h.proof === "string" && /^[a-z-]{2,24}$/.test(h.proof) ? h.proof : undefined;
      if (proof === undefined) p.push(`${at}.proof: must be a proof method or null`);
      const classes = Array.isArray(h.classes) ? h.classes.filter((c): c is SafetyClass => (SAFETY_CLASSES as readonly unknown[]).includes(c)) : [];
      if (!Array.isArray(h.classes) || classes.length !== h.classes.length || !classes.length) p.push(`${at}.classes: at least one known kind of test`);
      const windows = Array.isArray(h.windows) ? h.windows.filter((w): w is string => typeof w === "string" && WINDOW.test(w)) : [];
      if (!Array.isArray(h.windows) || windows.length !== h.windows.length || windows.length > 7) p.push(`${at}.windows: each must read HH:MM-HH:MM (UTC), at most 7`);
      const rps = typeof h.requests_per_second === "number" && Number.isFinite(h.requests_per_second) ? h.requests_per_second : NaN;
      if (!(rps >= 0.1 && rps <= MAX_RPS)) p.push(`${at}.requests_per_second: between 0.1 and ${MAX_RPS}`);
      if (environment === "production") {
        if (classes.includes("timing")) p.push(`${at}.classes: timing tests can never be switched on for a production host`);
        if (classes.includes("race")) p.push(`${at}.classes: race tests can never be switched on for a production host`);
        if (!windows.length) p.push(`${at}.windows: a production host needs a time window`);
        if (rps > PRODUCTION_MAX_RPS) p.push(`${at}.requests_per_second: a production host allows at most ${PRODUCTION_MAX_RPS} requests a second`);
        if (classes.some((c) => PRODUCTION_GUARDED.includes(c)) && proof !== "dns") p.push(`${at}.proof: tests that write on production need the host proven with the DNS record`);
      }
      hosts.push({ host, environment: environment ?? "production", proof: proof ?? null, classes: SAFETY_CLASSES.filter((c) => classes.includes(c)), windows: [...new Set(windows)].sort(), requests_per_second: rps });
    });
  }
  const b = isObj(input.budgets) ? input.budgets : {};
  if (!isObj(input.budgets)) p.push("budgets: must be an object"); else only(b, ["total_requests", "max_minutes"], "budgets", p);
  const total = Number.isInteger(b.total_requests) ? (b.total_requests as number) : NaN;
  const minutes = Number.isInteger(b.max_minutes) ? (b.max_minutes as number) : NaN;
  if (!(total >= 1 && total <= MAX_TOTAL_REQUESTS)) p.push(`budgets.total_requests: a whole number from 1 to ${MAX_TOTAL_REQUESTS}`);
  if (!(minutes >= 1 && minutes <= MAX_MINUTES)) p.push(`budgets.max_minutes: a whole number from 1 to ${MAX_MINUTES}`);
  const paths = Array.isArray(input.forbidden_paths) ? input.forbidden_paths.filter((x): x is string => typeof x === "string" && x.trim().length >= 2 && x.length <= 120).map((x) => x.trim().toLowerCase()) : [];
  if (!Array.isArray(input.forbidden_paths) || paths.length !== input.forbidden_paths.length || paths.length > 200) p.push("forbidden_paths: a list of path words, 2 to 120 characters each");
  if (SEED_FORBIDDEN_PATHS.some((s) => !paths.includes(s))) p.push("forbidden_paths: the built-in forbidden paths cannot be removed");
  const actions = Array.isArray(input.forbidden_actions) ? input.forbidden_actions.filter((a): a is ForbiddenAction => (FORBIDDEN_ACTIONS as readonly unknown[]).includes(a)) : [];
  if (!Array.isArray(input.forbidden_actions) || actions.length !== input.forbidden_actions.length) p.push("forbidden_actions: only known actions");
  if (FORBIDDEN_ACTIONS.some((a) => !actions.includes(a))) p.push("forbidden_actions: the forbidden actions cannot be removed");
  const d = isObj(input.data) ? input.data : {};
  if (!isObj(input.data)) p.push("data: must be an object"); else only(d, ["marker_only", "retention_days", "after_retention"], "data", p);
  const days = Number.isInteger(d.retention_days) ? (d.retention_days as number) : NaN;
  if (d.marker_only !== true) p.push("data.marker_only: must be true");
  if (!(days >= MIN_RETENTION_DAYS && days <= RETENTION_DAYS)) p.push(`data.retention_days: from ${MIN_RETENTION_DAYS} to ${RETENTION_DAYS}`);
  if (d.after_retention !== "hashes_and_replay_steps") p.push("data.after_retention: must be hashes_and_replay_steps");
  const sc = isObj(input.stop_contact) ? input.stop_contact : null;
  const email = sc && (sc.email === null || (typeof sc.email === "string" && /^[^\s@<>"]{1,64}@[^\s@<>"]{1,190}\.[^\s@<>".]{2,63}$/.test(sc.email))) ? (sc.email as string | null) : undefined;
  if (email === undefined) p.push("stop_contact.email: an email address or null");
  if (p.length) return { ok: false, problems: p };
  return {
    ok: true,
    roe: {
      schema: ROE_SCHEMA_VERSION, hosts: hosts.sort((x, y) => (x.host < y.host ? -1 : x.host > y.host ? 1 : 0)),
      budgets: { total_requests: total, max_minutes: minutes }, forbidden_paths: [...new Set(paths)].sort(),
      forbidden_actions: FORBIDDEN_ACTIONS.filter((a) => actions.includes(a)),
      data: { marker_only: true, retention_days: days, after_retention: "hashes_and_replay_steps" }, stop_contact: { email: email ? email.toLowerCase() : null },
    },
  };
}

// ── The check every request passes ───────────────────────────────────────────────────────────────────────────────
/** The methods a kind of test may send. A read sends only GET and HEAD, whatever the caller asks for. */
export const METHODS_OF_CLASS: Readonly<Record<SafetyClass, readonly Method[]>> = {
  read: ["GET", "HEAD"],
  write_own_test_records: ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"],
  write_cross_account_test_records: ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"],
  ai_messages: ["GET", "HEAD", "POST"],
  burst: ["GET", "HEAD", "POST"],
  timing: ["GET", "HEAD", "POST"],
  race: ["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"],
};

/** A cloud metadata address, in any spelling a URL parameter could carry it. Never requested and never sent as a value. */
export const METADATA_ADDRESS = /169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|0xa9fea9fe|2852039166|\b0?251\.0?376\.0?251\.0?376\b/i;

export type RoeRefusalCode =
  | "host_not_in_scope" | "not_proven" | "class_not_allowed" | "outside_window" | "method_not_allowed" | "forbidden_path" | "forbidden_action";
export type RoeDecision = { ok: true; host: EngageRoeHost } | { ok: false; code: RoeRefusalCode; message: string };

export interface PlannedRequest {
  host: string;
  method: Method;
  /** The path with its query, as it will be sent. */
  path: string;
  /** The kind of test this request belongs to. */
  cls: SafetyClass;
  /** The request body, when there is one (looked at only for a metadata address). */
  body?: string;
  /** What the step does, in the record's own words, when it is one of the forbidden actions (a library step says so). */
  actions?: readonly string[];
}

/** Is this path (with its query) one the record forbids? Lower-case substring match. Pure. */
export const roePathForbidden = (roe: Pick<EngageRoe, "forbidden_paths">, pathAndQuery: string): boolean => {
  const p = pathAndQuery.toLowerCase();
  return roe.forbidden_paths.some((f) => p.includes(f));
};

/** May this request be sent now? Pure: host in scope and proven, the class allowed, the window open, the method, the path, the action. */
export function roeCheckRequest(roe: EngageRoe, r: PlannedRequest, now: Date): RoeDecision {
  const no = (code: RoeRefusalCode, message: string): RoeDecision => ({ ok: false, code, message });
  const h = roe.hosts.find((x) => x.host === r.host.toLowerCase());
  if (!h) return no("host_not_in_scope", `${r.host} is not a host of the confirmed rules, so nothing is sent to it.`);
  if (!h.proof) return no("not_proven", `${h.host} is not proven, so nothing is sent to it.`);
  if (!h.classes.includes(r.cls)) return no("class_not_allowed", `The rules for ${h.host} do not allow this kind of test (${r.cls}).`);
  if (h.environment === "production" && NEVER_ON_PRODUCTION.includes(r.cls)) return no("class_not_allowed", `${r.cls} tests are never run on a production host.`);
  if (!METHODS_OF_CLASS[r.cls].includes(r.method)) return no("method_not_allowed", r.cls === "read" ? `A read test sends only GET and HEAD, so ${r.method} ${r.path.split("?")[0]} is not sent.` : `A ${r.cls} test does not send ${r.method}.`);
  if (h.windows.length ? !h.windows.some((w) => inWindow(w, now)) : h.environment === "production") return no("outside_window", `It is outside the time window agreed for ${h.host}${h.windows.length ? ` (${h.windows.join(", ")} UTC)` : ""}.`);
  if (roePathForbidden(roe, r.path)) return no("forbidden_path", `${r.path.split("?")[0]} holds a path word the rules forbid, so it is not requested.`);
  const named = (r.actions ?? []).find((a) => (roe.forbidden_actions as readonly string[]).includes(a));
  if (named) return no("forbidden_action", `The rules forbid this action (${named}).`);
  if (roe.forbidden_actions.includes("cloud_metadata_addresses") && (METADATA_ADDRESS.test(decodeSafe(r.path)) || (r.body !== undefined && METADATA_ADDRESS.test(r.body)))) {
    return no("forbidden_action", "A cloud metadata address is never requested or sent as a value.");
  }
  return { ok: true, host: h };
}
const decodeSafe = (s: string): string => { try { return decodeURIComponent(s); } catch { return s; } };

// ── The record of an owner's own run (the CLI) ───────────────────────────────────────────────────────────────────
export interface RoeFromConfigInput {
  cfg: AttackConfig;
  /** The host the run is aimed at. Default: the config's app. */
  host?: string;
  kind?: TargetKind;
  /** How yof attack proved the host, or null when it was not checked (`--roe` sends nothing). */
  proof?: ProofMethod | null;
  mode: Mode;
}

/**
 * The record an owner's own run works under, derived from the attack config. It is never looser than the config and
 * never looser than the owner's rules: a production host gets tests that write only when it was proven by DNS and the
 * config has a window; otherwise it is read only. Always passes parseRoe (with allowLocal for a local host). Pure.
 */
export function roeFromConfig(i: RoeFromConfigInput): EngageRoe {
  const { cfg, mode } = i;
  const host = (i.host ?? cfg.app.replace(/:\d+$/, "")).toLowerCase();
  const kind: TargetKind = i.kind ?? (LOCAL_HOST.test(host) ? "local" : "production");
  const production = kind === "production";
  const window = cfg.production.window ?? null;
  const wants: SafetyClass[] = ["read"];
  if (mode === "full") {
    if (cfg.objects.length || cfg.accounts.a || cfg.accounts.b) wants.push("write_own_test_records");
    if (cfg.objects.length && cfg.accounts.a && (cfg.accounts.b || cfg.accounts.viewer)) wants.push("write_cross_account_test_records");
    if (cfg.ai.length) wants.push("ai_messages");
    if (cfg.surface.rateLimit || cfg.ai.some((a) => a.limits)) wants.push("burst");
  }
  // D6: on production, tests that write (and bursts) only with DNS proof and a window. Otherwise read only.
  const guardedOk = !production || (i.proof === "dns" && !!window);
  const classes = SAFETY_CLASSES.filter((c) => wants.includes(c) && (guardedOk || c === "read"));
  const rps = Math.max(0.1, Math.min(cfg.budget.perSecond, production ? PRODUCTION_MAX_RPS : MAX_RPS));
  return {
    schema: ROE_SCHEMA_VERSION,
    hosts: [{ host, environment: production ? "production" : "preview", proof: i.proof ?? null, classes, windows: production ? [window ?? NIGHT_WINDOW] : [], requests_per_second: rps }],
    budgets: { total_requests: Math.max(1, Math.min(Math.floor(cfg.budget.requests), MAX_TOTAL_REQUESTS)), max_minutes: Math.max(1, Math.min(Math.ceil(cfg.budget.seconds / 60), MAX_MINUTES)) },
    forbidden_paths: [...SEED_FORBIDDEN_PATHS].sort(),
    forbidden_actions: [...FORBIDDEN_ACTIONS],
    data: { marker_only: true, retention_days: RETENTION_DAYS, after_retention: "hashes_and_replay_steps" },
    stop_contact: { email: null },
  };
}

// ── The record in the scope-document form (`yof attack --roe`) ───────────────────────────────────────────────────
const CLASS_WORDS: Record<SafetyClass, string> = {
  read: "reads (GET and HEAD only)",
  write_own_test_records: "creating, changing and deleting the run's own test records, and signing the test accounts in",
  write_cross_account_test_records: "one test account trying to change or delete another test account's test record",
  ai_messages: "fixed, mild test messages to the app's own assistant",
  burst: "small bursts of repeated requests",
  timing: "tests that measure answer times",
  race: "the same request sent several times at once",
};
const ACTION_WORDS: Record<ForbiddenAction, string> = {
  change_or_delete_records_yof_did_not_create: "Changing or deleting a record the run did not create.",
  read_more_than_the_marker_from_another_account: "Reading more than the run's own marker from another account's record. Only the shape of an answer is kept.",
  password_guessing_on_real_accounts: "Guessing passwords on real accounts.",
  lock_out_real_accounts: "Locking real accounts out.",
  write_files_or_run_commands: "Writing files or running commands on the server.",
  cloud_metadata_addresses: "Requesting a cloud metadata address, or sending one as a value.",
  denial_of_service: "Trying to make the app unavailable.",
  solve_a_captcha: "Solving a CAPTCHA or getting around a bot wall. A blocked test is reported as blocked, not tested.",
  hosts_not_in_this_record: "Sending anything to a host that is not listed here.",
};
const tick = (s: string) => `\`${s.replace(/`/g, "")}\``;

export interface RoeDocInput { roe: EngageRoe; date: string; version: string; source: string; ownerRun: boolean }

/** The record as Markdown, in the form of the scope document: to read, and to confirm in the yof app. Pure. */
export function roeDocument(i: RoeDocInput): string {
  const { roe } = i;
  const L: string[] = [];
  const add = (...s: string[]) => { L.push(...s); };
  add(`# Rules of engagement: ${roe.hosts.map((h) => h.host).join(", ")}`, "");
  add(`Prepared on ${i.date} with yof attack ${i.version} from ${tick(i.source)}. Nothing was sent to any host to make this document.`, "");
  add("This is the record a run works under. Every request is checked against it before it is sent, and a request it does not allow is not sent. It describes automated testing with no human tester. It does not replace a manual test where a standard requires one.", "");
  add("## 1. Hosts", "");
  add("| Host | Environment | Proven by | Kinds of test | Time windows (UTC) | Requests a second |", "| --- | --- | --- | --- | --- | --- |");
  for (const h of roe.hosts) add(`| ${tick(h.host)} | ${h.environment} | ${h.proof ?? "not checked for this document: a run proves the host first"} | ${h.classes.join(", ")} | ${h.windows.length ? h.windows.join(", ") : "any time"} | ${h.requests_per_second} |`);
  add("", "Every other host is out of scope: nothing is sent to it.", "");
  add("## 2. Kinds of test", "");
  for (const c of SAFETY_CLASSES) {
    const where = roe.hosts.filter((h) => h.classes.includes(c)).map((h) => h.host);
    add(`- **${c}**: ${CLASS_WORDS[c]}. ${where.length ? `Allowed on ${where.join(", ")}.` : "Not allowed."}`);
  }
  add("", "A read test sends only GET and HEAD. On a production host, tests that write need the host proven by its DNS record and a time window, and timing and race tests are never run.", "");
  add("## 3. Budget", "");
  add(`- At most ${roe.budgets.total_requests} requests and ${roe.budgets.max_minutes} minutes for the whole run.`, "- The run measures the app first (20 harmless reads) and checks its health every 25 requests.", "- When the app answers 429 or 503 the run halves its pace; the second time it pauses for 10 minutes; the third time it stops.", "- It stops when server errors over the last 50 requests go above the measured level plus 5 points (or 2%, whichever is larger), or when answers are three times slower than measured, three checks in a row.", "- A bot wall or a challenge page stops the run. Those tests are reported as blocked, not tested, never as passed.", "");
  add("## 4. Paths that are never requested", "");
  add(`A path or query that holds one of these words is not requested: ${roe.forbidden_paths.map(tick).join(", ")}.`, "");
  add("## 5. What is never done", "");
  for (const a of roe.forbidden_actions) add(`- ${ACTION_WORDS[a]}`);
  add("");
  add("## 6. Data", "");
  add("- The run plants its own marker text in its own test records and reads only that marker from another account's record.", `- Evidence is kept for ${roe.data.retention_days} days. After that only hashes and the steps needed to repeat a test are kept.`, "- No password, token or cookie is written to a report. Evidence shows the shape of an answer, with keys, email addresses and long numbers masked.", "");
  add("## 7. Stopping", "");
  add("- `yof attack stop` in this folder, Ctrl+C, or a cancel in CI stops a run on your machine: nothing new is sent and the run deletes its test records.", "- In the yof app: the Stop button, the stop link, removing the ownership proof from a host, or serving a file at `/.well-known/yof-stop` whose first line is `yof-stop`.", `- Stop notices go to: ${roe.stop_contact.email ?? "nobody by email (the yof app still shows them)"}.`, "");
  add("## 8. Who ran it", "");
  add(i.ownerRun
    ? "A run you start with this command line is your own run. Its results are yours: yof did not see them, and the yof app shows them as reported by the owner."
    : "This record belongs to an engagement yof runs itself, after you confirm it in the yof app.", "");
  add("## 9. The record", "", "```json", JSON.stringify(roe, null, 2), "```", "");
  return L.join("\n");
}
