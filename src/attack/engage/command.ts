/**
 * yof engagement, open core: the commands.
 *
 *   yof attack --roe                     prints the rules-of-engagement record for this config, in the form of the
 *                                        scope document. Reads the config only: nothing is sent.
 *   yof attack replay <finding.json>     runs a finding's stored steps again. Exit 1 while the attack still works.
 *   yof attack verify <finding.json>     the verifier: new sessions, a new marker, and the refutation rules. Exit 1
 *                                        when the finding stands, 0 when it is refuted, 2 when it cannot be decided.
 *   yof attack stop                      asks every yof attack run that is under way in this folder to stop.
 *   yof attack --engage                  not available yet: it says which parts exist and which do not.
 *
 * Every request of replay and verify goes through the same gate as `yof attack` (the host must be proven: ../proof.ts)
 * and then through the governor (./governor.ts) under the record derived from the config (./roe.ts roeFromConfig).
 *
 * WHO RAN IT: these commands run on your machine or in your CI. yof did not see them, so their results are
 * `owner_run`, always. Only yof's own hosted runner may say `yof_run`, and that code is not in this package.
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { AttackError, loadConfig } from "../command";
import { ENV_PREFIX, fill, isLoginAccount, ROLES, type AttackConfig } from "../config";
import { AttackClient, BudgetError, RefusedError, StoppedError, type FetchFn, type HttpAnswer } from "../http";
import { findPreviewUrl, parseTarget, proveTarget, type Mode, type ProofOk } from "../proof";
import type { ReplaySpec } from "../replay";
import { Auth } from "../runner";
import { totpCode } from "../totp";
import { buildEvidenceBundle, recordingIo, type EvidenceBundle } from "./evidence";
import { Governor, GovernorStopped, RoeRefused, outcomeOfStop, type Baseline, type GovernorEvent, type GovernorStop } from "./governor";
import { MarkerRegistry, type EngageIo } from "./markers";
import { parseRoe, roeDocument, roeFromConfig, roePathForbidden, type EngageRoe } from "./roe";
import { runSpec, specFromFile, type SpecRun } from "./spec";
import { verifySpec, type RefutationRule, type Undecided, type VerifierFacts, type VerifierResult } from "./verifier";

/** Every result of this command line is the owner's own run. */
export const REPORTED_BY = "owner_run" as const;
export const STOP_FILE = ".yof/attack.stop";
export const MAX_FINDING_FILE_BYTES = 2 * 1024 * 1024;

export const ENGAGE_NOT_AVAILABLE = [
  "yof attack --engage is not available yet.",
  "",
  "What exists in this version:",
  "  yof attack --roe                    the rules-of-engagement record for your config (sends nothing)",
  "  yof attack replay <finding.json>    run a finding's stored steps again",
  "  yof attack verify <finding.json>    try to refute a finding with new sessions and a new marker",
  "  yof attack stop                     stop a run that is under way in this folder",
  "",
  "What does not exist yet: the planner that turns your app's own rules into tests, the test library per kind of",
  "problem, the coverage numbers and the engagement report. Nothing was sent.",
].join("\n");

// ── yof attack --roe ─────────────────────────────────────────────────────────────────────────────────────────────
export interface RoeDocOptions { cwd: string; config?: string; mode?: Mode; target?: string; version: string; now?: () => number }

/** The record a run of this config works under. Nothing is sent, so the host is shown as "not checked here". */
export function attackRoe(o: Pick<RoeDocOptions, "cwd" | "config" | "mode" | "target">): EngageRoe {
  const cfg = loadConfig(o.cwd, o.config);
  let host: string | undefined;
  let local = false;
  if (o.target) {
    const p = parseTarget(o.target);
    if (!p.ok) throw new AttackError(p.message);
    host = p.url.hostname.toLowerCase();
  }
  const appHost = cfg.app.replace(/:\d+$/, "");
  local = /^(?:localhost|127\.0\.0\.1|\[::1\])$/.test(host ?? appHost);
  const isApp = !host || host === appHost || host === `www.${appHost}` || `www.${host}` === appHost;
  return roeFromConfig({ cfg, host, kind: local ? "local" : isApp ? "production" : "preview", proof: null, mode: o.mode ?? "full" });
}
export function attackRoeDoc(o: RoeDocOptions): string {
  const roe = attackRoe(o);
  return roeDocument({ roe, date: new Date((o.now ?? Date.now)()).toISOString().slice(0, 10), version: o.version, source: o.config ?? ".yof/attack.json", ownerRun: true });
}

// ── yof attack stop ──────────────────────────────────────────────────────────────────────────────────────────────
/** Ask the runs under way in this folder to stop. A run that starts later is not affected. */
export function attackStop(o: { cwd: string; now?: () => number }): string {
  const file = resolve(o.cwd, STOP_FILE);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify({ stop: true, at: new Date((o.now ?? Date.now)()).toISOString() })}\n`);
  return `Stop asked for (${STOP_FILE}). A yof attack run under way in this folder sends nothing new and deletes its test records. A run you start after this is not affected.`;
}
/** When a stop was asked for in this folder (milliseconds), or null. */
export function stopAskedAt(cwd: string): number | null {
  try {
    const file = resolve(cwd, STOP_FILE);
    if (!existsSync(file) || statSync(file).size > 1024) return null;
    const v = JSON.parse(readFileSync(file, "utf8")) as { stop?: unknown; at?: unknown };
    const at = typeof v.at === "string" ? Date.parse(v.at) : NaN;
    return v.stop === true && Number.isFinite(at) ? at : null;
  } catch { return null; }
}
/** A check a run asks before every request: was a stop asked for AFTER this run started? Looks at the file once a second at most. */
export function stopWatch(cwd: string, startedAt: number = Date.now(), clock: () => number = Date.now): () => boolean {
  let last = -Infinity, stopped = false;
  return () => {
    if (stopped) return true;
    if (clock() - last < 1000) return false;
    last = clock();
    const at = stopAskedAt(cwd);
    stopped = at !== null && at >= startedAt;
    return stopped;
  };
}

// ── A session: the proven target, the record, the client, the governor, the accounts ─────────────────────────────
export interface EngageOptions {
  cwd: string;
  config?: string;
  target?: string;
  mode?: Mode;
  version: string;
  env?: Record<string, string | undefined>;
  fetch?: FetchFn;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Aborted when the person stops the run (SIGINT, SIGTERM). */
  signal?: AbortSignal;
  /** Twelve random hex characters (tests). */
  random?: () => string;
  /** Look for `yof attack stop` (default true). */
  watchStopFile?: boolean;
}
interface Session {
  cfg: AttackConfig; proof: ProofOk; roe: EngageRoe; client: AttackClient; governor: Governor; io: EngageIo;
  login: (role: "a" | "b" | "admin" | "viewer", wrong: boolean, wrongPassword: string) => Promise<HttpAnswer | null>;
  newSessions: () => void; notes: string[]; random: () => string; startedAt: string;
}

async function openSession(o: EngageOptions): Promise<Session> {
  const env = o.env ?? process.env;
  const now = o.now ?? Date.now;
  const mode = o.mode ?? "full";
  const cfg = loadConfig(o.cwd, o.config);
  let target = o.target ?? env.YOF_ATTACK_TARGET ?? null;
  if (!target) target = await findPreviewUrl(env, o.fetch);
  if (!target) throw new AttackError("Give the address to test: yof attack replay <finding.json> <url>, or YOF_ATTACK_TARGET.");
  const proof = await proveTarget(target, cfg, mode, { fetch: o.fetch, env, now: new Date(now()) });
  if (!proof.ok) throw new AttackError(`Refused: ${proof.message}`);

  const derived = roeFromConfig({ cfg, host: proof.host, kind: proof.kind, proof: proof.method, mode });
  const checked = parseRoe(derived, { allowLocal: proof.kind === "local" });
  if (!checked.ok) throw new AttackError(`The rules for this run could not be made: ${(checked as { problems: string[] }).problems.slice(0, 3).join("; ")}`);
  const roe = checked.roe;
  const host = roe.hosts[0]!;
  const writes = host.classes.includes("write_own_test_records");
  const postPaths = [
    ...cfg.objects.map((x) => x.create.path), ...cfg.ai.map((a) => a.path), ...cfg.ai.flatMap((a) => (a.ingest ? [a.ingest.create.path] : [])),
    ...ROLES.flatMap((r) => { const acc = cfg.accounts[r]; return acc && isLoginAccount(acc) ? [acc.login.path] : []; }),
  ];
  // The governor keeps the record's pace and budgets; the client keeps its own hard rules under it (one origin, writes
  // only to what the run owns) and is read-only whenever the record allows reads only.
  const client = new AttackClient({
    origin: proof.origin, budget: { requests: roe.budgets.total_requests, seconds: roe.budgets.max_minutes * 60, perSecond: 1000 },
    fetch: o.fetch, now: o.now, sleep: o.sleep, postPaths, signal: o.signal, readOnly: !writes,
  });
  const watch = o.watchStopFile === false ? () => false : stopWatch(o.cwd);
  const governor = new Governor({ client, roe, now: o.now, sleep: o.sleep, shouldStop: () => o.signal?.aborted === true || watch() });
  const notes: string[] = [];
  const authSender = { send: (...a: Parameters<AttackClient["send"]>) => governor.send(a[0], a[1], a[2], a[3]) };
  let auth = new Auth(cfg, env, authSender, !writes, (role) => notes.push(`account ${role} signs in with a password, and this run is read-only, so it takes no part`));
  const io: EngageIo = {
    own: (id) => governor.own(id),
    pathAllowed: (p) => !roePathForbidden(roe, p),
    send: async (as, method, path, init = {}) => {
      const h = await auth.headers(as);
      if (h === null) return null;
      return governor.send(as, method, path, { ...init, headers: { ...h, ...(init.headers ?? {}) } });
    },
  };
  const login: Session["login"] = async (role, wrong, wrongPassword) => {
    const acc = cfg.accounts[role];
    if (!acc || !isLoginAccount(acc)) return null;
    const read = (name: string) => (name.startsWith(ENV_PREFIX) ? env[name] : undefined);
    const email = read(acc.emailEnv), pw = wrong ? wrongPassword : read(acc.passwordEnv);
    if (!email || !pw) return null;
    const totp: Record<string, string> = acc.login.totpEnv ? { totp: totpCode(read(acc.login.totpEnv) ?? "") } : {};
    return governor.send(role, "POST", acc.login.path, { body: fill(acc.login.body, { email, password: pw, ...totp }), purpose: "login", cls: wrong ? "burst" : "write_own_test_records" });
  };
  return {
    cfg, proof, roe, client, governor, io, login, notes, startedAt: new Date(now()).toISOString(),
    random: o.random ?? (() => randomBytes(6).toString("hex")),
    newSessions: () => { auth = new Auth(cfg, env, authSender, !writes, () => {}); },
  };
}

/** Read the finding file: at most 2 MB of JSON. */
function readFinding(cwd: string, file: string, pick: number | undefined): ReplaySpec {
  const path = resolve(cwd, file);
  let text: string;
  try {
    if (statSync(path).size > MAX_FINDING_FILE_BYTES) throw new AttackError(`${file} is larger than 2 MB.`);
    text = readFileSync(path, "utf8");
  } catch (e) { if (e instanceof AttackError) throw e; throw new AttackError(`Could not read ${file}.`); }
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new AttackError(`${file} is not valid JSON.`); }
  const parsed = specFromFile(raw, pick);
  if (!parsed.ok) throw new AttackError(`${file}: ${(parsed as { why: string }).why}.`);
  return parsed.spec;
}

export interface GovernorSummary { baseline: Baseline | null; requests: number; events: GovernorEvent[]; stop: GovernorStop | null }
interface CommonOutcome {
  tool: "yof"; version: string; reported_by: typeof REPORTED_BY; rule_id: string;
  target: { origin: string; host: string; kind: ProofOk["kind"]; proof: ProofOk["method"] };
  roe: EngageRoe; governor: GovernorSummary;
  /** Set when the run stopped or a request was refused: what was being tested was NOT tested. Never "passed". */
  not_tested: null | { outcome: "blocked_not_tested" | "not_tested"; why: string };
  cleanup: { planted: number; deleted: number; left: { route: string; why: string }[] };
  notes: string[];
  evidence: EvidenceBundle | null;
}
export interface ReplayOutcome extends CommonOutcome { command: "attack replay"; run: SpecRun | null; still_works: boolean | null }
export interface VerifyOutcome extends CommonOutcome { command: "attack verify"; result: VerifierResult | null; verdict: "stands" | "refuted" | "undecided" }

const notTested = (e: unknown): CommonOutcome["not_tested"] | undefined => {
  if (e instanceof GovernorStopped) return { outcome: outcomeOfStop(e.stop), why: e.stop.detail };
  if (e instanceof RoeRefused) return { outcome: "not_tested", why: e.message };
  if (e instanceof RefusedError) return { outcome: "not_tested", why: e.message };
  if (e instanceof BudgetError) return { outcome: "not_tested", why: e.message };
  if (e instanceof StoppedError) return { outcome: "not_tested", why: "The run was stopped." };
  return undefined;
};
const common = (s: Session, o: EngageOptions, spec: ReplaySpec): Omit<CommonOutcome, "not_tested" | "cleanup" | "evidence"> => ({
  tool: "yof", version: o.version, reported_by: REPORTED_BY, rule_id: spec.ruleId,
  target: { origin: s.proof.origin, host: s.proof.host, kind: s.proof.kind, proof: s.proof.method }, roe: s.roe,
  governor: { baseline: s.governor.baseline, requests: s.governor.state.sent, events: s.governor.events, stop: s.governor.stop }, notes: s.notes,
});

/** `yof attack replay`: the stored steps, as they are, with fresh random values. */
export async function attackReplay(o: EngageOptions & { file: string; pick?: number }): Promise<ReplayOutcome> {
  const spec = readFinding(o.cwd, o.file, o.pick);
  const s = await openSession(o);
  const rec = recordingIo(s.io);
  let run: SpecRun | null = null;
  let stopped: CommonOutcome["not_tested"] = null;
  try {
    await s.governor.measureBaseline();
    run = await runSpec(spec, rec.io, { random: s.random, login: s.login, base: s.proof.origin });
  } catch (e) {
    const n = notTested(e);
    if (n === undefined) throw e;
    stopped = n;
  }
  // What the replay itself created and deleted, counted from what was really sent and answered.
  const good = (c: number) => c >= 200 && c < 300;
  const made = (run?.steps ?? []).filter((x) => { const st = spec.steps[x.step - 1]; return x.leg !== "cleanup" && x.method === "POST" && !!st && "save" in st && !!st.save && x.statuses.some(good); }).length;
  const swept = (run?.steps ?? []).filter((x) => x.leg === "cleanup");
  const deleted = Math.min(made, swept.filter((x) => x.statuses.some((c) => good(c) || c === 404 || c === 410)).length);
  const failed = swept.filter((x) => !x.statuses.some((c) => good(c) || c === 404 || c === 410));
  return {
    ...common(s, o, spec), command: "attack replay", run, not_tested: stopped ?? (run?.incomplete ? { outcome: "not_tested", why: run.incomplete } : null),
    still_works: run && !run.incomplete && !stopped ? run.failures.length > 0 : null,
    cleanup: {
      planted: made, deleted,
      left: made > deleted ? (failed.length ? failed.map((x) => ({ route: x.path, why: x.statuses.length ? `the delete request answered ${x.statuses.at(-1)}` : "the delete request was not sent" })) : [{ route: "the test record of this replay", why: "the delete request was not sent" }]) : [],
    },
    evidence: buildEvidenceBundle({ ruleId: spec.ruleId, reportedBy: REPORTED_BY, runNonce: "", createdAt: s.startedAt, markers: [], exchanges: rec.exchanges, replay: spec }),
  };
}

/** What the config says about tenants: B is a second tenant; the viewer is a member of account A's tenant. */
export const factsFromConfig = (cfg: AttackConfig): VerifierFacts => ({
  tenants: { ...(cfg.accounts.a ? { a: "tenant-a" } : {}), ...(cfg.accounts.viewer ? { viewer: "tenant-a" } : {}), ...(cfg.accounts.b ? { b: "tenant-b" } : {}) },
  publicRoutes: [],
});

/** `yof attack verify`: the verifier. It is handed the steps only, never what an earlier run concluded. */
export async function attackVerify(o: EngageOptions & { file: string; pick?: number }): Promise<VerifyOutcome> {
  const spec = readFinding(o.cwd, o.file, o.pick);
  const s = await openSession(o);
  const rec = recordingIo(s.io);
  const registry = new MarkerRegistry();
  let result: VerifierResult | null = null;
  let stopped: CommonOutcome["not_tested"] = null;
  try {
    await s.governor.measureBaseline();
    result = await verifySpec(spec, rec.io, { registry, random: s.random, facts: factsFromConfig(s.cfg), newSessions: s.newSessions });
  } catch (e) {
    const n = notTested(e);
    if (n === undefined) throw e;
    stopped = n;
  }
  const verdict: VerifyOutcome["verdict"] = result?.stands === true ? "stands" : result?.stands === false ? "refuted" : "undecided";
  return {
    ...common(s, o, spec), command: "attack verify", result, verdict, not_tested: stopped, cleanup: registry.summary(),
    evidence: buildEvidenceBundle({
      ruleId: spec.ruleId, reportedBy: REPORTED_BY, runNonce: registry.nonce, createdAt: s.startedAt, markers: registry.markers(), exchanges: rec.exchanges, replay: spec,
      verifier: result ? { stands: result.stands, refuted_by: result.refutedBy, undecided: result.undecided, notes: result.notes } : null,
    }),
  };
}

// ── Words ────────────────────────────────────────────────────────────────────────────────────────────────────────
export const REFUTATION_WORDS: Record<RefutationRule, string> = {
  marker_reflected: "the test request itself carries the marker, so an answer that shows it proves nothing",
  same_tenant: "the two test accounts are in the same tenant, so one may read the other's record",
  marked_public: "this object is marked as public on purpose",
  cache_served: "a cache gave out the owner's answer: the other account saw the marker only after the owner had read the record",
  negative_control_failed: "the app answers the same way for a record that does not exist",
  not_reproduced: "it did not show again with a new record and a new marker",
};
export const UNDECIDED_WORDS: Record<Undecided, string> = {
  no_marker: "these steps plant no marker, so there is nothing a second run could prove",
  not_supported: "this kind of result cannot be verified by rules yet (only a read of a planted marker can)",
  no_account: "a test account the steps need is not set, or its sign-in failed",
  setup_failed: "the new test record could not be created",
  positive_control_failed: "the owner could not read its own new record, so the test shows nothing",
  no_answer: "the app did not answer, or asked the run to slow down",
};
const cleanupText = (c: CommonOutcome["cleanup"]): string[] => [
  ...(c.planted ? [`Test records: ${c.deleted} deleted${c.left.length ? `, ${c.left.length} left` : ""}.`] : []),
  ...c.left.map((l) => `  Not deleted (delete it in your app): ${l.route} (${l.why})`),
];
const head = (r: CommonOutcome, what: string): string[] => [
  `yof attack ${what}: ${r.rule_id} on ${r.target.host} (${r.target.kind})`,
  `Your own run: yof did not see it, so the result is reported by the owner (${REPORTED_BY}).`,
  ...(r.governor.baseline ? [`Measured the app first: ${r.governor.baseline.samples} reads, half answered within ${Math.round(r.governor.baseline.medianMs)} ms. ${r.governor.requests} requests in all.`] : []),
  ...r.notes.map((n) => `Note: ${n}.`),
];

export function formatReplayText(r: ReplayOutcome): string {
  const out = head(r, "replay");
  out.push("");
  if (r.not_tested) out.push(r.not_tested.outcome === "blocked_not_tested" ? `Blocked, not tested: ${r.not_tested.why}` : `Not tested: ${r.not_tested.why}`);
  else if (r.still_works) { out.push("The attack still works:"); for (const f of r.run!.failures) out.push(`  ${f}`); }
  else out.push("The attack no longer works: every recorded step was refused as it should be. A replay shows what it tried, not that nothing can go wrong.");
  out.push(...cleanupText(r.cleanup));
  return out.join("\n");
}
export function formatVerifyText(r: VerifyOutcome): string {
  const out = head(r, "verify");
  out.push("");
  if (r.not_tested) out.push(r.not_tested.outcome === "blocked_not_tested" ? `Blocked, not tested: ${r.not_tested.why}` : `Not tested: ${r.not_tested.why}`);
  else if (r.result?.stands === true) out.push("The finding stands: a new record with a new marker showed the same, both controls worked, and no rule could refute it.");
  else if (r.result?.stands === false) out.push(`The finding is refuted: ${REFUTATION_WORDS[r.result.refutedBy!]}.`);
  else out.push(`Undecided: ${UNDECIDED_WORDS[r.result?.undecided ?? "no_answer"]}. The finding stays "needs validation".`);
  for (const n of r.result?.notes ?? []) out.push(`  Note: ${n}.`);
  out.push(...cleanupText(r.cleanup));
  return out.join("\n");
}
/** Exit codes: replay 1 while the attack still works; verify 1 when the finding stands. 2 = could not be tested or decided. */
export const replayExit = (r: ReplayOutcome): number => (r.not_tested ? 2 : r.still_works ? 1 : 0);
export const verifyExit = (r: VerifyOutcome): number => (r.not_tested || r.verdict === "undecided" ? 2 : r.verdict === "stands" ? 1 : 0);
