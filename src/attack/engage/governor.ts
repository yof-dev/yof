/**
 * yof engagement, open core: the governor. It stands between a run and the app and decides, before and after every
 * request, whether the run may go on. It wraps the attack HTTP client (../http.ts), which keeps its own rules (one
 * origin, writes only to what the run owns, the hard budgets).
 *
 * BEFORE A RUN   a baseline: 20 harmless GETs. The median and the 95th-percentile answer time and the share of
 *                server errors are what "normal" means for this app today. Nothing else is sent before it exists.
 * EVERY REQUEST  is checked against the rules-of-engagement record (./roe.ts roeCheckRequest): the host is in scope
 *                and proven, the kind of test is allowed there, the time window is open, a read sends only GET and
 *                HEAD, the path holds no forbidden word, the action is not forbidden. Then the pace of the record
 *                (requests a second) and its budgets (total requests, minutes).
 * EVERY 25       requests, a health probe: one more harmless GET.
 * 429 OR 503     the first time the pace is halved; the second time the run pauses for 10 minutes; the third time
 *                it stops.
 * SERVER ERRORS  the run stops when the share of server errors (5xx, or no answer) over the last 50 requests is above
 *                the larger of the baseline plus 5 points, or 2%.
 * SLOW ANSWERS   the run stops when the 95th-percentile answer time of a window of 25 requests is over 3 times the
 *                baseline, three windows running.
 * A BOT WALL     or a challenge page stops the run. What it was about to test is "blocked, not tested", never "passed".
 *
 * The decisions are PURE functions over a small state (computeBaseline, onAnswer, budgetStop, looksBlocked): a test
 * drives them with a fake clock and no network. The Governor class adds the I/O: the waiting and the sending.
 * After a stop, only clean-up requests still go (deleting the run's own test records).
 *
 * The thresholds are the ones written in the design; they are constants here so they can be tuned on our own apps.
 */
import type { As, HttpAnswer, Method, Purpose } from "../http";
import { roeCheckRequest, type EngageRoe, type RoeRefusalCode, type SafetyClass } from "./roe";

export const BASELINE_REQUESTS = 20;
export const PROBE_EVERY = 25;
export const ERROR_WINDOW = 50;
export const ERROR_MARGIN = 0.05;
export const ERROR_FLOOR = 0.02;
export const LATENCY_WINDOW = 25;
export const LATENCY_FACTOR = 3;
export const SLOW_WINDOWS_TO_STOP = 3;
/** A baseline faster than this is counted as this, so a very fast app is not stopped over a few milliseconds. */
export const MIN_BASELINE_P95_MS = 50;
export const PAUSE_MS = 10 * 60_000;
export const MIN_RATE = 0.05;
/** The health probe got no answer this many times in a row: the app may be down, the run stops. */
export const PROBE_FAILS_TO_STOP = 2;

export interface Baseline { samples: number; medianMs: number; p95Ms: number; errorRate: number }
export type GovernorStopReason =
  | "blocked" | "too_many_slow_down_answers" | "server_errors" | "slow_answers" | "no_answer" | "unhealthy_before_start"
  | "request_budget" | "time_budget" | "stopped_by_person";
export interface GovernorStop { reason: GovernorStopReason; detail: string; at: number }

/** What a stopped or refused test may be called. Never "passed" and never "held": it was not tested. */
export type UntestedOutcome = "blocked_not_tested" | "not_tested";
export const outcomeOfStop = (s: GovernorStop): UntestedOutcome => (s.reason === "blocked" ? "blocked_not_tested" : "not_tested");

// ── Pure decisions ───────────────────────────────────────────────────────────────────────────────────────────────
/** Nearest-rank percentile (p from 0 to 1) of a list of numbers; 0 for an empty list. */
export function percentile(values: readonly number[], p: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1))]!;
}
/** A server error for the governor: a 5xx answer, or no answer at all (status 0: a timeout or a dropped connection). */
export const isServerError = (status: number): boolean => status === 0 || status >= 500;
export const isSlowDown = (status: number): boolean => status === 429 || status === 503;

export function computeBaseline(samples: readonly { status: number; ms: number }[]): Baseline {
  const ms = samples.map((s) => s.ms);
  return { samples: samples.length, medianMs: percentile(ms, 0.5), p95Ms: percentile(ms, 0.95), errorRate: samples.length ? samples.filter((s) => isServerError(s.status)).length / samples.length : 0 };
}
/** The share of server errors over the last 50 requests above which the run stops. */
export const errorLimit = (b: Baseline): number => Math.max(b.errorRate + ERROR_MARGIN, ERROR_FLOOR);
/** The 95th-percentile answer time above which a window counts as slow. */
export const latencyLimit = (b: Baseline): number => LATENCY_FACTOR * Math.max(b.p95Ms, MIN_BASELINE_P95_MS);

export interface AnswerView { status: number; body: string; header: (name: string) => string | null }
const REFUSING = new Set([401, 403, 405, 406, 409, 429, 503]);
/**
 * Is this answer a bot wall or a challenge page? Returns its name, or null. An answer like this says nothing about the
 * app behind it, so a test that got it is "blocked, not tested". Pure.
 */
export function looksBlocked(a: AnswerView): string | null {
  const h = (n: string) => (a.header(n) ?? "").toLowerCase();
  if (h("cf-mitigated").includes("challenge")) return "a Cloudflare challenge";
  if (/challenge|captcha/.test(h("x-amzn-waf-action"))) return "an AWS WAF challenge";
  if (h("x-vercel-mitigated")) return "a Vercel challenge";
  if (h("x-datadome") || h("x-dd-b")) return "a DataDome challenge";
  if (h("x-sucuri-block")) return "a Sucuri block";
  const body = a.body.slice(0, 30_000);
  if (/__cf_chl_|cf-chl-|\/cdn-cgi\/challenge-platform\//.test(body)) return "a Cloudflare challenge";
  if (/<title>\s*(?:Just a moment\.\.\.|Attention Required! \| Cloudflare)\s*<\/title>/i.test(body)) return "a Cloudflare challenge";
  if (/captcha-delivery\.com|geo\.captcha-delivery/i.test(body)) return "a DataDome challenge";
  if (/_Incapsula_Resource|Incapsula incident ID/i.test(body)) return "an Imperva block";
  if (/px-captcha|perimeterx/i.test(body) && REFUSING.has(a.status)) return "a PerimeterX challenge";
  if (/errors\.edgesuite\.net|Reference&#32;&#35;|Reference #[0-9a-f.]{8,}/i.test(body) && /access denied/i.test(body)) return "an Akamai block";
  if (/The requested URL was rejected\. Please consult with your administrator/i.test(body)) return "a firewall block";
  if (REFUSING.has(a.status) && /g-recaptcha|recaptcha\/api\.js|h-captcha|hcaptcha\.com\/1\/api\.js|cf-turnstile|challenges\.cloudflare\.com\/turnstile/i.test(body)) return "a CAPTCHA page";
  if (REFUSING.has(a.status) && /(?:verify|verifying) (?:that )?you are (?:a )?human|checking your browser before|pardon our interruption|are you a robot|unusual traffic from your/i.test(body)) return "a bot wall";
  return null;
}

export interface GovernorState {
  baseline: Baseline | null;
  /** Requests a second now (the record's pace, halved after the first 429 or 503). */
  rate: number;
  /** 429 or 503 answers acted on so far: 1 halved the pace, 2 paused, 3 stopped. */
  slowDowns: number;
  pausedUntil: number | null;
  /** The statuses of the last 50 requests after the baseline. */
  recent: number[];
  /** The answer times of the current window of 25. */
  window: number[];
  /** Slow windows in a row. */
  slowWindows: number;
  /** Requests sent, the baseline and the probes included. */
  sent: number;
  sinceProbe: number;
  probeFails: number;
  startedAt: number;
  stop: GovernorStop | null;
}
export const newState = (rate: number, now: number): GovernorState => ({
  baseline: null, rate, slowDowns: 0, pausedUntil: null, recent: [], window: [], slowWindows: 0, sent: 0, sinceProbe: 0, probeFails: 0, startedAt: now, stop: null,
});

export type Decision =
  | { action: "continue" }
  | { action: "halve"; rate: number }
  | { action: "pause"; until: number }
  | { action: "stop"; stop: GovernorStop };

export interface Observed { status: number; ms: number; blocked: string | null; probe?: boolean; baseline?: boolean }

/**
 * What one answer means for the run. Mutates `s` (the counters) and returns what to do next. Pure apart from that:
 * no clock but the `now` it is given, no network.
 */
export function onAnswer(s: GovernorState, a: Observed, now: number): Decision {
  const stop = (reason: GovernorStopReason, detail: string): Decision => { s.stop = { reason, detail, at: now }; return { action: "stop", stop: s.stop }; };
  if (s.stop) return { action: "stop", stop: s.stop };
  if (a.blocked) return stop("blocked", `The app answered with ${a.blocked}. What was being tested is blocked, not tested.`);
  if (a.probe) {
    s.probeFails = a.status === 0 ? s.probeFails + 1 : 0;
    if (s.probeFails >= PROBE_FAILS_TO_STOP) return stop("no_answer", `The health check got no answer ${s.probeFails} times in a row.`);
  }
  if (!a.baseline) {
    s.recent.push(a.status);
    if (s.recent.length > ERROR_WINDOW) s.recent.shift();
    s.window.push(a.ms);
  }
  let decision: Decision = { action: "continue" };
  if (isSlowDown(a.status)) {
    s.slowDowns++;
    if (s.slowDowns >= 3) return stop("too_many_slow_down_answers", `The app answered ${a.status} a third time.`);
    if (s.slowDowns === 2) { s.pausedUntil = now + PAUSE_MS; decision = { action: "pause", until: s.pausedUntil }; }
    else { s.rate = Math.max(MIN_RATE, s.rate / 2); decision = { action: "halve", rate: s.rate }; }
  }
  if (s.baseline && !a.baseline) {
    const errors = s.recent.filter(isServerError).length / ERROR_WINDOW;
    if (errors > errorLimit(s.baseline)) {
      return stop("server_errors", `${s.recent.filter(isServerError).length} of the last ${ERROR_WINDOW} requests got a server error or no answer (the limit is ${Math.round(errorLimit(s.baseline) * 1000) / 10}%).`);
    }
    if (s.window.length >= LATENCY_WINDOW) {
      const p95 = percentile(s.window, 0.95);
      s.window = [];
      s.slowWindows = p95 > latencyLimit(s.baseline) ? s.slowWindows + 1 : 0;
      if (s.slowWindows >= SLOW_WINDOWS_TO_STOP) return stop("slow_answers", `Answers were more than ${LATENCY_FACTOR} times slower than before the run, ${SLOW_WINDOWS_TO_STOP} checks in a row (${Math.round(p95)} ms now, ${Math.round(s.baseline.p95Ms)} ms before).`);
    }
  }
  return decision;
}

/** Is a budget of the record used up? Pure. */
export function budgetStop(s: GovernorState, roe: Pick<EngageRoe, "budgets">, now: number): GovernorStop | null {
  if (s.sent >= roe.budgets.total_requests) return { reason: "request_budget", detail: `The budget of ${roe.budgets.total_requests} requests is used up.`, at: now };
  if (now - s.startedAt >= roe.budgets.max_minutes * 60_000) return { reason: "time_budget", detail: `The budget of ${roe.budgets.max_minutes} minutes is used up.`, at: now };
  return null;
}
/** Milliseconds to wait before the next request so the pace is kept. Pure. */
export const paceWait = (s: Pick<GovernorState, "rate">, lastSentAt: number | null, now: number): number => (lastSentAt === null ? 0 : Math.max(0, Math.ceil(1000 / s.rate - (now - lastSentAt))));
export const probeDue = (s: Pick<GovernorState, "sinceProbe">): boolean => s.sinceProbe >= PROBE_EVERY;
/** The kind of test a request belongs to when the caller did not say. A GET or HEAD is a read. */
export const classOf = (method: Method, purpose: Purpose | undefined): SafetyClass => (method === "GET" || method === "HEAD" ? "read" : purpose === "ai" ? "ai_messages" : "write_own_test_records");

// ── I/O ──────────────────────────────────────────────────────────────────────────────────────────────────────────
/** The run stopped: nothing but clean-up is sent from now on. */
export class GovernorStopped extends Error {
  constructor(readonly stop: GovernorStop) { super(stop.detail); }
  get outcome(): UntestedOutcome { return outcomeOfStop(this.stop); }
}
/** The record does not allow this request. It was not sent. */
export class RoeRefused extends Error {
  constructor(readonly code: RoeRefusalCode, message: string) { super(message); }
}

/** What the governor needs from the HTTP client (AttackClient has all of it). */
export interface GovernedClient {
  readonly origin: string;
  send(as: As, method: Method, path: string, init?: { headers?: Record<string, string>; body?: string; purpose?: Purpose; timeoutMs?: number }): Promise<HttpAnswer>;
  own(id: string, reserve?: number): void;
}
export interface GovernorEvent { kind: "baseline" | "pace_halved" | "paused" | "resumed" | "stopped" | "refused"; at: number; detail: Record<string, string | number> }
export interface GovernorOptions {
  client: GovernedClient;
  roe: EngageRoe;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** The harmless path of the health probe. Default "/". */
  healthPath?: string;
  /** Asked before every request and during a pause: true = the person stopped the run. */
  shouldStop?: () => boolean;
  onEvent?: (e: GovernorEvent) => void;
}
export interface GovernedInit { headers?: Record<string, string>; body?: string; purpose?: Purpose; timeoutMs?: number; cls?: SafetyClass; actions?: readonly string[] }

export class Governor {
  readonly events: GovernorEvent[] = [];
  readonly state: GovernorState;
  readonly host: string;
  private lastSentAt: number | null = null;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly healthPath: string;

  constructor(private readonly o: GovernorOptions) {
    this.now = o.now ?? Date.now;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.host = new URL(o.client.origin).hostname.toLowerCase();
    this.healthPath = o.healthPath ?? "/";
    const h = o.roe.hosts.find((x) => x.host === this.host);
    this.state = newState(h?.requests_per_second ?? MIN_RATE, this.now());
  }

  get stop(): GovernorStop | null { return this.state.stop; }
  get baseline(): Baseline | null { return this.state.baseline; }

  private emit(kind: GovernorEvent["kind"], detail: GovernorEvent["detail"]): void {
    const e = { kind, at: this.now(), detail };
    this.events.push(e);
    this.o.onEvent?.(e);
  }
  private halt(stop: GovernorStop): never {
    const first = this.state.stop ?? stop;
    this.state.stop = first;
    this.emit("stopped", { reason: first.reason, detail: first.detail });
    throw new GovernorStopped(first);
  }
  /** The record's own check. Clean-up may go outside the window (the run's test records must be deleted). */
  private allow(method: Method, path: string, cls: SafetyClass, init: GovernedInit, cleanup: boolean): void {
    const d = roeCheckRequest(this.o.roe, { host: this.host, method, path, cls, body: init.body, actions: init.actions }, new Date(this.now()));
    if (d.ok) return;
    if (cleanup && (d.code === "outside_window" || d.code === "class_not_allowed")) return;
    this.emit("refused", { code: d.code, method, path: path.split("?")[0]! });
    throw new RoeRefused(d.code, d.message);
  }
  /** Wait, in steps of a second at most, so a stop is noticed. */
  private async wait(ms: number): Promise<void> {
    let left = ms;
    while (left > 0) {
      if (this.o.shouldStop?.()) this.halt({ reason: "stopped_by_person", detail: "The run was stopped.", at: this.now() });
      const step = Math.min(1000, left);
      await this.sleep(step);
      left -= step;
    }
  }
  private apply(d: Decision): void {
    if (d.action === "halve") this.emit("pace_halved", { rate: d.rate });
    if (d.action === "pause") this.emit("paused", { until: d.until });
    if (d.action === "stop") { this.emit("stopped", { reason: d.stop.reason, detail: d.stop.detail }); throw new GovernorStopped(d.stop); }
  }
  private async raw(as: As, method: Method, path: string, init: GovernedInit, flags: { probe?: boolean; baseline?: boolean }): Promise<{ answer: HttpAnswer; ms: number }> {
    const pace = paceWait(this.state, this.lastSentAt, this.now());
    if (pace > 0) await this.wait(pace);
    const started = this.now();
    this.lastSentAt = started;
    this.state.sent++;
    const r = await this.o.client.send(as, method, path, { headers: init.headers, body: init.body, purpose: init.purpose, timeoutMs: init.timeoutMs });
    const ms = this.now() - started;
    const blocked = looksBlocked({ status: r.status, body: r.body, header: (n) => r.headers.get(n) });
    this.apply(onAnswer(this.state, { status: r.status, ms, blocked, ...flags }, this.now()));
    return { answer: r, ms };
  }

  /**
   * The baseline: 20 harmless GETs with no sign-in, spread over the given paths (default: the health path). Must run
   * before anything else. An app that is already failing, or a bot wall, stops the run before it starts.
   */
  async measureBaseline(paths: readonly string[] = [this.healthPath]): Promise<Baseline> {
    if (this.state.baseline) return this.state.baseline;
    const list = paths.length ? paths : [this.healthPath];
    const samples: { status: number; ms: number }[] = [];
    for (let i = 0; i < BASELINE_REQUESTS; i++) {
      if (this.state.stop) throw new GovernorStopped(this.state.stop);
      if (this.o.shouldStop?.()) this.halt({ reason: "stopped_by_person", detail: "The run was stopped.", at: this.now() });
      const path = list[i % list.length]!;
      this.allow("GET", path, "read", {}, false);
      const b = budgetStop(this.state, this.o.roe, this.now());
      if (b) this.halt(b);
      if (this.state.pausedUntil !== null && this.state.pausedUntil > this.now()) { await this.wait(this.state.pausedUntil - this.now()); this.state.pausedUntil = null; this.emit("resumed", {}); }
      const r = await this.raw("anon", "GET", path, {}, { baseline: true });
      samples.push({ status: r.answer.status, ms: r.ms });
    }
    const baseline = computeBaseline(samples);
    if (baseline.errorRate >= 0.5) this.halt({ reason: "unhealthy_before_start", detail: `${Math.round(baseline.errorRate * 100)}% of the first ${BASELINE_REQUESTS} harmless requests got a server error or no answer, so the run did not start.`, at: this.now() });
    this.state.baseline = baseline;
    this.emit("baseline", { samples: baseline.samples, median_ms: baseline.medianMs, p95_ms: baseline.p95Ms, error_rate: baseline.errorRate });
    return baseline;
  }

  /** Send one request under the record and the governor. Throws RoeRefused (not sent) or GovernorStopped. */
  async send(as: As, method: Method, path: string, init: GovernedInit = {}): Promise<HttpAnswer> {
    const cleanup = init.purpose === "cleanup";
    const cls = init.cls ?? classOf(method, init.purpose);
    this.allow(method, path, cls, init, cleanup);
    if (cleanup) {
      // Clean-up goes after a stop too, and is not held back by a pause or by the record's budgets (the HTTP client
      // keeps room for it). It is still paced.
      const started = this.now();
      this.lastSentAt = started;
      this.state.sent++;
      return this.o.client.send(as, method, path, { headers: init.headers, body: init.body, purpose: init.purpose, timeoutMs: init.timeoutMs });
    }
    if (this.state.stop) throw new GovernorStopped(this.state.stop);
    if (!this.state.baseline) throw new Error("The governor has no baseline yet: measureBaseline() runs before anything else is sent.");
    if (this.o.shouldStop?.()) this.halt({ reason: "stopped_by_person", detail: "The run was stopped.", at: this.now() });
    const end = this.state.startedAt + this.o.roe.budgets.max_minutes * 60_000;
    if (this.state.pausedUntil !== null && this.state.pausedUntil > this.now()) {
      if (this.state.pausedUntil >= end) this.halt({ reason: "time_budget", detail: `The pause would last longer than the budget of ${this.o.roe.budgets.max_minutes} minutes.`, at: this.now() });
      await this.wait(this.state.pausedUntil - this.now());
      this.state.pausedUntil = null;
      this.emit("resumed", {});
    }
    const b = budgetStop(this.state, this.o.roe, this.now());
    if (b) this.halt(b);
    if (probeDue(this.state)) {
      this.state.sinceProbe = 0;
      this.allow("GET", this.healthPath, "read", {}, false);
      await this.raw("anon", "GET", this.healthPath, {}, { probe: true });
      const again = budgetStop(this.state, this.o.roe, this.now());
      if (again) this.halt(again);
    }
    this.state.sinceProbe++;
    return (await this.raw(as, method, path, init, {})).answer;
  }

  /** Mark an id as created by this run. Two requests are held back for it: the look before the delete, and the delete. */
  own(id: string): void { this.o.client.own(id, 2); }
}
