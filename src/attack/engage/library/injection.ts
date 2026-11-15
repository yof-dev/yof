/**
 * yof engagement, attack library: INJECTION. Text sent to the app must stay data: never part of a query, a template,
 * a page or a command. Every payload is a harmless marker from the fixed list (./payloads.ts). Nothing destructive,
 * nothing that reads a file or the environment.
 *
 *   injection.sql_boolean    SQL and NoSQL by answer pairs. The run searches for ITS OWN marker and adds a condition:
 *                            a true one must still find the record, a false one must lose it. The pairs only narrow a
 *                            search for the run's own record, so no other account's row is ever asked for.
 *   injection.sql_error      one unbalanced quote, and a database error message in the answer that was not there before
 *   injection.sql_time       a wait of two seconds added to the value. ONLY where the record allows timing tests,
 *                            which it never does on a production host (owner decision D8)
 *   injection.template       a sum in template brackets: the answer holds the RESULT (9801547), not the sum's text
 *   injection.xss_reflected  an unknown, do-nothing element with a unique word: it comes back unescaped in a page
 *   injection.xss_stored     the same, stored in the run's own test record and read again
 *   injection.command        an echo of a sum: the answer holds the echo's output (yofcmd1337yof), not its text.
 *                            Marker echo only: never a command that changes or reads anything.
 *
 * WHAT IS NOT CLAIMED. Nothing here runs a script in a browser: that is a later stage. So a markup result is worded
 * "the marker came back unescaped in an HTML context", and it is a finding only when the context is plain (an HTML
 * page, outside a script, a comment, a text area and an attribute value). An error message or a slower answer shows
 * that the text reached something, not what can be done with it: those two always need validation.
 */
import type { As, HttpAnswer } from "../../http";
import type { ReplaySpec, ReplayStep } from "../../replay";
import type { SafetyClass } from "../roe";
import { classFor, deleteStep, notTestable, ok, plant, plantStep, replayPath, result, routeOf, specOf, unusable } from "./kit";
import { CMD_ECHO, SSTI_PRODUCT, TIME_DELAY_SECONDS, fillPayload, payload, payloadsOf } from "./payloads";
import type { ImpactFacts, InputSpec, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";
import { EVIDENCE } from "./words";

const J = (s: string) => JSON.stringify(s).slice(1, -1);
const QUERY_IMPACT: ImpactFacts = { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" };
const EXEC_IMPACT: ImpactFacts = { what: "execution_marker", position: "self_registered", reach: "one_object", data: "ordinary" };
const MARKUP_IMPACT: ImpactFacts = { what: "rule_broken", position: "same_tenant_member", reach: "one_object", data: "ordinary" };
/** What the record calls running anything on the server. The command technique says so on every request it sends. */
export const COMMAND_ACTIONS: readonly string[] = ["write_files_or_run_commands"];

/** A value put into the input's request. `raw`: JSON put in place of the quoted value (an operator object). */
export function valueRequest(input: InputSpec, text: string, raw = false): { method: InputSpec["request"]["method"]; path: string; body?: string; headers?: Record<string, string> } {
  const r = input.request;
  const path = raw
    ? r.path.replace(/([A-Za-z0-9_.-]+)=\{\{value\}\}/g, (_m, name: string) => { try { const o = JSON.parse(text) as Record<string, unknown>; const k = Object.keys(o)[0] ?? ""; return `${name}[${encodeURIComponent(k)}]=${encodeURIComponent(String(o[k]))}`; } catch { return `${name}=${encodeURIComponent(text)}`; } })
    : r.path.split("{{value}}").join(encodeURIComponent(text));
  const body = r.body === undefined ? undefined : raw ? r.body.split("\"{{value}}\"").join(text) : r.body.split("{{value}}").join(J(text));
  return { method: r.method, path, ...(body !== undefined ? { body } : {}), ...(r.headers ? { headers: r.headers } : {}) };
}
async function sendValue(ctx: TechniqueContext, input: InputSpec, text: string, cls: SafetyClass | null = null, raw = false, actions?: readonly string[]): Promise<HttpAnswer | null> {
  const f = valueRequest(input, text, raw);
  return ctx.io.send(input.as ?? "a", f.method, f.path, {
    ...(f.body !== undefined ? { body: f.body } : {}), ...(f.headers ? { headers: f.headers } : {}),
    purpose: f.method === "GET" || f.method === "HEAD" ? "read" : "create", cls: cls ?? classFor(f.method), leg: "test", ...(actions ? { actions } : {}),
  });
}
/** A value request as a replay step. {{name}} parts of the text stay variables; everything else is encoded for its place. */
const valueStep = (input: InputSpec, text: string, extra: Partial<ReplayStep>, raw = false): ReplayStep => {
  const parts = (t: string, enc: (x: string) => string) => t.split(/(\{\{\w+\}\})/).map((part) => (/^\{\{\w+\}\}$/.test(part) ? part : enc(part))).join("");
  const r = input.request;
  let path = r.path.split("{{value}}").join(parts(text, encodeURIComponent));
  let body = r.body === undefined ? undefined : r.body.split("{{value}}").join(parts(text, J));
  if (raw) {
    let key = "", inner = "";
    try { const o = JSON.parse(text) as Record<string, unknown>; key = Object.keys(o)[0] ?? ""; inner = String(o[key] ?? ""); } catch { key = ""; }
    path = r.path.replace(/([A-Za-z0-9_.-]+)=\{\{value\}\}/g, (_m, name: string) => `${name}[${encodeURIComponent(key)}]=${parts(inner, encodeURIComponent)}`);
    body = r.body === undefined ? undefined : r.body.split("\"{{value}}\"").join(text);
  }
  return { as: input.as ?? "a", method: r.method, path: replayPath(path), ...(body !== undefined ? { body } : {}), ...(r.headers ? { headers: r.headers } : {}), ...extra };
};

// ── Signatures and contexts (pure) ───────────────────────────────────────────────────────────────────────────────
export const DATABASE_ERRORS: readonly { name: string; re: RegExp }[] = [
  { name: "sqlite", re: /SQLITE_ERROR|sqlite3?\.OperationalError|near "[^"]{0,40}": syntax error|unrecognized token:/ },
  { name: "postgresql", re: /syntax error at or near|unterminated quoted string at or near|PG::SyntaxError|org\.postgresql\.util\.PSQLException/ },
  { name: "mysql", re: /You have an error in your SQL syntax|check the manual that corresponds to your (?:MySQL|MariaDB)/ },
  { name: "sql_server", re: /Unclosed quotation mark after the character string|Incorrect syntax near/ },
  { name: "oracle", re: /\bORA-\d{5}\b/ },
  { name: "sql_state", re: /SQLSTATE\[\w{2,8}\]/ },
  { name: "mongodb", re: /MongoServerError|MongoError|unknown operator: \$yofnone|unknown top level operator: \$yofnone/ },
];
/** The database whose error message an answer holds, or null. Pure. */
export const databaseError = (body: string): string | null => DATABASE_ERRORS.find((s) => s.re.test(body.slice(0, 60_000)))?.name ?? null;

export type MarkupContext = "absent" | "escaped" | "not_html" | "inert" | "attribute" | "element";
const INERT = ["script", "style", "textarea", "title", "noscript", "xmp", "template"];
/**
 * Where the test element sits in an answer. "element": it came back as markup in the body of an HTML page. "inert":
 * inside a script, a style, a text area, a title or a comment, where a browser does not read it as an element.
 * "attribute": inside a tag, in an attribute value. Pure.
 */
export function markupContext(body: string, contentType: string, token: string): MarkupContext {
  const needle = `<yof-x data-m="${token}">`;
  const at = body.indexOf(needle);
  if (at < 0) return body.includes(token) ? "escaped" : "absent";
  if (!/\b(?:text\/html|application\/xhtml\+xml)\b/i.test(contentType)) return "not_html";
  const before = body.slice(0, at).toLowerCase();
  if (before.lastIndexOf("<!--") > before.lastIndexOf("-->")) return "inert";
  for (const tag of INERT) if (before.lastIndexOf(`<${tag}`) > before.lastIndexOf(`</${tag}`)) return "inert";
  return before.lastIndexOf("<") > before.lastIndexOf(">") ? "attribute" : "element";
}
const median = (xs: readonly number[]): number => { const s = [...xs].sort((a, b) => a - b); return s.length ? s[Math.floor((s.length - 1) / 2)]! : 0; };
/** Is the wait shown? Both delayed answers came at least 80% of the wait later than the usual answer, and the same value with no wait did not. Pure. */
export function waitShown(baselineMs: readonly number[], zeroMs: number, delayedMs: readonly number[], seconds: number): boolean {
  const usual = median(baselineMs), need = seconds * 800;
  return delayedMs.length >= 2 && delayedMs.every((d) => d - usual >= need) && zeroMs - usual < need / 2;
}

type Head = Omit<Technique, "run" | "chain">;
const NEEDS_INPUT = "the app model names no place where text goes in for this";
const base = { invariants: ["input_is_data"] as const, owasp: "A03" };

const SQL_BOOLEAN: Head = {
  ...base, id: "injection.sql_boolean", ruleId: "attack.query_injection", title: "Text sent to the app is run as part of a database query",
  prerequisites: ["account_a", "test_object", "text_input"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"],
  payloads: [...payloadsOf("sql_boolean"), ...payloadsOf("nosql_boolean")],
  oracle: "A search for the run's own marker finds its record; with a true condition added it still does, with a false one it does not, twice each, for at least two different pairs; a marker with two letters added finds nothing.",
  shows: "that a condition written into the value is evaluated by the database", cannotShow: "what else the query could be made to return: only the run's own record is searched for",
  best: "confirmed", impact: QUERY_IMPACT,
};
const SQL_ERROR: Head = {
  ...base, id: "injection.sql_error", ruleId: "attack.query_injection", title: SQL_BOOLEAN.title,
  prerequisites: ["text_input"], safetyClass: "read", classes: ["read", "write_own_test_records"], payloads: payloadsOf("sql_error"),
  oracle: "An unbalanced quote in the value brings back a database error message that an ordinary value does not.",
  shows: "that the value reached a query and broke it", cannotShow: "whether the query can be steered: an error is not a proof of that",
  best: "needs_validation", impact: QUERY_IMPACT,
};
const SQL_TIME: Head = {
  ...base, id: "injection.sql_time", ruleId: "attack.query_injection", title: SQL_BOOLEAN.title,
  prerequisites: ["text_input"], safetyClass: "timing", classes: ["timing"], payloads: payloadsOf("sql_time"),
  oracle: `Two answers come about ${TIME_DELAY_SECONDS} seconds later when a wait is added to the value, and the same value with a wait of zero does not.`,
  shows: "that a wait written into the value is run by the database", cannotShow: "anything on a production host: timing tests are never run there",
  best: "needs_validation", impact: QUERY_IMPACT,
};
const TEMPLATE: Head = {
  ...base, id: "injection.template", ruleId: "attack.template_injection", title: "Text sent to the app is run by its page template engine",
  prerequisites: ["text_input"], safetyClass: "read", classes: ["read", "write_own_test_records"], payloads: payloadsOf("template"),
  oracle: `The answer holds yof${SSTI_PRODUCT}yof, the result of the sum 1337 * 7331 sent in template brackets, twice; an ordinary value brings no such number.`,
  shows: "that the template engine evaluates what the request sends", cannotShow: "what else the engine would run: only a sum is sent",
  best: "confirmed", impact: EXEC_IMPACT,
};
const XSS_REFLECTED: Head = {
  ...base, id: "injection.xss_reflected", ruleId: "attack.unescaped_markup", title: "Text sent to the app comes back as live page markup",
  prerequisites: ["text_input"], safetyClass: "read", classes: ["read", "write_own_test_records"], payloads: payloadsOf("markup"),
  oracle: "An unknown element with a unique word comes back unescaped in the body of an HTML page (outside a script, a comment, a text area and an attribute value), twice.",
  shows: "that markup in the value becomes markup in the page", cannotShow: "that a script runs: nothing is run in a browser at this stage, so a content security policy may still stop it",
  best: "confirmed", impact: MARKUP_IMPACT,
};
const XSS_STORED: Head = {
  ...XSS_REFLECTED, id: "injection.xss_stored", prerequisites: ["account_a", "test_object"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"],
  oracle: "The same element, stored in the run's own test record, comes back unescaped in the body of an HTML page when the record is read again (as another test account where there is one), twice.",
};
const COMMAND: Head = {
  ...base, id: "injection.command", ruleId: "attack.command_injection", title: "Text sent to the app is run as a system command",
  prerequisites: ["text_input"], safetyClass: "read", classes: ["read", "write_own_test_records"], payloads: payloadsOf("command"),
  oracle: `The answer holds ${CMD_ECHO}, the output of an echo of the sum 1300 + 37, twice; an ordinary value brings no such text.`,
  shows: "that the server's shell runs what the request sends", cannotShow: "anything beyond the echo: no other command is ever sent",
  best: "confirmed", impact: EXEC_IMPACT, actions: COMMAND_ACTIONS,
};

/** Send every payload of a list, twice when the first answer shows the sign. The first payload that shows it twice wins. */
async function firstShown(ctx: TechniqueContext, input: InputSpec, ids: readonly string[], slots: Record<string, string>, shown: (r: HttpAnswer) => boolean, actions?: readonly string[]): Promise<{ id: string; status: number; twice: boolean } | null> {
  let once: { id: string; status: number; twice: boolean } | null = null;
  for (const id of ids) {
    const text = fillPayload(id, slots);
    const r = await sendValue(ctx, input, text, null, false, actions);
    if (!r || unusable(r) || !shown(r)) continue;
    const again = await sendValue(ctx, input, text, null, false, actions);
    if (again && shown(again)) return { id, status: r.status, twice: true };
    once ??= { id, status: r.status, twice: false };
  }
  return once;
}
const reflectedChain = (t: Head, input: InputSpec, text: string, forbidden: string, vars: string[], accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, vars, accounts, [valueStep(input, text, { expect: { kind: "not_contains", value: forbidden } })]);

async function runReflected(t: Head, ctx: TechniqueContext, target: TechniqueTarget, sign: string, evidence: string, actions?: readonly string[]): Promise<TechniqueResult> {
  const input = target.input;
  if (!input) return notTestable(t, NEEDS_INPUT);
  const route = routeOf(input.request.path), method = input.request.method, as: As = input.as ?? "a";
  const plain = await sendValue(ctx, input, `yof${ctx.random()}`, null, false, actions);
  if (plain === null) return notTestable(t, "the test account is not set, or its sign-in failed");
  if (unusable(plain)) return notTestable(t, "an ordinary value got no usable answer");
  if (plain.body.includes(sign)) return notTestable(t, "an ordinary value already brings the text this test looks for, so the test would show nothing");
  const hit = await firstShown(ctx, input, t.payloads, {}, (r) => r.body.includes(sign), actions);
  if (!hit) return result(t, "held", { reason: "no payload of the list was run: the answers held only what was sent, or nothing", method, route, as });
  return result(t, hit.twice ? "violated" : "needs_validation", {
    reason: hit.twice ? "the answer held the result, not the text that was sent, twice, and an ordinary value did not bring it" : "it showed once and not a second time",
    method, route, as, status: hit.status, payload: hit.id, evidence, meta: { payload: hit.id, param: "value" },
    replay: reflectedChain(t, input, payload(hit.id).value, sign, [], ctx.accounts),
  });
}

export const INJECTION_TECHNIQUES: readonly Technique[] = [
  {
    ...SQL_BOOLEAN,
    chain: (target, accounts) => (target.object && target.input ? specOf(SQL_BOOLEAN, ["marker"], accounts, [
      plantStep("a", target.object),
      valueStep(target.input, fillPayload("sqli.and_quote.true", { marker: "{{marker}}" }), { expect: { kind: "not_contains", value: "{{marker}}" } }),
      deleteStep("a", target.object),
    ]) : null),
    run: async (ctx, target) => {
      const t = SQL_BOOLEAN, input = target.input, o = target.object;
      if (!input?.searchesObject || !o) return notTestable(t, "the app model names no search that looks the test record up by its marked field");
      const planted = await plant(ctx, "a", o);
      if (!planted.ok) return notTestable(t, (planted as { why: string }).why);
      const { marker, id } = planted.record;
      const route = routeOf(input.request.path), method = input.request.method, as: As = input.as ?? "a";
      const finds = (r: HttpAnswer | null) => !!r && ok(r.status) && r.body.includes(marker);
      const own = await sendValue(ctx, input, marker);
      if (own === null) return notTestable(t, "the test account is not set, or its sign-in failed");
      if (!finds(own)) return notTestable(t, "the search does not find the run's own record by its marker, so the test would show nothing");
      if (finds(await sendValue(ctx, input, `${marker}ZZ`))) return notTestable(t, "the search finds the record for a value that does not match it, so answer pairs would show nothing");
      const pairs = [...new Set(t.payloads.map((p) => p.replace(/\.(?:true|false)$/, "")))];
      const hits: string[] = [];
      let status = own.status;
      for (const pair of pairs) {
        const raw = pair.startsWith("nosql.");
        const slots = { marker, id };
        const yes = fillPayload(`${pair}.true`, slots), no = fillPayload(`${pair}.false`, slots);
        const t1 = await sendValue(ctx, input, yes, null, raw);
        if (!finds(t1)) continue;
        const f1 = await sendValue(ctx, input, no, null, raw);
        if (!f1 || unusable(f1) || finds(f1)) continue;
        const t2 = await sendValue(ctx, input, yes, null, raw), f2 = await sendValue(ctx, input, no, null, raw);
        if (finds(t2) && f2 && !unusable(f2) && !finds(f2)) { hits.push(pair); status = t1!.status; }
        if (hits.length >= 2) break;
      }
      if (!hits.length) return result(t, "held", { reason: "a condition added to the value changed nothing: the value stayed data", method, route, as, status });
      return result(t, hits.length >= 2 ? "violated" : "needs_validation", {
        reason: hits.length >= 2 ? "two different pairs of conditions decided whether the run's own record was found, twice each, and the controls worked" : "one pair of conditions decided whether the record was found; a second, different pair did not show it",
        method, route, as, status, marker, payload: `${hits[0]}.true`, evidence: EVIDENCE.booleanPair(hits.length), meta: { payload: hits.join(", "), proof: "marker", count: String(hits.length) },
        replay: specOf(t, ["marker"], ctx.accounts, [plantStep("a", o), valueStep(input, fillPayload(`${hits[0]}.true`, { marker: "{{marker}}", id: "{{id}}" }), { expect: { kind: "not_contains", value: "{{marker}}" } }, hits[0]!.startsWith("nosql.")), deleteStep("a", o)]),
      });
    },
  },
  {
    ...SQL_ERROR, chainLimit: "The replay checks that the database's error text no longer comes back. It cannot check that the query is safe.",
    chain: (target, accounts) => (target.input ? reflectedChain(SQL_ERROR, target.input, "yof'", "syntax error", [], accounts) : null),
    run: async (ctx, target) => {
      const t = SQL_ERROR, input = target.input;
      if (!input) return notTestable(t, NEEDS_INPUT);
      const route = routeOf(input.request.path), method = input.request.method, as: As = input.as ?? "a";
      const word = `yof${ctx.random()}`;
      const plain = await sendValue(ctx, input, word);
      if (plain === null) return notTestable(t, "the test account is not set, or its sign-in failed");
      if (unusable(plain)) return notTestable(t, "an ordinary value got no usable answer");
      if (databaseError(plain.body)) return notTestable(t, "an ordinary value already brings a database error message, so the test would show nothing");
      for (const id of t.payloads) {
        const raw = id.startsWith("nosql.");
        const r = await sendValue(ctx, input, fillPayload(id, { marker: word }), null, raw);
        const db = r && !unusable(r) ? databaseError(r.body) : null;
        if (!db) continue;
        return result(t, "needs_validation", {
          reason: "an error message shows the value reached a query and broke it; it does not show that the query can be steered", method, route, as, status: r!.status, payload: id,
          evidence: EVIDENCE.databaseError(db), meta: { payload: id, signature: db }, replay: reflectedChain(t, input, fillPayload(id, { marker: "yof" }), DATABASE_ERRORS.find((s) => s.name === db)!.re.exec(r!.body)?.[0]?.replace(/[^A-Za-z0-9_ :.[\]-]/g, "").slice(0, 60) || "syntax error", [], ctx.accounts),
        });
      }
      return result(t, "held", { reason: "no unbalanced quote brought a database error message", method, route, as, status: plain.status });
    },
  },
  {
    ...SQL_TIME, chainLimit: "A replay cannot measure time. It sends the value with the wait and checks nothing: run the technique again to re-test.",
    chain: (target, accounts) => (target.input ? specOf(SQL_TIME, [], accounts, [valueStep(target.input, fillPayload("sqli.time.pg", { marker: "yof", n: String(TIME_DELAY_SECONDS) }), {})]) : null),
    run: async (ctx, target) => {
      const t = SQL_TIME, input = target.input;
      if (!input) return notTestable(t, NEEDS_INPUT);
      const route = routeOf(input.request.path), method = input.request.method, as: As = input.as ?? "a";
      const word = `yof${ctx.random()}`;
      const timed = async (text: string): Promise<{ ms: number; status: number } | null> => { const start = ctx.now(); const r = await sendValue(ctx, input, text, "timing"); return r && !unusable(r) ? { ms: ctx.now() - start, status: r.status } : null; };
      const usual: number[] = [];
      for (let i = 0; i < 3; i++) { const b = await timed(word); if (!b) return notTestable(t, "an ordinary value got no usable answer"); usual.push(b.ms); }
      for (const id of t.payloads) {
        const zero = await timed(fillPayload(id, { marker: word, n: "0" }));
        const d1 = await timed(fillPayload(id, { marker: word, n: String(TIME_DELAY_SECONDS) }));
        if (!zero || !d1 || !waitShown(usual, zero.ms, [d1.ms, d1.ms], TIME_DELAY_SECONDS)) continue;
        const d2 = await timed(fillPayload(id, { marker: word, n: String(TIME_DELAY_SECONDS) }));
        if (!d2 || !waitShown(usual, zero.ms, [d1.ms, d2.ms], TIME_DELAY_SECONDS)) continue;
        return result(t, "needs_validation", {
          reason: "a slower answer is a sign, not a proof: the wait may come from somewhere else", method, route, as, status: d1.status, payload: id,
          evidence: EVIDENCE.timedWait(TIME_DELAY_SECONDS), meta: { payload: id }, replay: specOf(t, [], ctx.accounts, [valueStep(input, fillPayload(id, { marker: "yof", n: String(TIME_DELAY_SECONDS) }), {})]),
        });
      }
      return result(t, "held", { reason: "no wait added to the value made the answer slower", method, route, as });
    },
  },
  {
    ...TEMPLATE,
    chain: (target, accounts) => (target.input ? reflectedChain(TEMPLATE, target.input, payload("ssti.curly").value, `yof${SSTI_PRODUCT}yof`, [], accounts) : null),
    run: (ctx, target) => runReflected(TEMPLATE, ctx, target, `yof${SSTI_PRODUCT}yof`, EVIDENCE.templateSum()),
  },
  {
    ...XSS_REFLECTED,
    chain: (target, accounts) => (target.input ? reflectedChain(XSS_REFLECTED, target.input, fillPayload("xss.break_tag", { token: "{{word}}" }), "<yof-x data-m=\"{{word}}\">", ["word"], accounts) : null),
    run: async (ctx, target) => {
      const t = XSS_REFLECTED, input = target.input;
      if (!input) return notTestable(t, NEEDS_INPUT);
      const route = routeOf(input.request.path), method = input.request.method, as: As = input.as ?? "a";
      let weak: { id: string; context: MarkupContext; status: number } | null = null;
      for (const id of t.payloads) {
        const token = `yofx${ctx.random()}`;
        const text = fillPayload(id, { token });
        const r = await sendValue(ctx, input, text);
        if (r === null) return notTestable(t, "the test account is not set, or its sign-in failed");
        if (unusable(r) || !ok(r.status)) continue;
        const context = markupContext(r.body, r.headers.get("content-type") ?? "", token);
        if (context === "inert" || context === "attribute") { weak ??= { id, context, status: r.status }; continue; }
        if (context !== "element") continue;
        const again = await sendValue(ctx, input, text);
        const twice = !!again && ok(again.status) && markupContext(again.body, again.headers.get("content-type") ?? "", token) === "element";
        return result(t, twice ? "violated" : "needs_validation", {
          reason: twice ? "the element came back as markup in the body of an HTML page, twice" : "it showed once and not a second time", method, route, as, status: r.status, payload: id,
          evidence: EVIDENCE.markupReflected("element"), meta: { payload: id, kind: "element" },
          replay: reflectedChain(t, input, fillPayload(id, { token: "{{word}}" }), "<yof-x data-m=\"{{word}}\">", ["word"], ctx.accounts),
        });
      }
      if (weak) return result(t, "needs_validation", {
        reason: weak.context === "inert" ? "the element came back unescaped, but inside a script, a comment or a text area, where a browser does not read it as an element" : "the element came back unescaped inside an attribute value; whether it can leave the attribute was not shown",
        method, route, as, status: weak.status, payload: weak.id, evidence: EVIDENCE.markupReflected(weak.context), meta: { payload: weak.id, kind: weak.context },
        replay: reflectedChain(t, input, fillPayload(weak.id, { token: "{{word}}" }), "<yof-x data-m=\"{{word}}\">", ["word"], ctx.accounts),
      });
      return result(t, "held", { reason: "the element came back escaped, or not in an HTML page, or not at all", method, route, as });
    },
  },
  {
    ...XSS_STORED,
    chain: (target, accounts) => {
      const o = target.object;
      if (!o) return null;
      const suffix = J(fillPayload("xss.tag", { token: "YOFWORDSLOT" })).split("YOFWORDSLOT").join("{{word}}");
      return specOf(XSS_STORED, ["marker", "word"], accounts, [
        { ...plantStep("a", o), body: o.create.body.split("{{marker}}").join(`{{marker}}${suffix}`) },
        { as: target.input?.render?.as ?? "a", method: "GET", path: replayPath(target.input?.render?.path ?? o.read), expect: { kind: "not_contains", value: "<yof-x data-m=\"{{word}}\">" } },
        deleteStep("a", o),
      ]);
    },
    run: async (ctx, target) => {
      const t = XSS_STORED, o = target.object;
      if (!o) return notTestable(t, "the app model names no test record for this");
      const show = target.input?.render?.path ?? o.read;
      const route = routeOf(show);
      const token = `yofx${ctx.random()}`;
      const planted = await plant(ctx, "a", o, fillPayload("xss.tag", { token }));
      if (!planted.ok) return notTestable(t, (planted as { why: string }).why);
      const path = show.split("{id}").join(encodeURIComponent(planted.record.id));
      // Read again as another test account where there is one; the owner's own read shows the same page otherwise.
      const readers: As[] = [...new Set<As>([target.input?.render?.as ?? "viewer", "admin", "a"])];
      let r: HttpAnswer | null = null, as: As = "a";
      for (const who of readers) { const x = await ctx.io.send(who, "GET", path, { purpose: "read", cls: "read", leg: "test" }); if (x && ok(x.status)) { r = x; as = who; break; } }
      if (!r) return notTestable(t, "no test account could read the record again");
      const context = markupContext(r.body, r.headers.get("content-type") ?? "", token);
      if (context !== "element" && context !== "inert" && context !== "attribute") return result(t, "held", { reason: "the stored element came back escaped, or not in an HTML page", route, as, status: r.status });
      const again = await ctx.io.send(as, "GET", path, { purpose: "read", cls: "read", leg: "test" });
      const twice = context === "element" && !!again && markupContext(again.body, again.headers.get("content-type") ?? "", token) === "element";
      return result(t, twice ? "violated" : "needs_validation", {
        reason: twice ? "the stored element came back as markup in the body of an HTML page, twice" : context === "element" ? "it showed once and not a second time" : "the stored element came back unescaped, but in a place where a browser does not read it as an element",
        route, as, status: r.status, payload: "xss.tag", marker: planted.record.marker, evidence: EVIDENCE.markupStored(context), meta: { payload: "xss.tag", kind: context, record: o.create.path },
        replay: INJECTION_TECHNIQUES[5]!.chain(target, ctx.accounts),
      });
    },
  },
  {
    ...COMMAND,
    chain: (target, accounts) => (target.input ? reflectedChain(COMMAND, target.input, payload("cmd.semicolon").value, CMD_ECHO, [], accounts) : null),
    run: (ctx, target) => runReflected(COMMAND, ctx, target, CMD_ECHO, EVIDENCE.commandEcho(), COMMAND_ACTIONS),
  },
];
