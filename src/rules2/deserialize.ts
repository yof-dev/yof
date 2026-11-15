/**
 * Family 3, loading objects from text the caller controls (insecure deserialization). Every form needs request
 * input (./ast.ts, ./py.ts) as the thing being loaded. Verdict: needs_validation.
 *
 *   inside.code_unsafe_deserialize
 *     JavaScript / TypeScript  node-serialize unserialize, serialize-to-js deserialize, funcster deepDeserialize;
 *                              js-yaml load / loadAll when the project pins js-yaml below 4 (where load runs
 *                              !!js/function) or the call asks for the full, unsafe schema
 *     Python                   pickle / cPickle / dill / cloudpickle load(s), marshal.loads, jsonpickle.decode,
 *                              yaml.unsafe_load, yaml.load without a Safe loader
 *     PHP                      unserialize() of $_GET / $_POST / $_COOKIE / $_REQUEST on the same line, without
 *                              allowed_classes
 *     Ruby                     Marshal.load of params / cookies / request on the same line
 * NOT COVERED: Java ObjectInputStream, .NET BinaryFormatter, XML external entities. JSON.parse is safe and never flagged.
 * KNOWN RISK of a false alarm: a value that was signed and verified earlier in another function.
 */
import type * as TS from "typescript";
import { calleeName, callsModule, importsOf, lineOfNode, prop, taintAt, walk } from "./ast";
import type { ProjectFacts } from "./injection";
import { isPython, pyCalls, pyCode, pyTaint } from "./py";
import { finding, lineOf, shortText, type R2File, type R2Finding, type Ts } from "./types";

const RULE = "inside.code_unsafe_deserialize";

export function deserializeFindings(ts: Ts, f: R2File, sf: TS.SourceFile, facts: ProjectFacts): R2Finding[] {
  const out: R2Finding[] = [];
  const imp = importsOf(ts, sf);
  const libs = ["node-serialize", "serialize-to-js", "funcster", "js-yaml"];
  if (!libs.some((m) => imp.modules.has(m))) return out;
  walk(ts, sf, (n) => {
    if (!ts.isCallExpression(n) || !n.arguments[0]) return;
    const a0 = n.arguments[0];
    const name = calleeName(ts, n);
    let sink = "";
    if (callsModule(ts, imp, n, ["node-serialize"], ["unserialize"])) sink = "node-serialize unserialize";
    else if (callsModule(ts, imp, n, ["serialize-to-js"], ["deserialize"])) sink = "serialize-to-js deserialize";
    else if (callsModule(ts, imp, n, ["funcster"], ["deepDeserialize", "deserialize"])) sink = `funcster ${name}`;
    else if (callsModule(ts, imp, n, ["js-yaml"], ["load", "loadAll"])) {
      const opts = n.arguments.find((a) => ts.isObjectLiteralExpression(a));
      const schema = opts ? prop(ts, opts, "schema")?.getText(sf) ?? "" : "";
      const unsafeSchema = /DEFAULT_FULL_SCHEMA|unsafe/i.test(schema);
      const safeSchema = /SAFE|JSON_SCHEMA|FAILSAFE|CORE_SCHEMA/i.test(schema) && !unsafeSchema;
      if (unsafeSchema || (facts.jsYamlMajor !== null && facts.jsYamlMajor < 4 && !safeSchema)) sink = `js-yaml ${name}`;
    }
    if (sink && taintAt(ts, sf, n).is(a0)) out.push(finding(RULE, f, lineOfNode(sf, n), { sink, input: "request" }, { snippet: shortText(n.getText(sf)) }));
  });
  return out;
}

const PHP = /\bunserialize\s*\(\s*(?:base64_decode\s*\(\s*|urldecode\s*\(\s*|stripslashes\s*\(\s*)*\$_(?:GET|POST|COOKIE|REQUEST)\b[^\n]*/g;
const RUBY = /\b(?:Marshal\.load|YAML\.unsafe_load)\s*\(?\s*(?:Base64\.\w+\s*\(?\s*)?(?:params|cookies|request)\b[^\n]*/g;

export function textDeserializeFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  if (isPython(f.path)) {
    const code = pyCode(f.content);
    for (const c of pyCalls(code, "(?:pickle|cPickle|_pickle|dill|cloudpickle)\\.loads?|marshal\\.loads?|jsonpickle\\.decode|yaml\\.(?:unsafe_load|unsafe_load_all|load|load_all|full_load)")) {
      if (/^yaml\.load(?:_all)?$/.test(c.name) && /Loader\s*=\s*(?:yaml\.)?C?SafeLoader|Loader\s*=\s*(?:yaml\.)?BaseLoader|,\s*(?:yaml\.)?C?SafeLoader/.test(c.args)) continue;
      if (c.name === "yaml.full_load") continue;   // FullLoader does not build arbitrary objects since PyYAML 5.4
      if (pyTaint(code, c.line).is(c.first)) out.push(finding(RULE, f, c.line, { sink: c.name, input: "request", language: "python" }, { snippet: shortText(f.content.split("\n")[c.line - 1] ?? "") }));
    }
    return out;
  }
  const re = /\.php$/i.test(f.path) ? PHP : /\.rb$/i.test(f.path) ? RUBY : null;
  if (!re) return out;
  re.lastIndex = 0;
  for (let m = re.exec(f.content); m; m = re.exec(f.content)) {
    if (/allowed_classes/.test(m[0])) continue;
    const line = lineOf(f.content, m.index);
    if (/^\s*(?:\/\/|#|\*)/.test(f.content.split("\n")[line - 1] ?? "")) continue;
    out.push(finding(RULE, f, line, { sink: m[0].split("(")[0]!.trim(), input: "request", language: /\.php$/i.test(f.path) ? "php" : "ruby" }, { snippet: shortText(m[0]) }));
  }
  return out;
}
