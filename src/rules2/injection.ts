/**
 * Family 1, injection patterns in code. Every rule here needs request input (./ast.ts: read from the request in the
 * same function or handler) to reach a known sink. Verdict: needs_validation, always. yof read the code, it did not
 * run it.
 *
 *   inside.code_sql_injection       SQL text built with ${} or + from request input, handed to a raw query call
 *                                   (query, execute, raw, unsafe, $queryRawUnsafe, exec, all, get, run, prepare,
 *                                   whereRaw and friends). Tagged templates (sql`...`) are parameterised: never flagged.
 *                                   Python: execute / executemany / raw / text with an f-string, % or + of request input.
 *   inside.code_nosql_injection     a MongoDB-style query (find, findOne, updateOne, deleteMany, ...) whose filter takes
 *                                   a value straight from req.body / req.query (so the caller can send {"$ne": null}),
 *                                   the whole filter from the request, or a $where string built from it. Only in a
 *                                   project that uses MongoDB, Mongoose or a database with the same query language.
 *   inside.code_command_injection   child_process exec / execSync with a command built from request input; spawn /
 *                                   execFile with shell: true; sh -c with request input. Python: os.system, os.popen,
 *                                   subprocess.* with shell=True.
 *   inside.code_template_injection  request input used as the TEMPLATE (not the data) of ejs, pug, handlebars,
 *                                   nunjucks, lodash template, doT, eta. Python: render_template_string, Template().
 *   inside.code_eval_input          eval, new Function, vm.runIn*, setTimeout("text") on request input. Python: eval, exec.
 *   inside.code_xss_sink            dangerouslySetInnerHTML, innerHTML / outerHTML, insertAdjacentHTML, document.write
 *                                   with request input or the page's own address; res.send of HTML text built from
 *                                   request input.
 *   inside.code_open_redirect       a redirect whose target starts with request input, with no same-site check in the handler.
 *   inside.code_ssrf                a server fetch (fetch, axios, got, needle, request, http.get, undici) whose address
 *                                   starts with request input, with no host check in the handler. Python: requests,
 *                                   httpx, urllib.
 * GUARDS shared by all: a value that went through another function, .replace() or a comparison is not request input
 * any more; tests, fixtures, examples and docs are not read (types.ts skipPath).
 */
import type * as TS from "typescript";
import { bare, calleeName, callsModule, dotted, fixedParts, handlerText, importsOf, lineOfNode, movingParts, prop, receiverOf, strLit, taintAt, taintedStart, walk, isTrue, type Imports, type Taint } from "./ast";
import { isPython, pyArgs, pyCalls, pyCode, pyTaint } from "./py";
import { finding, shortText, type R2File, type R2Finding, type Ts } from "./types";

export interface ProjectFacts {
  /** The project uses MongoDB or a database with the same query language (package.json, requirements). */
  mongo: boolean;
  /** Some file cleans query operators out of request input (mongo-sanitize and friends). */
  mongoSanitized: boolean;
  /** The major version of js-yaml in package.json, or null. */
  jsYamlMajor: number | null;
}

const SQL_WORDS = /\b(?:select\b[\s\S]*\bfrom|insert\s+into|update\s+[\w."`[\]]+\s+set|delete\s+from|where\s+[\w."`]+\s*(?:=|<|>|like|in\b))/i;
const SQL_PIECE = /(?:=|<|>|\blike|\bin\s*\(|\bvalues\s*\(|\bwhere|\band|\bor|\bset|\bby|\blimit|\boffset|,)\s*['"%(]*$/i;
const RAW_SQL_CALLS = new Set(["query", "execute", "raw", "unsafe", "$queryRawUnsafe", "$executeRawUnsafe", "queryRawUnsafe", "executeRawUnsafe", "exec", "all", "get", "run", "each", "prepare", "queryRaw", "whereRaw", "havingRaw", "orderByRaw", "selectRaw", "joinRaw", "fromRaw", "literal", "sql"]);
const WHERE_CALLS = new Set(["where", "andWhere", "orWhere", "having"]);

/** Is `e` SQL text with a request-input piece in it? One step through a local name is followed. */
function sqlWithInput(ts: Ts, e: TS.Expression, t: Taint, whereOnly = false): boolean {
  let x = bare(ts, e);
  if (ts.isIdentifier(x)) { const v = t.valueOf(x.text); if (!v) return false; x = bare(ts, v); }
  if (!ts.isTemplateExpression(x) && !(ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken)) return false;
  const fixed = fixedParts(ts, x);
  if (fixed === null) return false;
  const text = fixed.replace(/\u0000/g, " ? ");
  if (whereOnly ? !/[=<>]|\blike\b|\bin\s*\(/i.test(text) : !SQL_WORDS.test(text)) return false;
  if (!movingParts(ts, x).some((p) => t.is(p))) return false;
  // the tainted piece sits where a VALUE goes (after =, LIKE, IN (, VALUES (, a comma), or anywhere in a full statement
  if (ts.isTemplateExpression(x)) {
    let before = x.head.text;
    for (const s of x.templateSpans) { if (t.is(s.expression) && (SQL_PIECE.test(before) || SQL_WORDS.test(text))) return true; before = s.literal.text; }
    return false;
  }
  return true;
}

const MONGO_CALLS = new Set(["find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "findOneAndRemove", "updateOne", "updateMany", "update", "deleteOne", "deleteMany", "remove", "replaceOne", "countDocuments", "count", "exists", "distinct"]);
const MONGO_MODULES = ["mongodb", "mongoose", "monk", "mongojs", "marsdb", "nedb", "@seald-io/nedb", "nedb-promises", "@typegoose/typegoose", "mongoist", "tingodb"];

/**
 * Can this value be an OBJECT the caller chose? Only what is read from the request body or the query string can
 * (JSON, or ?a[$ne]=1); route parameters, headers and cookies are always text. One or two local names are followed.
 */
function objectFromRequest(ts: Ts, e: TS.Expression, t: Taint, depth = 0): boolean {
  const x = bare(ts, e);
  if (ts.isIdentifier(x)) {
    if (!t.is(x) || depth > 2) return false;
    const o = t.originOf(x.text);
    return !!o && objectFromRequest(ts, o, t, depth + 1);
  }
  if (ts.isCallExpression(x)) {
    const full = dotted(ts, x.expression) ?? "";
    if (full === "JSON.parse") return !!x.arguments[0] && t.is(x.arguments[0]);
    return /\.json$/.test(full) && t.is(x);
  }
  if (ts.isPropertyAccessExpression(x) || ts.isElementAccessExpression(x)) {
    if (!t.is(x)) return false;
    let root: TS.Expression = x;
    const names: string[] = [];
    while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) { if (ts.isPropertyAccessExpression(root)) names.push(root.name.text); root = bare(ts, root.expression); }
    if (names.includes("body") || names.includes("query")) return true;
    return depth <= 2 && (ts.isIdentifier(root) || ts.isCallExpression(root)) && objectFromRequest(ts, root, t, depth + 1);
  }
  return false;
}

const SHELLS = /^(?:sh|bash|zsh|dash|ksh|cmd|cmd\.exe|powershell|pwsh|\/bin\/(?:ba|z|da)?sh)$/i;
const TEMPLATE_ENGINES: Readonly<Record<string, readonly string[]>> = {
  ejs: ["render", "compile"], pug: ["render", "compile"], jade: ["render", "compile"], handlebars: ["compile", "precompile"], hbs: ["compile"],
  nunjucks: ["renderString", "compile"], dot: ["template", "compile"], eta: ["renderString", "render", "compile"], squirrelly: ["render", "compile"],
  lodash: ["template"], "lodash.template": ["default"], underscore: ["template"], mustache: [], marko: [],
};
const SAME_SITE_CHECK = /startsWith\(\s*["'`]\/["'`]\s*\)|startsWith\(\s*["'`]\/\/["'`]|\.origin\s*[!=]==?|\.host(?:name)?\s*[!=]==?|\b(?:allow\w*|safe\w*|isSafe\w*|isValid\w*|isInternal\w*|isRelative\w*|isLocal\w*|sameOrigin\w*|validate\w*|whitelist\w*|trusted\w*)\s*[(.[]|\b(?:ALLOWED|SAFE|TRUSTED|WHITELIST)\w*\b|\.includes\(|\.has\(|\.indexOf\(/i;
const HOST_CHECK = /\.(?:hostname|host|origin|protocol)\b[\s\S]{0,80}(?:===?|!==?|includes|has\(|endsWith|startsWith|in\s|test\()|\b(?:allow\w*|ALLOWED\w*|isAllowed\w*|isSafe\w*|assertSafe\w*|validate\w*|ssrf\w*|isPrivate\w*|isPublic\w*|guarded\w*|whitelist\w*|trusted\w*|blocklist\w*|denylist\w*)\b|\.includes\(|\.has\(/i;
const FETCH_MODULES = ["axios", "got", "needle", "request", "request-promise", "request-promise-native", "superagent", "node-fetch", "undici", "ky", "cross-fetch", "http", "https", "phin", "bent"];
const FETCH_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "request", "fetch", "stream", "default"]);

export function injectionFindings(ts: Ts, f: R2File, sf: TS.SourceFile, facts: ProjectFacts): R2Finding[] {
  const out: R2Finding[] = [];
  const imp: Imports = importsOf(ts, sf);
  const client = /^\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/\s*)*["']use client["']/.test(f.content);
  const usesMongo = facts.mongo || MONGO_MODULES.some((m) => imp.modules.has(m));
  const add = (rule: string, n: TS.Node, sink: string, extra: Record<string, string> = {}) =>
    out.push(finding(rule, f, lineOfNode(sf, n), { sink, input: "request", ...extra }, { snippet: shortText(n.getText(sf)) }));
  const tOf = (n: TS.Node, browser = false): Taint => taintAt(ts, sf, n, { browser });

  walk(ts, sf, (n) => {
    // ── XSS: JSX and DOM assignments ──
    if (ts.isJsxAttribute(n) && ts.isIdentifier(n.name) && n.name.text === "dangerouslySetInnerHTML" && n.initializer && ts.isJsxExpression(n.initializer) && n.initializer.expression) {
      const html = prop(ts, bare(ts, n.initializer.expression), "__html");
      if (html && tOf(n, true).is(html)) add("inside.code_xss_sink", n, "dangerouslySetInnerHTML");
      return;
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left)) {
      const name = n.left.name.text;
      if ((name === "innerHTML" || name === "outerHTML") && tOf(n, true).is(n.right)) add("inside.code_xss_sink", n, name);
      const target = dotted(ts, n.left);
      if (target && /^(?:window\.|document\.|self\.)?location(?:\.href)?$/.test(target)) {
        const t = tOf(n, true);
        if (taintedStart(ts, n.right, t) && !SAME_SITE_CHECK.test(handlerText(ts, sf, n))) add("inside.code_open_redirect", n, "location");
      }
      return;
    }
    if (ts.isNewExpression(n)) {
      if (ts.isIdentifier(n.expression) && n.expression.text === "Function" && n.arguments?.length) {
        const t = tOf(n);
        if (n.arguments.some((a) => t.is(a))) add("inside.code_eval_input", n, "new Function");
      }
      if (callsModule(ts, imp, n, ["vm"], ["Script"]) && n.arguments?.[0] && tOf(n).is(n.arguments[0])) add("inside.code_eval_input", n, "vm.Script");
      return;
    }
    if (!ts.isCallExpression(n)) return;
    const name = calleeName(ts, n);
    const recv = receiverOf(ts, n);
    const a0 = n.arguments[0], a1 = n.arguments[1];
    if (!name || !a0) return;

    // ── SQL ──
    if (RAW_SQL_CALLS.has(name) || WHERE_CALLS.has(name)) {
      const t = tOf(n);
      if (t.hasRequest && (sqlWithInput(ts, a0, t, WHERE_CALLS.has(name)) || (a1 && !WHERE_CALLS.has(name) && name === "query" && sqlWithInput(ts, a1, t)))) { add("inside.code_sql_injection", n, name); return; }
    }

    // ── NoSQL ──
    if (MONGO_CALLS.has(name) && usesMongo && !facts.mongoSanitized && ts.isPropertyAccessExpression(n.expression)) {
      const t = tOf(n);
      if (t.hasRequest) {
        const filter = bare(ts, a0);
        const guarded = /typeof\s+[^;\n]{1,80}[!=]==?\s*["'`](?:string|number)["'`]|\bString\s*\(\s*(?:req|request|ctx)\b|\b(?:body|query)\b[\w.[\]"'`]*\.toString\s*\(|ObjectId\s*\(|isValidObjectId|sanitize\w*\s*\(/.test(handlerText(ts, sf, n));
        if (ts.isObjectLiteralExpression(filter) && !prop(ts, filter, "where")) {
          const where$ = prop(ts, filter, "$where");
          if (where$ && t.is(where$)) { add("inside.code_nosql_injection", n, `${name} $where`); return; }
          const direct = filter.properties.find((p) => (ts.isPropertyAssignment(p) && objectFromRequest(ts, p.initializer, t)) || (ts.isShorthandPropertyAssignment(p) && objectFromRequest(ts, p.name, t)));
          if (direct && !guarded) { add("inside.code_nosql_injection", n, name, { field: shortText(direct.name?.getText(sf) ?? "", 40) }); return; }
        } else if (ts.isPropertyAccessExpression(filter) && /^(?:req|request|ctx\.request)\.(?:body|query)$/.test(dotted(ts, filter) ?? "") && t.is(filter) && !guarded) {
          add("inside.code_nosql_injection", n, `${name} (whole filter)`); return;
        }
      }
    }

    // ── command execution ──
    if (callsModule(ts, imp, n, ["child_process"], ["exec", "execSync"]) || (callsModule(ts, imp, n, ["shelljs"], ["exec"])) || callsModule(ts, imp, n, ["execa"], ["command", "commandSync", "execaCommand", "execaCommandSync"])) {
      if (tOf(n).is(a0)) { add("inside.code_command_injection", n, name); return; }
    }
    if (callsModule(ts, imp, n, ["child_process"], ["spawn", "spawnSync", "execFile", "execFileSync"])) {
      const t = tOf(n);
      const opts = n.arguments.find((a) => ts.isObjectLiteralExpression(a));
      const shellOn = !!opts && (isTrue(ts, prop(ts, opts, "shell")) || strLit(ts, prop(ts, opts, "shell")) !== null);
      const argv = a1 && ts.isArrayLiteralExpression(a1) ? a1.elements : [];
      const dashC = SHELLS.test(strLit(ts, a0) ?? "") && argv.length >= 2 && /^(?:-c|\/c|-Command)$/i.test(strLit(ts, argv[0]) ?? "") && argv.slice(1).some((x) => t.is(x));
      if (dashC || (shellOn && (t.is(a0) || argv.some((x) => t.is(x)) || (!!a1 && !ts.isArrayLiteralExpression(a1) && !ts.isObjectLiteralExpression(a1) && t.is(a1))))) { add("inside.code_command_injection", n, dashC ? `${name} sh -c` : `${name} shell: true`); return; }
    }

    // ── template engines: request input as the template itself ──
    for (const [mod, methods] of Object.entries(TEMPLATE_ENGINES)) {
      if (!methods.length) continue;
      const byImport = callsModule(ts, imp, n, [mod], methods);
      const byName = new RegExp(`^(?:${mod}|${mod[0]!.toUpperCase()}${mod.slice(1)})$`).test(recv) && methods.includes(name) && imp.modules.has(mod);
      const lodash = (mod === "lodash" || mod === "underscore") && recv === "_" && name === "template" && (imp.modules.has(mod) || imp.ns.get("_") === mod);
      if ((byImport || byName || lodash) && tOf(n).is(a0)) { add("inside.code_template_injection", n, `${mod} ${name}`); return; }
    }

    // ── eval ──
    if (ts.isIdentifier(n.expression) && name === "eval" && tOf(n).is(a0)) { add("inside.code_eval_input", n, "eval"); return; }
    if (callsModule(ts, imp, n, ["vm"], ["runInNewContext", "runInContext", "runInThisContext", "compileFunction"]) && tOf(n).is(a0)) { add("inside.code_eval_input", n, `vm.${name}`); return; }
    if (ts.isIdentifier(n.expression) && (name === "setTimeout" || name === "setInterval") && !ts.isArrowFunction(a0) && !ts.isFunctionExpression(a0) && !ts.isIdentifier(bare(ts, a0)) && tOf(n).is(a0)) { add("inside.code_eval_input", n, name); return; }

    // ── XSS: DOM calls and HTML answers ──
    if ((name === "write" || name === "writeln") && /^(?:window\.)?document$/.test(recv) && n.arguments.some((a) => tOf(n, true).is(a))) { add("inside.code_xss_sink", n, "document.write"); return; }
    if (name === "insertAdjacentHTML" && a1 && tOf(n, true).is(a1)) { add("inside.code_xss_sink", n, "insertAdjacentHTML"); return; }
    if ((name === "send" || name === "end" || name === "write" || name === "html") && /^(?:res|response|reply|c|ctx)$/.test(recv)) {
      const t = tOf(n);
      let body = bare(ts, a0);
      if (ts.isIdentifier(body)) { const v = t.valueOf(body.text); if (v) body = bare(ts, v); }
      const fixed = fixedParts(ts, body);
      if (fixed !== null && /<\/?[a-z][a-z0-9]*[\s>/]/i.test(fixed) && movingParts(ts, body).some((p) => t.is(p))) { add("inside.code_xss_sink", n, `${recv}.${name}`); return; }
    }

    // ── redirects ──
    const isRedirect = (name === "redirect" && (/^(?:res|response|reply|ctx|c|NextResponse|Response)$/.test(recv) || (!recv && (imp.named.has("redirect") || imp.modules.has("next/navigation")))))
      || (name === "permanentRedirect" && !recv) || ((name === "assign" || name === "replace") && /^(?:window\.|document\.)?location$/.test(recv));
    if (isRedirect) {
      const target = n.arguments.length >= 2 && (ts.isNumericLiteral(a0) || /^(?:30[1-8]|\w*status\w*)$/i.test(a0.getText(sf))) ? a1! : a0;
      const t = tOf(n, true);
      if (taintedStart(ts, target, t) && !SAME_SITE_CHECK.test(handlerText(ts, sf, n))) { add("inside.code_open_redirect", n, recv ? `${recv}.${name}` : name); return; }
    }

    // ── server fetches ──
    if (!client) {
      const plainFetch = ts.isIdentifier(n.expression) && (name === "fetch" || name === "$fetch" || name === "ofetch");
      const lib = callsModule(ts, imp, n, FETCH_MODULES, [...FETCH_METHODS]) || (FETCH_MODULES.includes(imp.ns.get(recv) ?? "") && FETCH_METHODS.has(name));
      if (plainFetch || lib) {
        const t = tOf(n);
        if (t.hasRequest) {
          const first = bare(ts, a0);
          const urlArg = ts.isObjectLiteralExpression(first) ? (prop(ts, first, "url") ?? prop(ts, first, "uri") ?? prop(ts, first, "href")) : (strLit(ts, first) !== null && a1 && /^(?:needle|request)$/.test(imp.ns.get(name) ?? imp.ns.get(recv) ?? "") ? a1 : first);
          if (urlArg && taintedStart(ts, urlArg, t) && !HOST_CHECK.test(handlerText(ts, sf, n))) add("inside.code_ssrf", n, recv ? `${recv}.${name}` : name);
        }
      }
    }
  });
  return out;
}

// ── Python ───────────────────────────────────────────────────────────────────────────────────────────────────────
const PY_BUILT = /(?:^|[^\w])[fF][rR]?["']|["']\s*%\s*[\w(]|["']\s*\+|\+\s*["']|\.format\s*\(/;
const PY_REDIRECT_GUARD = /url_has_allowed_host_and_scheme|is_safe_url|urlparse\s*\(|urlsplit\s*\(|\.netloc\b|\.startswith\s*\(\s*["']\/["']|ALLOWED|allowed_|whitelist|safe_/i;
const PY_HOST_GUARD = /urlparse\s*\(|urlsplit\s*\(|\.hostname\b|\.netloc\b|ALLOWED|allowed_|whitelist|is_private|ipaddress\.|ssrf/i;

export function pyInjectionFindings(f: R2File): R2Finding[] {
  if (!isPython(f.path)) return [];
  const code = pyCode(f.content);
  const out: R2Finding[] = [];
  const add = (rule: string, line: number, sink: string) => out.push(finding(rule, f, line, { sink, input: "request", language: "python" }, { snippet: shortText(f.content.split("\n")[line - 1] ?? "") }));

  for (const c of pyCalls(code, "[\\w.]*\\.(?:execute|executemany|executescript|raw)|text")) {
    const t = pyTaint(code, c.line);
    let sql = c.first;
    // one step through a local name: query = f"..." ; cursor.execute(query)
    if (/^[A-Za-z_]\w*$/.test(sql)) {
      const def = new RegExp(`^\\s*${sql}\\s*=(?!=)\\s*(.+)$`, "m").exec(t.text);
      if (!def) continue;
      sql = def[1]!;
    }
    if (!/\b(?:select|insert|update|delete)\b/i.test(sql) || !PY_BUILT.test(sql)) continue;
    if (t.is(sql)) add("inside.code_sql_injection", c.line, c.name.split(".").pop()!);
  }
  for (const c of pyCalls(code, "os\\.system|os\\.popen|commands\\.getoutput|subprocess\\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)")) {
    const shell = /^os\.|^commands\.|getoutput|getstatusoutput/.test(c.name) || /\bshell\s*=\s*True\b/.test(c.args);
    if (shell && pyTaint(code, c.line).is(c.first)) add("inside.code_command_injection", c.line, c.name);
  }
  for (const c of pyCalls(code, "render_template_string|(?:jinja2\\.)?Template|[\\w.]*\\.from_string")) {
    if (pyTaint(code, c.line).is(c.first)) add("inside.code_template_injection", c.line, c.name);
  }
  for (const c of pyCalls(code, "eval|exec")) {
    if (pyTaint(code, c.line).is(c.first)) add("inside.code_eval_input", c.line, c.name);
  }
  for (const c of pyCalls(code, "redirect|HttpResponseRedirect|RedirectResponse")) {
    const t = pyTaint(code, c.line);
    const first = c.first.replace(/^url\s*=\s*/, "");
    // the address must START with request input: "/next/" + x stays on this site
    if (/^\s*(?:[fF]?["']\/[\w-]|url_for\s*\()/.test(first)) continue;
    if (t.is(first) && !PY_REDIRECT_GUARD.test(t.text)) add("inside.code_open_redirect", c.line, c.name);
  }
  for (const c of pyCalls(code, "requests\\.(?:get|post|put|patch|delete|head|request)|httpx\\.(?:get|post|put|patch|delete|head|request|stream)|urllib\\.request\\.urlopen|urlopen|urllib2\\.urlopen")) {
    const t = pyTaint(code, c.line);
    const args = pyArgs(c.args);
    const url = (/\.request$/.test(c.name) ? args[1] : args[0]) ?? "";
    if (/^\s*[fF]?["']https?:\/\/[\w.-]+/.test(url)) continue;   // a fixed host
    if (t.is(url) && !PY_HOST_GUARD.test(t.text)) add("inside.code_ssrf", c.line, c.name);
  }
  return out;
}

/** What the whole project says about itself (read once, from the manifests and a word search). */
export function projectFacts(files: readonly R2File[]): ProjectFacts {
  let mongo = false, mongoSanitized = false, jsYamlMajor: number | null = null;
  for (const f of files) {
    if (/(?:^|\/)package\.json$/.test(f.path) && !/(?:^|\/)node_modules\//.test(f.path)) {
      if (new RegExp(`"(?:${MONGO_MODULES.map((m) => m.replace(/[/.]/g, "\\$&")).join("|")})"\\s*:`).test(f.content)) mongo = true;
      const y = /"js-yaml"\s*:\s*"[^\d"]*(\d+)\./.exec(f.content);
      if (y) jsYamlMajor = jsYamlMajor === null ? Number(y[1]) : Math.min(jsYamlMajor, Number(y[1]));
    }
    if (/(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/.test(f.path) && /\b(?:pymongo|mongoengine|motor)\b/i.test(f.content)) mongo = true;
    if (/mongo-sanitize|express-mongo-sanitize|mongoSanitize|sanitizeFilter\s*:\s*true|["']sanitizeFilter["']\s*,\s*true/.test(f.content)) mongoSanitized = true;
  }
  return { mongo, mongoSanitized, jsYamlMajor };
}
