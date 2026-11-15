/**
 * The syntax-tree toolkit of the JavaScript / TypeScript rules: parsing, imports, and yof's taint notion.
 *
 * TAINT, stated plainly: a value is "request input" when it is read from the request object IN THE SAME FUNCTION OR
 * HANDLER (or in a function that encloses it): req.query / body / params / headers / cookies, request.json(),
 * searchParams.get(), a Hono c.req, a Koa ctx.request, a Lambda event. It stays request input through a local
 * variable, a destructuring, a template literal, a + and a method called on it (x.trim()).
 * It STOPS being request input, on purpose, when it goes through any other function (validate(x), schema.parse(x),
 * Number(x), escape(x)), through .replace(), or into a comparison. A value that arrives as a function ARGUMENT from
 * another function, a value read from a database and anything that crosses a file are out of scope: no rule here
 * follows them, and the report says so.
 */
import type * as TS from "typescript";
import type { R2File, Ts } from "./types";

export const isScript = (p: string): boolean => /\.(?:[cm]?[jt]sx?)$/i.test(p) && !/\.d\.[cm]?ts$/i.test(p);
export const MAX_SCRIPT_BYTES = 400_000;

export function parseScript(ts: Ts, f: R2File): TS.SourceFile | null {
  if (!isScript(f.path) || f.content.length > MAX_SCRIPT_BYTES) return null;
  const p = f.path.toLowerCase();
  const kind = p.endsWith(".tsx") ? ts.ScriptKind.TSX : /\.[cm]?ts$/.test(p) ? ts.ScriptKind.TS : ts.ScriptKind.JSX;
  try { return ts.createSourceFile(f.path, f.content, ts.ScriptTarget.Latest, true, kind); } catch { return null; }
}

export const lineOfNode = (sf: TS.SourceFile, n: TS.Node): number => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;

export function walk(ts: Ts, root: TS.Node, visit: (n: TS.Node) => void): void {
  const go = (n: TS.Node): void => { visit(n); ts.forEachChild(n, go); };
  go(root);
}

/** A string literal's text ("x", 'x' or `x` with no ${}), or null. */
export function strLit(ts: Ts, n: TS.Node | undefined): string | null {
  if (!n) return null;
  return ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) ? n.text : null;
}

/** Strip parentheses, `as`, `!`, `satisfies` and `await`. */
export function bare(ts: Ts, n: TS.Expression): TS.Expression {
  let cur = n;
  for (;;) {
    if (ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur) || ts.isNonNullExpression(cur) || ts.isAwaitExpression(cur) || ts.isTypeAssertionExpression(cur)) cur = cur.expression;
    else if (ts.isSatisfiesExpression && ts.isSatisfiesExpression(cur)) cur = cur.expression;
    else return cur;
  }
}

/** "a.b.c" for a chain of plain property accesses (optional chaining included), or null. */
export function dotted(ts: Ts, n: TS.Node): string | null {
  if (ts.isIdentifier(n)) return n.text;
  if (n.kind === ts.SyntaxKind.ThisKeyword) return "this";
  if (ts.isPropertyAccessExpression(n)) { const l = dotted(ts, n.expression); return l ? `${l}.${n.name.text}` : null; }
  if (ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n) || ts.isAsExpression(n)) return dotted(ts, n.expression);
  return null;
}

/** The called name: "exec" for exec(), child.exec() and a.b.exec(); "" when it is not a name. */
export function calleeName(ts: Ts, call: TS.CallExpression | TS.NewExpression): string {
  const c = call.expression;
  if (ts.isIdentifier(c)) return c.text;
  if (ts.isPropertyAccessExpression(c)) return c.name.text;
  return "";
}
/** The receiver of a method call as dotted text ("child" in child.exec()), or "". */
export function receiverOf(ts: Ts, call: TS.CallExpression): string {
  const c = call.expression;
  return ts.isPropertyAccessExpression(c) ? dotted(ts, c.expression) ?? "" : "";
}

// ── imports ──────────────────────────────────────────────────────────────────────────────────────────────────────
export interface Imports {
  /** local name -> module ("cp" -> "child_process") for namespace, default and `require` bindings. */
  ns: Map<string, string>;
  /** local name -> [module, exported name] for named imports and destructured requires. */
  named: Map<string, readonly [string, string]>;
  /** every module the file imports or requires. */
  modules: Set<string>;
}
const modName = (s: string) => s.replace(/^node:/, "");

export function importsOf(ts: Ts, sf: TS.SourceFile): Imports {
  const out: Imports = { ns: new Map(), named: new Map(), modules: new Set() };
  walk(ts, sf, (n) => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const mod = modName(n.moduleSpecifier.text);
      out.modules.add(mod);
      const c = n.importClause;
      if (!c) return;
      if (c.name) out.ns.set(c.name.text, mod);
      if (c.namedBindings && ts.isNamespaceImport(c.namedBindings)) out.ns.set(c.namedBindings.name.text, mod);
      if (c.namedBindings && ts.isNamedImports(c.namedBindings)) for (const e of c.namedBindings.elements) out.named.set(e.name.text, [mod, (e.propertyName ?? e.name).text]);
      return;
    }
    if (ts.isVariableDeclaration(n) && n.initializer) {
      let init: TS.Expression = bare(ts, n.initializer);
      let member: string | null = null;
      if (ts.isPropertyAccessExpression(init)) { member = init.name.text; init = bare(ts, init.expression); }
      if (ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === "require") {
        const m = strLit(ts, init.arguments[0]);
        if (!m) return;
        const mod = modName(m);
        out.modules.add(mod);
        if (ts.isIdentifier(n.name)) { if (member) out.named.set(n.name.text, [mod, member]); else out.ns.set(n.name.text, mod); }
        else if (ts.isObjectBindingPattern(n.name) && !member) for (const e of n.name.elements) if (ts.isIdentifier(e.name)) out.named.set(e.name.text, [mod, e.propertyName && ts.isIdentifier(e.propertyName) ? e.propertyName.text : e.name.text]);
      }
    }
  });
  return out;
}

/** Is this call `name` of one of `modules` (child_process.exec, cp.exec, or an imported exec)? */
export function callsModule(ts: Ts, imp: Imports, call: TS.CallExpression | TS.NewExpression, modules: readonly string[], names: readonly string[]): boolean {
  const c = call.expression;
  if (ts.isIdentifier(c)) {
    const b = imp.named.get(c.text);
    if (b) return modules.includes(b[0]) && names.includes(b[1]);
    const ns = imp.ns.get(c.text);
    return !!ns && modules.includes(ns) && names.includes("default");
  }
  if (ts.isPropertyAccessExpression(c) && names.includes(c.name.text)) {
    const recv = bare(ts, c.expression);
    if (ts.isIdentifier(recv)) {
      const ns = imp.ns.get(recv.text);
      if (ns) return modules.includes(ns);
      const b = imp.named.get(recv.text);
      return !!b && modules.includes(b[0]);
    }
    // the module required and called in one expression: require(<module>).exec(...)
    if (ts.isCallExpression(recv) && ts.isIdentifier(recv.expression) && recv.expression.text === "require") { const m = strLit(ts, recv.arguments[0]); return !!m && modules.includes(modName(m)); }
  }
  return false;
}

// ── functions and taint ──────────────────────────────────────────────────────────────────────────────────────────
export type Fn = TS.FunctionDeclaration | TS.FunctionExpression | TS.ArrowFunction | TS.MethodDeclaration | TS.ConstructorDeclaration | TS.GetAccessorDeclaration | TS.SetAccessorDeclaration;
export function isFn(ts: Ts, n: TS.Node): n is Fn {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n);
}
export function enclosingFn(ts: Ts, n: TS.Node): Fn | null {
  for (let p = n.parent; p; p = p.parent) if (isFn(ts, p)) return p;
  return null;
}
/** The outermost function around a node (the handler a callback sits in), or null at top level. */
export function outermostFn(ts: Ts, n: TS.Node): Fn | null {
  let out: Fn | null = null;
  for (let p = n.parent; p; p = p.parent) if (isFn(ts, p)) out = p;
  return out;
}

const REQ_NAMES = new Set(["req", "request"]);
const REQ_PROPS = new Set(["query", "body", "params", "headers", "cookies", "url", "originalUrl", "path", "hostname", "nextUrl", "rawBody", "payload", "fields", "signedCookies"]);
const REQ_CALLS = new Set(["json", "formData", "text", "param", "get", "header", "query", "queries", "parseBody", "arrayBuffer", "blob", "input", "valid"]);
const CTX_NAMES = new Set(["ctx", "context", "c"]);
const EVENT_PROPS = new Set(["queryStringParameters", "pathParameters", "body", "headers", "multiValueQueryStringParameters", "rawQueryString", "rawPath"]);
/** Methods that give back something that is no longer the user's text (a number, a yes/no, a cleaned string). */
const KILL_METHODS = new Set(["replace", "replaceAll", "includes", "startsWith", "endsWith", "indexOf", "lastIndexOf", "test", "match", "matchAll", "search", "localeCompare", "has", "charCodeAt", "codePointAt", "every", "some", "findIndex", "equals"]);
const KILL_PROPS = new Set(["length", "size", "byteLength"]);
/** Global functions that pass their text through unchanged. */
const PASS_CALLS = new Set(["String", "decodeURIComponent", "decodeURI", "unescape", "atob", "Buffer.from", "JSON.parse", "structuredClone", "Object.assign", "Object.values"]);

export interface Taint {
  /** Is this expression request input, by the notion at the top of this file? */
  is(e: TS.Expression | undefined): boolean;
  /** The first declared value of a local name, for one-step lookups (const sql = `...`). */
  valueOf(name: string): TS.Expression | undefined;
  /** What a local name was read from: its own first value, or for a destructured name the value that was taken apart. */
  originOf(name: string): TS.Expression | undefined;
  /** Names of the request object's parameters seen in the enclosing functions. */
  hasRequest: boolean;
}

/** Is `e` a direct read of the request (no local names involved)? `params` = parameter names of the enclosing functions. */
function isSource(ts: Ts, e: TS.Expression, params: ReadonlySet<string>): boolean {
  const x = bare(ts, e);
  if (ts.isCallExpression(x)) {
    const c = x.expression;
    if (ts.isPropertyAccessExpression(c)) {
      const recv = dotted(ts, c.expression);
      const name = c.name.text;
      if (recv && REQ_NAMES.has(recv) && params.has(recv) && REQ_CALLS.has(name)) return true;
      // Hono: c.req.query("x"), c.req.param("id"), c.req.json(); Koa: ctx.request.get("x")
      if (recv && /^(?:c|ctx|context)\.(?:req|request)$/.test(recv) && params.has(recv.split(".")[0]!) && REQ_CALLS.has(name)) return true;
      // new URL(request.url).searchParams.get("x"), searchParams.get("x"), url.searchParams.getAll("x")
      if ((name === "get" || name === "getAll") && recv && /(?:^|\.)searchParams$/.test(recv)) return true;
      if ((name === "get" || name === "getAll") && ts.isPropertyAccessExpression(c.expression) && c.expression.name.text === "searchParams" && isSource(ts, c.expression.expression, params)) return true;
    }
    return false;
  }
  if (ts.isNewExpression(x) && ts.isIdentifier(x.expression) && x.expression.text === "URL" && x.arguments?.[0]) return isSource(ts, x.arguments[0], params);
  if (ts.isPropertyAccessExpression(x) || ts.isElementAccessExpression(x)) {
    const chain = dotted(ts, ts.isElementAccessExpression(x) ? x.expression : x);
    if (chain) {
      const parts = chain.split(".");
      const root = parts[0]!;
      if (REQ_NAMES.has(root) && params.has(root) && parts[1] && REQ_PROPS.has(parts[1])) return true;
      if (CTX_NAMES.has(root) && params.has(root)) {
        if ((parts[1] === "req" || parts[1] === "request") && parts[2] && REQ_PROPS.has(parts[2])) return true;
        if (root !== "c" && (parts[1] === "query" || parts[1] === "params") ) return true;
      }
      if (root === "event" && params.has(root) && parts[1] && EVENT_PROPS.has(parts[1])) return true;
      if (root === "searchParams" && parts.length >= 2) return true;
    }
    return isSource(ts, x.expression, params);
  }
  return false;
}

/** Reads of the page's own address and of messages from other windows (the browser's side of "request input"). */
export function isBrowserSource(ts: Ts, e: TS.Expression): boolean {
  const x = bare(ts, e);
  const chain = ts.isPropertyAccessExpression(x) ? dotted(ts, x) : null;
  if (chain && /^(?:window\.|document\.|globalThis\.|self\.)?location\.(?:search|hash|href|pathname)$/.test(chain)) return true;
  if (chain && /^(?:window\.)?document\.(?:referrer|URL|documentURI|cookie)$/.test(chain)) return true;
  if (chain && /^window\.name$/.test(chain)) return true;
  // new URLSearchParams(location.search), new URL(location.href)
  if (ts.isNewExpression(x) && ts.isIdentifier(x.expression) && (x.expression.text === "URLSearchParams" || x.expression.text === "URL") && x.arguments?.[0]) return isBrowserSource(ts, x.arguments[0]);
  if (ts.isCallExpression(x) && ts.isPropertyAccessExpression(x.expression)) {
    const name = x.expression.name.text;
    const inner = bare(ts, x.expression.expression);
    if ((name === "get" || name === "getAll") && ts.isNewExpression(inner) && ts.isIdentifier(inner.expression) && inner.expression.text === "URLSearchParams") return true;
    if ((name === "get" || name === "getAll") && ts.isCallExpression(inner) && ts.isIdentifier(inner.expression) && inner.expression.text === "useSearchParams") return true;
  }
  if (ts.isPropertyAccessExpression(x) || ts.isElementAccessExpression(x) || ts.isCallExpression(x)) {
    const next = ts.isCallExpression(x) ? (ts.isPropertyAccessExpression(x.expression) && !KILL_METHODS.has(x.expression.name.text) ? x.expression.expression : null) : x.expression;
    if (ts.isPropertyAccessExpression(x) && KILL_PROPS.has(x.name.text)) return false;
    return next ? isBrowserSource(ts, next) : false;
  }
  return false;
}

const taintCache = new WeakMap<TS.Node, Taint>();

/** The taint view at a node: the request parameters and tainted locals of every function around it. */
export function taintAt(ts: Ts, sf: TS.SourceFile, at: TS.Node, opts: { browser?: boolean } = {}): Taint {
  const chain: Fn[] = [];
  for (let p: TS.Node | undefined = at; p; p = p.parent) if (isFn(ts, p)) chain.unshift(p);
  const scope: TS.Node = chain[0] ?? sf;
  const key = chain[chain.length - 1] ?? sf;
  const cached = opts.browser ? undefined : taintCache.get(key);
  if (cached) return cached;

  const params = new Set<string>();
  const tainted = new Set<string>();
  const values = new Map<string, TS.Expression>();
  const origins = new Map<string, TS.Expression>();
  for (const fn of chain) {
    for (const p of fn.parameters) {
      if (ts.isIdentifier(p.name)) params.add(p.name.text);
      // ({ searchParams }) and ({ query, body }: Request-like) of a handler: only the well-known searchParams name
      else if (ts.isObjectBindingPattern(p.name)) for (const el of p.name.elements) if (ts.isIdentifier(el.name) && el.name.text === "searchParams") tainted.add("searchParams");
    }
  }
  const inChain = new Set<TS.Node>(chain);

  const is = (e: TS.Expression | undefined): boolean => {
    if (!e) return false;
    const x = bare(ts, e);
    if (ts.isIdentifier(x)) return tainted.has(x.text);
    if (isSource(ts, x, params)) return true;
    if (opts.browser && isBrowserSource(ts, x)) return true;
    if (ts.isTemplateExpression(x)) return x.templateSpans.some((s) => is(s.expression));
    if (ts.isBinaryExpression(x)) {
      const op = x.operatorToken.kind;
      if (op === ts.SyntaxKind.PlusToken || op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken) return is(x.left) || is(x.right);
      return false;
    }
    if (ts.isConditionalExpression(x)) return is(x.whenTrue) || is(x.whenFalse);
    if (ts.isPropertyAccessExpression(x)) return !KILL_PROPS.has(x.name.text) && is(x.expression);
    if (ts.isElementAccessExpression(x)) return is(x.expression);
    if (ts.isSpreadElement(x)) return is(x.expression);
    if (ts.isCallExpression(x)) {
      if (ts.isPropertyAccessExpression(x.expression)) {
        const full = dotted(ts, x.expression);
        if (full && PASS_CALLS.has(full)) return x.arguments.some((a) => is(a));
        return !KILL_METHODS.has(x.expression.name.text) && is(x.expression.expression);
      }
      if (ts.isIdentifier(x.expression) && PASS_CALLS.has(x.expression.text)) return x.arguments.some((a) => is(a));
      return false;   // any other function: out of scope on purpose
    }
    if (ts.isNewExpression(x) && ts.isIdentifier(x.expression) && x.expression.text === "URL") return is(x.arguments?.[0]);
    return false;
  };

  const bind = (name: TS.BindingName, init: TS.Expression | undefined): void => {
    if (ts.isIdentifier(name)) {
      if (init && !values.has(name.text)) values.set(name.text, init);
      if (is(init)) tainted.add(name.text);
      return;
    }
    if (!is(init)) return;
    for (const el of name.elements) {
      if (ts.isOmittedExpression(el)) continue;
      if (ts.isIdentifier(el.name)) { tainted.add(el.name.text); if (init && !origins.has(el.name.text)) origins.set(el.name.text, init); }
      else bind(el.name, init);
    }
  };
  // one pass in source order over the functions of the chain (nested functions that are not in the chain are other
  // handlers: their locals are not ours)
  const scan = (n: TS.Node): void => {
    if (isFn(ts, n) && n !== scope && !inChain.has(n)) return;
    if (ts.isVariableDeclaration(n)) bind(n.name, n.initializer);
    else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && is(n.right)) tainted.add(n.left.text);
    ts.forEachChild(n, scan);
  };
  // module-level statements too: a browser script often has no function around it
  scan(sf);

  const out: Taint = { is, valueOf: (name) => values.get(name), originOf: (name) => values.get(name) ?? origins.get(name), hasRequest: [...params].some((p) => REQ_NAMES.has(p) || CTX_NAMES.has(p) || p === "event") || tainted.has("searchParams") };
  if (!opts.browser) taintCache.set(key, out);
  return out;
}

/** The literal text of a string being built: the fixed parts of a template or of a + chain, joined by "\u0000". */
export function fixedParts(ts: Ts, e: TS.Expression): string | null {
  const x = bare(ts, e);
  if (ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x)) return x.text;
  if (ts.isTemplateExpression(x)) return [x.head.text, ...x.templateSpans.map((s) => s.literal.text)].join("\u0000");
  if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = fixedParts(ts, x.left), r = fixedParts(ts, x.right);
    if (l === null && r === null) return null;
    return `${l ?? ""}\u0000${r ?? ""}`;
  }
  return null;
}

/** The moving parts of a string being built (template spans, the non-literal sides of a +). */
export function movingParts(ts: Ts, e: TS.Expression): TS.Expression[] {
  const x = bare(ts, e);
  if (ts.isTemplateExpression(x)) return x.templateSpans.map((s) => s.expression);
  if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken) return [...movingParts(ts, x.left), ...movingParts(ts, x.right)];
  if (ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x)) return [];
  return [x];
}

/** Does request input decide where the text STARTS (the host of a URL)? "/x/" + q and a fixed host followed by ${q} do not. */
export function taintedStart(ts: Ts, e: TS.Expression, t: Taint): boolean {
  const x = bare(ts, e);
  if (ts.isTemplateExpression(x)) return x.head.text === "" && !!x.templateSpans[0] && t.is(x.templateSpans[0].expression);
  if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken) return taintedStart(ts, x.left, t);
  if (ts.isNewExpression(x) && ts.isIdentifier(x.expression) && x.expression.text === "URL" && x.arguments?.[0]) return taintedStart(ts, x.arguments[0], t);
  if (ts.isIdentifier(x)) { const v = t.valueOf(x.text); if (v && (ts.isTemplateExpression(bare(ts, v)) || ts.isBinaryExpression(bare(ts, v)))) return taintedStart(ts, v, t); }
  return t.is(x);
}

/** The text of the outermost function around a node (comments included), for "is there a check nearby" guards. */
export function handlerText(ts: Ts, sf: TS.SourceFile, n: TS.Node): string {
  const fn = outermostFn(ts, n);
  return fn ? fn.getText(sf) : "";
}

/** The name a value is being given: `const token = ...`, `{ token: ... }`, `x.token = ...`, or the function it is returned from. */
export function targetName(ts: Ts, n: TS.Node): string {
  for (let p = n.parent, child: TS.Node = n; p; child = p, p = p.parent) {
    if (ts.isVariableDeclaration(p) && p.initializer === child && ts.isIdentifier(p.name)) return p.name.text;
    if (ts.isPropertyAssignment(p) && p.initializer === child) return ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) ? p.name.text : "";
    if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.right === child) return dotted(ts, p.left)?.split(".").pop() ?? "";
    if (isFn(ts, p)) {
      if ((ts.isFunctionDeclaration(p) || ts.isMethodDeclaration(p)) && p.name && ts.isIdentifier(p.name)) return p.name.text;
      const gp = p.parent;
      if (gp && ts.isVariableDeclaration(gp) && ts.isIdentifier(gp.name)) return gp.name.text;
      if (gp && ts.isPropertyAssignment(gp) && ts.isIdentifier(gp.name)) return gp.name.text;
      // an unnamed callback (.map(() => ...)): keep climbing to what its result is given to
    }
  }
  return "";
}

/** One object literal property by name, or undefined. */
export function prop(ts: Ts, obj: TS.Node | undefined, name: string): TS.Expression | undefined {
  if (!obj || !ts.isObjectLiteralExpression(obj)) return undefined;
  for (const p of obj.properties) {
    if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && p.name.text === name) return p.initializer;
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === name) return p.name;
  }
  return undefined;
}
export const isTrue = (ts: Ts, n: TS.Node | undefined): boolean => !!n && n.kind === ts.SyntaxKind.TrueKeyword;
export const isFalse = (ts: Ts, n: TS.Node | undefined): boolean => !!n && n.kind === ts.SyntaxKind.FalseKeyword;
