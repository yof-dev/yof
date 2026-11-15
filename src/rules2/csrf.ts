/**
 * Family 2, cross-site request forgery, the code side only (the live header and cookie test is the engagement
 * library's).
 *
 *   inside.code_csrf_missing  an Express-style app that signs people in with a COOKIE SESSION (express-session,
 *                             cookie-session) and has routes that change things (post, put, patch, delete), where
 *                             nothing yof read checks a CSRF token and no cookie setting says SameSite strict or lax.
 *                             One finding per session setup, with the routes counted. needs_validation.
 *   inside.code_cookie_flags  a sign-in cookie set in code without httpOnly or without SameSite (or with SameSite
 *                             "none"), or a session whose cookie options turn a protection off. A hardening note.
 *
 * GUARDS for code_csrf_missing, each one read across the WHOLE set of files (a check anywhere silences the rule,
 * because yof cannot tell which routes it covers): a CSRF library or token name (csurf, csrf-csrf, csrf-sync, lusca,
 * @fastify/csrf, hono/csrf, x-csrf-token, x-xsrf-token, _csrf, csrfToken); sameSite set to strict, lax or true; a
 * check of the Origin, Sec-Fetch-Site or X-Requested-With header; any sign of token sign-in (an Authorization
 * header read, passport-jwt, express-jwt, "Bearer"), because then the routes may not use the cookie at all.
 * Sign-in, sign-up, sign-out, webhook and callback routes are not counted.
 * KNOWN RISK of a false alarm: a check yof could not read (the run was capped) or one done by a proxy in front of
 * the app. Languages: JavaScript and TypeScript. Django and Rails check tokens by default and are not judged.
 */
import type * as TS from "typescript";
import { bare, calleeName, importsOf, isFalse, lineOfNode, prop, receiverOf, strLit, walk } from "./ast";
import { finding, shortText, type R2File, type R2Finding, type Ts } from "./types";

const CSRF_GUARD = /\bcsurf\b|csrf-csrf|csrf-sync|\blusca\b|@fastify\/csrf|tiny-csrf|hono\/csrf|csrf\s*\(|csrfProtection|doubleCsrf|x-csrf-token|x-xsrf-token|csrf[-_]?token|_csrf\b|\bxsrf|SameSite=(?:Strict|Lax)/i;
const SAMESITE_SET = /\bsameSite\s*:\s*(?:true|["'`](?:strict|lax)["'`])/i;
const ORIGIN_CHECK = /headers\.origin\b|headers\[\s*["'`]origin["'`]\s*\]|\.(?:get|header)\(\s*["'`]origin["'`]\s*\)|["'`]x-requested-with["'`]|sec-fetch-site/i;
const TOKEN_AUTH = /passport-jwt|express-jwt|express-oauth2-jwt-bearer|["'`]bearer["'`]|\bBearer\s|headers\.authorization\b|headers\[\s*["'`]authorization["'`]\s*\]|\.(?:get|header)\(\s*["'`]authorization["'`]\s*\)/i;
const NOT_COUNTED = /webhook|callback|log-?in|sign-?in|log-?out|sign-?out|register|sign-?up|csrf|health|oauth|token|\/auth\b/i;
const SESSION_MODULES = ["express-session", "cookie-session"];
const ROUTER = /^(?:app|router|server|api|routes?|\w*[Rr]outer|\w*[Aa]pp)$/;
const AUTH_COOKIE = /sess|(?:^|[_-])sid$|token|auth|jwt|login|remember|access|refresh/i;

export interface ParsedScript { f: R2File; sf: TS.SourceFile }

export function csrfFindings(ts: Ts, scripts: readonly ParsedScript[], all: readonly R2File[]): R2Finding[] {
  const out: R2Finding[] = [];
  const sessions: { f: R2File; line: number; lib: string; text: string }[] = [];
  const routes: { method: string; path: string; file: string }[] = [];

  for (const { f, sf } of scripts) {
    const imp = importsOf(ts, sf);
    const hasSessionLib = SESSION_MODULES.some((m) => imp.modules.has(m));
    walk(ts, sf, (n) => {
      if (!ts.isCallExpression(n)) return;
      const name = calleeName(ts, n);
      const recv = receiverOf(ts, n);
      const a0 = n.arguments[0];
      // the session setup: session({...}) / cookieSession({...}) from the two libraries
      if (hasSessionLib && ts.isIdentifier(n.expression) && SESSION_MODULES.includes(imp.ns.get(n.expression.text) ?? "")) {
        sessions.push({ f, line: lineOfNode(sf, n), lib: imp.ns.get(n.expression.text)!, text: shortText(n.getText(sf)) });
        const cookie = a0 && ts.isObjectLiteralExpression(a0) ? (prop(ts, a0, "cookie") ?? a0) : undefined;
        if (cookie && ts.isObjectLiteralExpression(cookie)) {
          const off: string[] = [];
          if (isFalse(ts, prop(ts, cookie, "httpOnly"))) off.push("httpOnly: false");
          if (/^none$/i.test(strLit(ts, prop(ts, cookie, "sameSite")) ?? "") || isFalse(ts, prop(ts, cookie, "sameSite"))) off.push("sameSite: none");
          if (isFalse(ts, prop(ts, cookie, "secure"))) off.push("secure: false");
          if (off.length) out.push(finding("inside.code_cookie_flags", f, lineOfNode(sf, cookie), { cookie: "session", missing: off.join(", ") }, { key: `session|${off.join(",")}` }));
        }
        return;
      }
      // routes that change things
      if (/^(?:post|put|patch|delete)$/.test(name) && ROUTER.test(recv) && a0) {
        const path = strLit(ts, a0);
        if (path && path.startsWith("/") && !NOT_COUNTED.test(path)) routes.push({ method: name.toUpperCase(), path, file: f.path });
        return;
      }
      // a sign-in cookie set by hand
      if ((name === "cookie" || name === "setCookie") && /^(?:res|response|reply)$/.test(recv) && a0) {
        const cookieName = strLit(ts, a0);
        // a CSRF token cookie is read by the page's own script on purpose (the double-submit pattern): not a sign-in cookie
        if (!cookieName || !AUTH_COOKIE.test(cookieName) || /csrf|xsrf/i.test(cookieName)) return;
        const opts = n.arguments[2] ? bare(ts, n.arguments[2]) : undefined;
        if (opts && (!ts.isObjectLiteralExpression(opts) || opts.properties.some((p) => ts.isSpreadAssignment(p)))) return;   // options yof cannot read exactly
        const missing: string[] = [];
        const http = opts && prop(ts, opts, "httpOnly");
        if (!http || isFalse(ts, http)) missing.push("httpOnly");
        const same = opts && prop(ts, opts, "sameSite");
        if (!same) missing.push("sameSite");
        else if (/^none$/i.test(strLit(ts, same) ?? "") || isFalse(ts, same)) missing.push("sameSite: none");
        if (missing.length) {
          out.push(finding("inside.code_cookie_flags", f, lineOfNode(sf, n), { cookie: cookieName.slice(0, 60), missing: missing.join(", ") }, { key: `${cookieName}|${missing.join(",")}` }));
        }
      }
    });
  }

  if (!sessions.length || !routes.length) return out;
  const guard = (re: RegExp) => all.some((f) => re.test(f.content));
  if (guard(CSRF_GUARD) || guard(SAMESITE_SET) || guard(ORIGIN_CHECK) || guard(TOKEN_AUTH)) return out;
  const first = routes[0]!;
  for (const s of sessions) {
    out.push(finding("inside.code_csrf_missing", s.f, s.line, {
      session: s.lib, routes: String(routes.length), first_route: `${first.method} ${first.path}`.slice(0, 120), first_route_file: first.file,
      looked_for: "a CSRF token check, SameSite strict or lax, an Origin check", live: "not_checked",
    }, { key: `session|${s.lib}`, snippet: s.text }));
  }
  return out;
}
