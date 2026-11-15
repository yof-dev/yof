/**
 * Family 4, weak cryptography.
 *
 *   inside.crypto_weak_hash      MD5 or SHA-1 over a value named like a password, token, secret or session; or a
 *                                fast hash (SHA-2, SHA-3, RIPEMD, BLAKE2) over a password with no salt in the call
 *                                and no slow hash (bcrypt, scrypt, argon2, pbkdf2) in the function.
 *                                A checksum, a cache key, an ETag or a Gravatar hash is never flagged. needs_validation.
 *   inside.crypto_math_random    Math.random() (Python: the random module) giving a value whose NAME says token,
 *                                session id, reset code, one-time code, password, secret, nonce, salt or API key.
 *                                needs_validation.
 *   inside.crypto_hardcoded_key  a text literal used as the key or IV of a cipher, the key of an HMAC or the secret
 *                                of a JWT (crypto.createCipheriv / createHmac, jsonwebtoken, jose, CryptoJS; Python:
 *                                AES.new, hmac.new, jwt.encode, Fernet). needs_validation (it may be a sample value).
 *   inside.crypto_ecb            a cipher asked for in ECB mode: the pattern alone is the defect. confirmed.
 *   inside.tls_verify_off        certificate checking switched off: rejectUnauthorized: false, strictSSL: false,
 *                                NODE_TLS_REJECT_UNAUTHORIZED=0 (code, .env, Dockerfile, scripts, YAML), Python
 *                                verify=False / CERT_NONE / _create_unverified_context, Go InsecureSkipVerify: true.
 *                                The pattern alone is the defect. confirmed.
 *   inside.code_jwt_unverified   a JWT accepted without a signature: the "none" algorithm allowed, verify called
 *                                with no key, PyJWT with verify_signature False or verify=False. confirmed.
 * GUARDS: tests, fixtures, examples and docs are not read; placeholders are not keys; a TLS switch inside a branch
 * that names development, local or test is skipped.
 * KNOWN RISKS of a false alarm: a database client that must accept a provider's self-signed certificate
 * (tls_verify_off is still true: the check IS off); a random value named "token" that guards nothing.
 */
import type * as TS from "typescript";
import { bare, calleeName, callsModule, dotted, handlerText, importsOf, isFalse, lineOfNode, receiverOf, strLit, targetName, taintAt, walk, type Imports } from "./ast";
import { isPython, pyCalls, pyCode } from "./py";
import { finding, isPlaceholderValue, lineOf, maskValue, maskedLine, nameWords, shortText, type R2File, type R2Finding, type Ts } from "./types";

/** The words of an expression: `req.body.newPassword + salt` gives req, body, new, password, salt. */
const wordsOf = (text: string): string[] => text.split(/[^A-Za-z0-9_$]+/).flatMap(nameWords);
const PASSWORD_WORDS = new Set(["password", "passwd", "pwd", "pass", "passphrase", "passcode"]);
const TOKEN_WORDS = new Set(["token", "tokens", "secret", "session", "otp", "apikey", "signature", "credential", "credentials", "reset"]);
const namesPassword = (text: string): boolean => wordsOf(text).some((w) => PASSWORD_WORDS.has(w));
const namesToken = (text: string): boolean => { const w = wordsOf(text); return w.some((x) => TOKEN_WORDS.has(x)) || /api_key/.test(w.join("_")); };
const BENIGN_HASH = /etag|checksum|cache|gravatar|fingerprint|integrity|avatar|filename|file_?hash|content_?hash/i;
const SLOW_HASH = /pbkdf2|scrypt|bcrypt|argon2/i;
const JWT_LIBS = ["jsonwebtoken", "jose", "express-jwt", "passport-jwt", "koa-jwt", "fast-jwt", "@fastify/jwt", "hono/jwt", "jwt-simple", "njwt"];
const FAST_HASH = /^(?:sha-?(?:224|256|384|512)|sha3-\d+|ripemd-?160|rmd160|blake2[bs]\d*|whirlpool|sha512-256)$/i;
const BROKEN_HASH = /^(?:md5|md4|sha-?1)$/i;

/** Does the name say the value protects something (a token, a session id, a reset code)? */
export function isTokenName(name: string): boolean {
  if (!name) return false;
  const w = nameWords(name);
  if (w.some((x) => /^(?:test|mock|fake|demo|example|sample|colou?r|delay|jitter|index|offset)$/.test(x))) return false;
  if (w.some((x) => /^(?:tokens?|secret|password|passwd|pwd|otp|nonce|salt|csrf|apikey|passcode|pin)$/.test(x))) return true;
  return /session_?id|\bsid\b|reset_?(?:code|token|key)|verif\w*_?code|auth_?code|invite_?code|api_?key|one_?time|magic_?link|access_?code|recovery_?code/i.test(w.join("_"));
}

function hashVerdict(alg: string, hashed: string, target: string, scope: string): string | null {
  const subject = `${hashed} ${target}`;
  if (BENIGN_HASH.test(subject)) return null;
  const pw = namesPassword(hashed);
  if (BROKEN_HASH.test(alg)) {
    if (pw || namesPassword(target)) return `${alg.toLowerCase()} for a password`;
    if (namesToken(subject)) return `${alg.toLowerCase()} for a token or secret`;
    return null;
  }
  if (FAST_HASH.test(alg) && pw && !/salt|pepper/i.test(hashed) && !SLOW_HASH.test(scope)) return `unsalted ${alg.toLowerCase()} for a password`;
  return null;
}

/** The text literal behind a key argument: "text", Buffer.from("text"), new TextEncoder().encode("text"), or a const holding one. */
function literalKey(ts: Ts, e: TS.Expression | undefined, consts: ReadonlyMap<string, string>): string | null {
  if (!e) return null;
  const x = bare(ts, e);
  const s = strLit(ts, x);
  if (s !== null) return s;
  if (ts.isIdentifier(x)) return consts.get(x.text) ?? null;
  if (ts.isCallExpression(x) && x.arguments[0]) {
    const full = dotted(ts, x.expression) ?? "";
    const method = ts.isPropertyAccessExpression(x.expression) ? x.expression.name.text : "";
    if (full === "Buffer.from" || method === "encode") return literalKey(ts, x.arguments[0], consts);
  }
  return null;
}
const realKey = (v: string | null, min = 8): v is string => !!v && v.length >= min && !isPlaceholderValue(v) && !/^(.)\1+$/.test(v);

export function cryptoFindings(ts: Ts, f: R2File, sf: TS.SourceFile): R2Finding[] {
  const out: R2Finding[] = [];
  const imp: Imports = importsOf(ts, sf);
  const consts = new Map<string, string>();
  for (const st of sf.statements) {
    if (!ts.isVariableStatement(st)) continue;
    for (const d of st.declarationList.declarations) { const v = d.initializer ? literalKey(ts, d.initializer, consts) : null; if (v !== null && ts.isIdentifier(d.name)) consts.set(d.name.text, v); }
  }
  const seenRandom = new Set<number>();
  const cryptoCall = (n: TS.CallExpression, names: string[]) => callsModule(ts, imp, n, ["crypto"], names) || (names.includes(calleeName(ts, n)) && /crypto/i.test(receiverOf(ts, n)));
  const keyHit = (n: TS.Node, what: string, value: string) =>
    out.push(finding("inside.crypto_hardcoded_key", f, lineOfNode(sf, n), { what, length: String(value.length) }, { key: `${what}|${maskValue(value)}`, masked: maskValue(value), snippet: maskedLine(shortText(n.getText(sf)), value) }));

  walk(ts, sf, (n) => {
    // ── TLS switched off ──
    if (ts.isPropertyAssignment(n) && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name))) {
      const k = n.name.text;
      if ((k === "rejectUnauthorized" || k === "strictSSL") && isFalse(ts, n.initializer) && !devOnly(ts, sf, n)) out.push(finding("inside.tls_verify_off", f, lineOfNode(sf, n), { what: `${k}: false` }));
      if (/^algorithms?$/.test(k) && JWT_LIBS.some((m) => imp.modules.has(m))) {
        const v = bare(ts, n.initializer);
        const list = ts.isArrayLiteralExpression(v) ? v.elements.map((e) => strLit(ts, e)) : [strLit(ts, v)];
        if (list.some((a) => a !== null && /^none$/i.test(a))) out.push(finding("inside.code_jwt_unverified", f, lineOfNode(sf, n), { what: 'the "none" algorithm is accepted' }));
      }
      return;
    }
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = ts.isElementAccessExpression(n.left) ? `${dotted(ts, n.left.expression) ?? ""}.${strLit(ts, n.left.argumentExpression) ?? ""}` : dotted(ts, n.left) ?? "";
      if (/(?:^|\.)process\.env\.NODE_TLS_REJECT_UNAUTHORIZED$/.test(left) && /^["'`]?0["'`]?$/.test(n.right.getText(sf)) && !devOnly(ts, sf, n)) out.push(finding("inside.tls_verify_off", f, lineOfNode(sf, n), { what: "NODE_TLS_REJECT_UNAUTHORIZED = 0" }));
      return;
    }
    if (ts.isPropertyAccessExpression(n) && dotted(ts, n) === "CryptoJS.mode.ECB") { out.push(finding("inside.crypto_ecb", f, lineOfNode(sf, n), { what: "CryptoJS.mode.ECB" })); return; }
    if (!ts.isCallExpression(n)) return;
    const name = calleeName(ts, n);
    const full = dotted(ts, n.expression) ?? "";
    const a0 = n.arguments[0], a1 = n.arguments[1], a2 = n.arguments[2];

    // ── Math.random for a secret value ──
    if (full === "Math.random") {
      const target = targetName(ts, n);
      const line = lineOfNode(sf, n);
      if (isTokenName(target) && !seenRandom.has(line)) { seenRandom.add(line); out.push(finding("inside.crypto_math_random", f, line, { name: target.slice(0, 60) })); }
      return;
    }

    // ── hashes ──
    if (name === "update" && a0 && ts.isPropertyAccessExpression(n.expression)) {
      let src = bare(ts, n.expression.expression);
      if (ts.isIdentifier(src)) { const v = taintAt(ts, sf, n).valueOf(src.text); if (v) src = bare(ts, v); }
      if (ts.isCallExpression(src) && calleeName(ts, src) === "createHash" && cryptoCall(src, ["createHash"])) {
        const alg = strLit(ts, src.arguments[0]) ?? "";
        const what = hashVerdict(alg, a0.getText(sf), targetName(ts, n), handlerText(ts, sf, n));
        if (what) out.push(finding("inside.crypto_weak_hash", f, lineOfNode(sf, n), { what, algorithm: alg.toLowerCase() }, { snippet: shortText(n.getText(sf)) }));
      }
      return;
    }
    const direct = /^(?:md5|sha1)$/i.test(name) && (callsModule(ts, imp, n, ["md5", "js-md5", "blueimp-md5", "sha1", "js-sha1", "crypto-js/md5", "crypto-js/sha1", "md5.js"], ["default", "md5", "sha1"])) ? name.toLowerCase()
      : /^CryptoJS\.(?:MD5|SHA1)$/.test(full) ? name.toLowerCase() : "";
    if (direct && a0) {
      const what = hashVerdict(direct, a0.getText(sf), targetName(ts, n), handlerText(ts, sf, n));
      if (what) out.push(finding("inside.crypto_weak_hash", f, lineOfNode(sf, n), { what, algorithm: direct }, { snippet: shortText(n.getText(sf)) }));
      return;
    }

    // ── ciphers: ECB, fixed keys and IVs ──
    if (/^create(?:Cipher|Decipher)(?:iv)?$/.test(name) && cryptoCall(n, [name])) {
      const alg = strLit(ts, a0) ?? "";
      if (/-ecb$/i.test(alg)) out.push(finding("inside.crypto_ecb", f, lineOfNode(sf, n), { what: alg.toLowerCase() }));
      const key = literalKey(ts, a1, consts), iv = literalKey(ts, a2, consts);
      if (realKey(key)) keyHit(n, "cipher key", key);
      else if (realKey(iv)) keyHit(n, "cipher IV", iv);
      return;
    }
    if (name === "createHmac" && cryptoCall(n, ["createHmac"])) { const k = literalKey(ts, a1, consts); if (realKey(k)) keyHit(n, "HMAC key", k); return; }
    if (/^CryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4)\.(?:en|de)crypt$/.test(full)) { const k = strLit(ts, a1 ? bare(ts, a1) : undefined); if (realKey(k)) keyHit(n, "cipher key", k); return; }
    if (/^CryptoJS\.Hmac\w+$/.test(full)) { const k = strLit(ts, a1 ? bare(ts, a1) : undefined); if (realKey(k)) keyHit(n, "HMAC key", k); return; }

    // ── JWT ──
    const jwtLib = callsModule(ts, imp, n, ["jsonwebtoken"], ["sign", "verify"]);
    if (jwtLib) {
      const k = literalKey(ts, a1, consts);
      if (realKey(k, 6)) keyHit(n, "JWT secret", k);
      if (name === "verify" && a1 && /^(?:null|undefined|false|""|''|``)$/.test(a1.getText(sf))) out.push(finding("inside.code_jwt_unverified", f, lineOfNode(sf, n), { what: "verify is called with no key" }));
      return;
    }
    if (imp.modules.has("jose") && (callsModule(ts, imp, n, ["jose"], ["jwtVerify"]) || name === "sign")) {
      const k = literalKey(ts, name === "sign" ? a0 : a1, consts);
      if (realKey(k)) keyHit(n, "JWT secret", k);
      return;
    }
    if (/^UnsecuredJWT\.decode$/.test(full) && imp.modules.has("jose")) out.push(finding("inside.code_jwt_unverified", f, lineOfNode(sf, n), { what: "an unsecured (unsigned) JWT is accepted" }));
  });
  return out;
}

/** Is this node inside a branch whose condition names development, local or test? */
function devOnly(ts: Ts, sf: TS.SourceFile, n: TS.Node): boolean {
  const DEV = /dev|local|test|debug|insecure|self_?signed|NODE_ENV\s*!==?\s*["'`]production["'`]/i;
  for (let p = n.parent, child: TS.Node = n; p; child = p, p = p.parent) {
    if (ts.isIfStatement(p) && p.thenStatement === child && DEV.test(p.expression.getText(sf))) return true;
    if (ts.isConditionalExpression(p) && p.whenTrue === child && DEV.test(p.condition.getText(sf))) return true;
    if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken && p.right === child && DEV.test(p.left.getText(sf))) return true;
    if (ts.isSourceFile(p)) break;
  }
  return false;
}

// ── other languages and config, by exact text forms ──────────────────────────────────────────────────────────────
const CODE_LINE_COMMENT = /^\s*(?:\/\/|#|\*|\/\*|--|;)/;
const TLS_ENV = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*(?:=|:)\s*["']?0["']?(?![\w.])/g;
const isEnvLike = (p: string) => /(?:^|\/)\.env(?:\.[\w.-]+)?$|(?:^|\/)(?:Dockerfile(?:\.[\w-]+)?|Containerfile|Procfile|Makefile)$|\.(?:sh|bash|zsh|ya?ml|toml|dockerfile)$|(?:^|\/)package\.json$/i.test(p);

export function textCryptoFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  const lines = f.content.split("\n");
  const at = (rule: string, index: number, meta: Record<string, string>) => {
    const line = lineOf(f.content, index);
    if (CODE_LINE_COMMENT.test(lines[line - 1] ?? "")) return;
    out.push(finding(rule, f, line, meta));
  };
  if (isEnvLike(f.path)) {
    TLS_ENV.lastIndex = 0;
    for (let m = TLS_ENV.exec(f.content); m; m = TLS_ENV.exec(f.content)) at("inside.tls_verify_off", m.index, { what: "NODE_TLS_REJECT_UNAUTHORIZED = 0" });
  }
  if (/\.go$/i.test(f.path)) for (const m of f.content.matchAll(/\bInsecureSkipVerify\s*:\s*true\b/g)) at("inside.tls_verify_off", m.index!, { what: "InsecureSkipVerify: true", language: "go" });
  if (/\.(?:java|kt)$/i.test(f.path)) for (const m of f.content.matchAll(/Cipher\.getInstance\(\s*"((?:AES|DES|DESede|Blowfish)(?:\/ECB\/[^"]*)?)"/g)) at("inside.crypto_ecb", m.index!, { what: m[1]!, language: /\.kt$/i.test(f.path) ? "kotlin" : "java" });
  if (/\.cs$/i.test(f.path)) for (const m of f.content.matchAll(/\bCipherMode\.ECB\b/g)) at("inside.crypto_ecb", m.index!, { what: "CipherMode.ECB", language: "csharp" });
  if (/\.(?:php|rb|go)$/i.test(f.path)) for (const m of f.content.matchAll(/["'](aes-(?:128|192|256)-ecb|des-ecb|des-ede3-ecb|bf-ecb)["']/gi)) at("inside.crypto_ecb", m.index!, { what: m[1]!.toLowerCase() });
  if (/\.php$/i.test(f.path)) for (const m of f.content.matchAll(/\b(md5|sha1)\s*\(\s*\$\w*(?:pass|pwd)\w*/gi)) at("inside.crypto_weak_hash", m.index!, { what: `${m[1]!.toLowerCase()} for a password`, algorithm: m[1]!.toLowerCase(), language: "php" });
  if (!isPython(f.path)) return out;

  const code = pyCode(f.content);
  const py = (rule: string, line: number, meta: Record<string, string>, extra: { key?: string; masked?: string; snippet?: string } = {}) => out.push(finding(rule, f, line, { ...meta, language: "python" }, extra));
  for (const m of code.matchAll(/\bMODE_ECB\b|\bmodes\.ECB\s*\(/g)) py("inside.crypto_ecb", lineOf(code, m.index!), { what: m[0].replace(/\s*\($/, "") });
  const httpLib = /^\s*(?:import|from)\s+[^\n]*\b(?:requests|httpx|urllib3|aiohttp)\b/m.test(code);
  for (const m of code.matchAll(/\bverify\s*=\s*False\b|\bverify_ssl\s*=\s*False\b|\bssl\._create_unverified_context\b|\bcert_reqs\s*=\s*(?:ssl\.CERT_NONE|["']CERT_NONE["'])|\bverify_mode\s*=\s*ssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b/g)) {
    const line = lineOf(code, m.index!);
    if (/^verify\s*=/.test(m[0])) {
      // verify=False means "no certificate check" only on an HTTP client call; on jwt.decode it means "no signature"
      const around = code.split("\n").slice(Math.max(0, line - 6), line).join("\n");
      if (/\bjwt\.decode\s*\(/.test(around)) continue;
      if (!httpLib) continue;
    }
    py("inside.tls_verify_off", line, { what: m[0].replace(/\s+/g, "") });
  }
  for (const c of pyCalls(code, "jwt\\.decode")) {
    const what = /["']verify_signature["']\s*:\s*False/.test(c.args) ? "verify_signature is False" : /\bverify\s*=\s*False\b/.test(c.args) ? "verify=False" : /algorithms\s*=\s*\[[^\]]*["']none["']/i.test(c.args) ? 'the "none" algorithm is accepted' : "";
    if (what) py("inside.code_jwt_unverified", c.line, { what });
  }
  for (const c of pyCalls(code, "hashlib\\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s)")) {
    if (/usedforsecurity\s*=\s*False/.test(c.args)) continue;
    const lineText = f.content.split("\n")[c.line - 1] ?? "";
    const target = /^\s*([A-Za-z_][\w.]*)\s*=(?!=)/.exec(lineText)?.[1] ?? "";
    const [a, b] = [Math.max(0, c.line - 12), c.line + 4];
    const what = hashVerdict(c.name.split(".")[1]!.replace(/^sha3_/, "sha3-"), c.first, target.split(".").pop() ?? "", code.split("\n").slice(a, b).join("\n"));
    if (what) py("inside.crypto_weak_hash", c.line, { what, algorithm: c.name.split(".")[1]! }, { snippet: shortText(lineText) });
  }
  if (/^\s*import\s+[^\n]*\brandom\b|^\s*from\s+random\s+import\b/m.test(code)) {
    for (const m of code.matchAll(/^[ \t]*([A-Za-z_][\w.]*)\s*=(?!=)[^\n]*(?<![\w.])(?:random\.(?:random|randint|choice|choices|randrange|getrandbits|sample)|randint|choice|choices)\s*\(/gm)) {
      if (/SystemRandom|secrets\./.test(m[0])) continue;
      const name = m[1]!.split(".").pop()!;
      if (isTokenName(name)) py("inside.crypto_math_random", lineOf(code, m.index!), { name: name.slice(0, 60) });
    }
  }
  for (const c of pyCalls(code, "AES\\.new|DES3?\\.new|Fernet|hmac\\.new|jwt\\.encode|jwt\\.decode")) {
    const args = c.args.split(",");
    const keyArg = (/^jwt\./.test(c.name) ? args[1] : args[0])?.trim() ?? "";
    const m = /^[bB]?(["'])((?:(?!\1)[^\\\n]){6,200})\1$/.exec(keyArg);
    if (!m || !realKey(m[2]!, /^jwt\./.test(c.name) ? 6 : 8)) continue;
    const what = /^jwt\./.test(c.name) ? "JWT secret" : c.name === "hmac.new" ? "HMAC key" : "cipher key";
    py("inside.crypto_hardcoded_key", c.line, { what, length: String(m[2]!.length) }, { key: `${what}|${maskValue(m[2]!)}`, masked: maskValue(m[2]!), snippet: maskedLine(f.content.split("\n")[c.line - 1] ?? "", m[2]!) });
  }
  return out;
}
