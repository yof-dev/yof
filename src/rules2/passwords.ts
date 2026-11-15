/**
 * Family 5, passwords in code and config. The existing rules catch known key shapes (inside.secret) and
 * random-looking values of 20+ characters (inside.secret_entropy). These three catch what is left: short and
 * human-made passwords. No value is ever returned: evidence is masked. Verdict: needs_validation, always (yof cannot
 * know that a literal is a live password).
 *
 *   inside.cred_password_literal  a text literal given to a name that says password / passwd / pwd / secret, in code
 *                                 (any common language) and in config (YAML, TOML, INI, properties, JSON).
 *   inside.cred_default_login     a well-known default pair close together: a user name such as admin, root or
 *                                 postgres with a password such as admin, password, 123456 or the user name itself.
 *   inside.cred_url_password      an address with the password inside it: scheme://user:password@host, for database
 *                                 addresses and for basic-auth addresses.
 *
 * GUARDS (each has a look-alike in the tests): placeholders and examples (changeme, your-password, <password>, ****,
 * ${VAR}); references to the environment or a secret store; empty values; values with a space (a label or a
 * sentence); a single plain word with no digit or symbol ("Password", "Passwort": a label); i18n and locale files;
 * names that talk ABOUT a password (passwordField, passwordPlaceholder, passwordMinLength, password_hash, resetPassword);
 * selectors and i18n keys ("#password", "auth.password"); tests, fixtures, examples and docs; values the entropy rule
 * already owns. For addresses: localhost and loopback, example.com, a one-word host with a default password (a
 * local compose service).
 * KNOWN RISKS of a false alarm: a sample password in a seed script outside a seeds/fixtures folder; a public demo login.
 */
import { ENV_REF, finding, isPlaceholderValue, isSecretName, lineOf, looksRandom, maskValue, maskedLine, skipPath, type R2File, type R2Finding } from "./types";

const CODE_EXT = /\.(?:[cm]?[jt]sx?|py|rb|go|php|java|kt|kts|cs|rs|swift|scala|vue|svelte|astro)$/i;
const CONFIG_EXT = /\.(?:ya?ml|toml|ini|cfg|conf|properties|json)$/i;
const I18N_PATH = /(?:^|\/)(?:locales?|i18n|l10n|lang|langs|languages|translations?|messages|intl|strings)\/|(?:^|\/|[._-])(?:i18n|l10n|locale|translations?|messages|strings)[._-]?[\w-]*\.(?:json|ya?ml|[cm]?[jt]s|properties)$|(?:^|\/)(?:en|de|fr|es|pt|it|nl|pl|ru|uk|ar|tr|ja|zh|ko|sv|da|no|nb|fi|cs|el|he|hi|id|th|vi|ro|hu|bg|hr|sk|sl|lt|lv|et|fa|ur|bn|ms|ca)(?:[-_][A-Za-z]{2,4})?\.(?:json|ya?ml)$/i;
const SKIP_FILES = /(?:^|\/)(?:package(?:-lock)?\.json|tsconfig[\w.-]*\.json|composer\.json|[\w.-]*lock[\w.-]*|\.eslintrc[\w.]*|openapi[\w.-]*\.(?:json|ya?ml)|swagger[\w.-]*\.(?:json|ya?ml)|[\w.-]*schema[\w.-]*\.json)$/i;
const OWN_RULES = /(?:^|\/)(?:docker-)?compose(?:[.\-][\w.-]+)?\.ya?ml$|^\.github\/|(?:^|\/)\.env(?:\.[\w.-]+)?$/i;

/** `name = "literal"` / `name: "literal"` / `"name": "literal"` / `name => "literal"`, the literal ending the value. */
const QUOTED = /(?:^|[\s,{(;[])(["']?)([A-Za-z_$][\w$.-]{0,60})\1\s*(?:=>|:=|:|(?<![=!<>+\-*/|&^%])=(?![=>~]))\s*(?:[A-Za-z_][\w.]*\s*\(\s*)?(["'`])((?:(?!\3)[^\\\n]){1,200})\3\s*\)?\s*(?=[,;)}\]]|$|\/\/|#)/gm;
const UNQUOTED = /^[ \t]*([A-Za-z_][\w.-]{0,60})[ \t]*[:=][ \t]*([^\s#"'`{[<|>&*!][^\s#]{0,199})[ \t]*(?:#.*)?$/gm;

/** Is this literal a plausible real password (not a label, a key, a selector or a placeholder)? */
export function plausiblePassword(v: string): boolean {
  if (v.length < 4 || v.length > 200 || /\s/.test(v)) return false;
  if (isPlaceholderValue(v) || ENV_REF.test(v)) return false;
  if (!/[0-9]/.test(v) && !/[^A-Za-z0-9]/.test(v)) return false;          // one plain word: a label
  if (/[^\x20-\x7e]/.test(v)) return false;                                // text in another script: a label
  if (/^[A-Za-z_]+(?:[.:/][A-Za-z_]+)+$/.test(v)) return false;            // an i18n key or a path of names
  if (/^[#.[]|^\w+\[|\]$/.test(v) && !/\d/.test(v)) return false;           // a selector
  if (/passw|secret|pwd/i.test(v) && /^[A-Za-z_\-.#[\]=]+$/.test(v)) return false;   // names the field itself
  if (/^(?:https?|file|data|mailto):/i.test(v) || /^\/[\w./-]+$/.test(v)) return false;   // an address or a path
  if (/^\d{1,3}$/.test(v) || /^(?:true|false|yes|no|on|off|null|none)$/i.test(v)) return false;
  if (/^[\w-]+\.(?:pem|key|crt|txt|json|ya?ml|env)$/i.test(v)) return false;   // a file name
  return true;
}

const USERS = new Set(["admin", "administrator", "root", "user", "test", "guest", "postgres", "mysql", "sa", "demo", "operator", "superuser", "support", "tomcat", "manager", "ubnt", "pi"]);
const WEAK = new Set(["admin", "password", "passw0rd", "p@ssw0rd", "123456", "12345678", "123456789", "1234", "12345", "root", "toor", "admin123", "admin1234", "pass", "pass123", "password1", "password123", "guest", "default", "secret", "letmein", "qwerty", "postgres", "mysql", "test", "test123", "changeit", "welcome", "welcome1", "raspberry", "ubnt", "tomcat", "manager", "demo"]);
const USER_KEY = /(?:^|[\s,{(;[])["']?([A-Za-z_$][\w$.-]{0,40})["']?\s*(?:=>|:=|:|=)\s*["'`]([^"'`\n]{1,40})["'`]/g;
const USER_KEY_PLAIN = /^[ \t]*([A-Za-z_][\w.-]{0,40})[ \t]*[:=][ \t]*([^\s#"'`{[<|>&*!$][^\s#]{0,39})[ \t]*(?:#.*)?$/gm;
const isUserKey = (name: string) => /^(?:user(?:_?name)?|login|uid|account|admin_?(?:user|name|login)|db_?user(?:name)?)$/i.test(name.split(/[.]/).pop() ?? "");

const DB_SCHEMES = new Set(["postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "mssql", "sqlserver", "clickhouse", "cockroachdb", "oracle", "db2", "cassandra", "couchdb", "neo4j", "bolt", "nats", "mqtt", "mqtts", "jdbc"]);
const AUTH_SCHEMES = new Set(["http", "https", "ftp", "ftps", "sftp", "ssh", "git", "smtp", "smtps", "imap", "imaps", "ldap", "ldaps", "ws", "wss"]);
const URL_RE = /\b((?:jdbc:)?[a-z][a-z0-9+.-]{1,24}):\/\/([^\s:@/"'`<>\\]{1,80}):([^\s@/"'`<>\\]{1,160})@([^\s/:"'`<>?#\\,;)]{1,200})/gi;
const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|[\w.-]*\.(?:local|localhost|test|example|invalid|internal)|(?:[\w-]+\.)?example\.(?:com|org|net))$/i;

export function passwordFindings(f: R2File): R2Finding[] {
  if (skipPath(f.path) || SKIP_FILES.test(f.path)) return [];
  const out: R2Finding[] = [];
  const lines = f.content.split("\n");
  const code = CODE_EXT.test(f.path), config = CONFIG_EXT.test(f.path);
  const taken = new Set<number>();

  // ── addresses with the password inside ──
  URL_RE.lastIndex = 0;
  for (let m = URL_RE.exec(f.content); m; m = URL_RE.exec(f.content)) {
    const scheme = m[1]!.toLowerCase().replace(/^jdbc:/, ""), user = m[2]!, pass = m[3]!, host = m[4]!;
    const kind = DB_SCHEMES.has(scheme) ? "database" : AUTH_SCHEMES.has(scheme) ? "basic_auth" : null;
    if (!kind) continue;
    if (isPlaceholderValue(pass) || /^(?:user(?:name)?|usr|login|name)$/i.test(user) || /[${}%*]|^<|>$/.test(pass) || /[${}<>]/.test(user) || /[${}<>]/.test(host)) continue;
    if (LOCAL_HOST.test(host)) continue;
    if (!host.includes(".") && (WEAK.has(pass.toLowerCase()) || pass === user)) continue;   // a local compose service with its default login
    if (/^(?:git|x-access-token|oauth2|token|apikey)$/i.test(user) && /^(?:gh[pousr]_|github_pat_|glpat-)/.test(pass)) continue;   // a token with a known shape: inside.secret's finding
    const line = lineOf(f.content, m.index);
    taken.add(line);
    out.push(finding("inside.cred_url_password", f, line, { kind, scheme, host: host.slice(0, 80), user: user.slice(0, 40) }, { key: `${scheme}|${host}|${user}`, masked: maskValue(pass), snippet: maskedLine(lines[line - 1] ?? "", pass) }));
  }
  if (!code && !config) return out;
  if (I18N_PATH.test(f.path)) return out;

  // ── default pairs ──
  if (!OWN_RULES.test(f.path)) {
    const pairs: { name: string; value: string; line: number }[] = [];
    const collect = (re: RegExp) => { re.lastIndex = 0; for (let m = re.exec(f.content); m; m = re.exec(f.content)) pairs.push({ name: m[1]!, value: m[2]!, line: lineOf(f.content, m.index + m[0].indexOf(m[1]!)) }); };
    collect(USER_KEY);
    if (config && !/\.json$/i.test(f.path)) collect(USER_KEY_PLAIN);
    const users = pairs.filter((x) => isUserKey(x.name) && USERS.has(x.value.toLowerCase()));
    for (const x of users.length ? pairs : []) {
      if (!(isSecretName(x.name) || /^(?:pass(?:word)?|pwd|passwd)$/i.test(x.name.split(".").pop()!))) continue;
      const u = users.find((y) => Math.abs(y.line - x.line) <= 3);
      if (!u || taken.has(x.line)) continue;
      if (!(WEAK.has(x.value.toLowerCase()) || x.value.toLowerCase() === u.value.toLowerCase())) continue;
      taken.add(x.line);
      out.push(finding("inside.cred_default_login", f, x.line, { user: u.value.slice(0, 40), name: x.name.slice(0, 60) }, { key: `${u.value}|${x.name}`, masked: maskValue(x.value), snippet: maskedLine(lines[x.line - 1] ?? "", x.value) }));
    }
  }

  // ── a literal given to a password name ──
  if (OWN_RULES.test(f.path)) return out;
  const hit = (name: string, value: string, index: number) => {
    const line = lineOf(f.content, index);
    if (taken.has(line)) return;
    if (!isSecretName(name) || !plausiblePassword(value)) return;
    if (value.length >= 20 && looksRandom(value)) return;                     // inside.secret_entropy owns it
    if (value.toLowerCase() === name.toLowerCase()) return;
    const text = lines[line - 1] ?? "";
    if (/^\s*(?:\/\/|#|\*|\/\*|--|<!--)/.test(text)) return;                  // a comment
    if (/\b(?:placeholder|label|title|aria-label|name|id|htmlFor|type|autoComplete|data-testid)\s*=\s*["'{]/.test(text) && /<\w/.test(text)) return;   // a form field in markup
    taken.add(line);
    out.push(finding("inside.cred_password_literal", f, line, { name: name.slice(0, 80) }, { key: `${name}|${maskValue(value)}`, masked: maskValue(value), snippet: maskedLine(text, value) }));
  };
  QUOTED.lastIndex = 0;
  for (let m = QUOTED.exec(f.content); m; m = QUOTED.exec(f.content)) hit(m[2]!, m[4]!, m.index + m[0].lastIndexOf(m[4]!));
  if (config && !/\.json$/i.test(f.path)) {
    UNQUOTED.lastIndex = 0;
    for (let m = UNQUOTED.exec(f.content); m; m = UNQUOTED.exec(f.content)) hit(m[1]!, m[2]!, m.index + m[0].lastIndexOf(m[2]!));
  }
  return out;
}
