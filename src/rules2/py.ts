/**
 * Python, read as text (no parser): only the simple, exact forms. A call is found by its dotted name, its arguments
 * are the text between its balanced parentheses, and "request input" is the same notion as in ./ast.ts, by text:
 * the argument reads request.args / form / values / json / data / cookies / headers / files (Flask, FastAPI) or
 * request.GET / POST / body (Django), or a local name that was assigned from one earlier IN THE SAME def.
 * A value wrapped in int(), float(), escape(), secure_filename() or shlex.quote() is no longer request input.
 * Anything else (a helper function, a class attribute, another file) is out of scope.
 */
import { lineOf } from "./types";

export const isPython = (p: string): boolean => /\.py$/i.test(p);

export const PY_SOURCE = /\brequest\.(?:args|form|values|json|data|cookies|headers|files|GET|POST|body|query_params|path_params|COOKIES|FILES|get_json\s*\(|get_data\s*\(|stream)\b|\bflask\.request\./;
const PY_KILL = /^\s*(?:int|float|bool|len|str\.isdigit|escape|html\.escape|markupsafe\.escape|quote|urllib\.parse\.quote|shlex\.quote|secure_filename|bleach\.clean|uuid\.UUID|ipaddress\.ip_address)\s*\(/;

/** The text with comments blanked (same length, same lines). Strings are kept. */
export function pyCode(src: string): string {
  const out = src.split("");
  let q: string | null = null;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (q) {
      if (ch === "\\") { i++; continue; }
      if (q.length === 3 ? src.startsWith(q, i) : ch === q) { i += q.length - 1; q = null; }
      else if (q.length === 1 && ch === "\n") q = null;
      continue;
    }
    if (ch === '"' || ch === "'") { q = src.startsWith(ch.repeat(3), i) ? ch.repeat(3) : ch; i += q.length - 1; continue; }
    if (ch === "#") { const e = src.indexOf("\n", i); const end = e === -1 ? src.length : e; for (let k = i; k < end; k++) out[k] = " "; i = end - 1; }
  }
  return out.join("");
}

export interface PyCall { name: string; index: number; line: number; args: string; first: string }

/** Split call arguments at the commas of their own level. */
export function pyArgs(args: string): string[] {
  const out: string[] = [];
  let depth = 0, q: string | null = null, start = 0;
  for (let i = 0; i < args.length; i++) {
    const ch = args[i]!;
    if (q) { if (ch === "\\") i++; else if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) { out.push(args.slice(start, i).trim()); start = i + 1; }
  }
  if (args.slice(start).trim()) out.push(args.slice(start).trim());
  return out;
}

/** Every call of a dotted name that matches `names` (a regex source for the name, without the parenthesis). */
export function pyCalls(code: string, names: string): PyCall[] {
  const re = new RegExp(`(?<![\\w.])(${names})\\s*\\(`, "g");
  const out: PyCall[] = [];
  for (let m = re.exec(code); m; m = re.exec(code)) {
    const open = m.index + m[0].length - 1;
    let depth = 0, q: string | null = null, close = -1;
    for (let i = open; i < code.length && i < open + 4000; i++) {
      const ch = code[i]!;
      if (q) { if (ch === "\\") i++; else if (ch === q) q = null; continue; }
      if (ch === '"' || ch === "'") q = ch;
      else if (ch === "(" || ch === "[" || ch === "{") depth++;
      else if (ch === ")" || ch === "]" || ch === "}") { depth--; if (depth === 0) { close = i; break; } }
    }
    if (close === -1) continue;
    const args = code.slice(open + 1, close);
    out.push({ name: m[1]!, index: m.index, line: lineOf(code, m.index), args, first: pyArgs(args)[0] ?? "" });
  }
  return out;
}

/** The lines of the def around a line (1-based, inclusive), or the whole file at module level. */
export function pyScope(lines: readonly string[], line: number): [number, number] {
  const indent = (s: string) => s.length - s.trimStart().length;
  const my = indent(lines[line - 1] ?? "");
  let start = 0, defIndent = -1;
  for (let i = line - 2; i >= 0; i--) {
    const l = lines[i]!;
    if (!l.trim()) continue;
    if (/^\s*(?:async\s+)?def\s+\w+/.test(l) && indent(l) < my) { start = i + 1; defIndent = indent(l); break; }
  }
  if (defIndent === -1) return [1, lines.length];
  let end = lines.length;
  for (let i = line; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() && indent(l) <= defIndent) { end = i; break; }
  }
  return [start, end];
}

/** The expression with the contents of plain strings blanked ("name" is not the variable name); f-strings are kept. */
export function pyNoPlainStrings(expr: string): string {
  let out = "";
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (ch !== '"' && ch !== "'") { out += ch; continue; }
    let k = i - 1;
    while (k >= 0 && /[rRbBuU]/.test(expr[k]!)) k--;
    const isF = k >= 0 && /[fF]/.test(expr[k]!) && !(k > 0 && /[\w.]/.test(expr[k - 1]!) && !/[rRbB]/.test(expr[k - 1]!));
    let j = i + 1;
    while (j < expr.length && expr[j] !== ch) { if (expr[j] === "\\") j++; j++; }
    out += isF ? expr.slice(i, j + 1) : `${ch}${ch}`;
    i = j;
  }
  return out;
}

export interface PyTaint { is(expr: string): boolean; text: string }

/** The taint view of the def around `line`: request reads and the local names assigned from them, in order. */
export function pyTaint(code: string, line: number): PyTaint {
  const lines = code.split("\n");
  const [a, b] = pyScope(lines, line);
  const names = new Set<string>();
  const is = (raw: string): boolean => {
    if (PY_KILL.test(raw)) return false;
    const expr = pyNoPlainStrings(raw);
    if (PY_SOURCE.test(expr)) return true;
    for (const n of names) if (new RegExp(`(?<![\\w.])${n}(?![\\w(])`).test(expr)) return true;
    return false;
  };
  for (let i = a - 1; i < Math.min(b, line); i++) {
    const m = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(.+)$/.exec(lines[i]!);
    if (m && is(m[2]!)) names.add(m[1]!);
  }
  return { is, text: lines.slice(a - 1, b).join("\n") };
}
