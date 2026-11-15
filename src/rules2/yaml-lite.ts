/**
 * A small YAML reader for docker-compose files and Kubernetes manifests (no dependency). It reads the plain subset
 * those files are written in: block maps and lists, quoted and plain scalars, one-line flow lists and maps, block
 * text (| and >), comments and several documents in one file. Every node keeps its line.
 *
 * What it does NOT read, on purpose: anchors, aliases and merge keys (&a, *a, <<), tags (!!x), tabs as indentation,
 * flow collections over several lines, and templates ({{ ... }} from Helm). A document that uses one of these throws
 * YamlUnsupported and the caller skips it: no finding is ever made from a file yof could not read exactly.
 */
export class YamlUnsupported extends Error {}

export type YNode =
  | { t: "map"; line: number; entries: { key: string; line: number; value: YNode | null }[] }
  | { t: "seq"; line: number; items: (YNode | null)[] }
  | { t: "str"; line: number; value: string; quoted: boolean };

interface Line { indent: number; text: string; line: number }

/** A line without its comment (a # at the start or after a space, outside quotes). */
function stripComment(raw: string): string {
  let q: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (q) { if (ch === "\\" && q === '"') i++; else if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { if (i === 0 || /[\s:[{,-]/.test(raw[i - 1]!)) q = ch; continue; }
    if (ch === "#" && (i === 0 || /\s/.test(raw[i - 1]!))) return raw.slice(0, i);
  }
  return raw;
}

function unquote(s: string): { value: string; quoted: boolean } {
  const t = s.trim();
  if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') return { value: t.slice(1, -1).replace(/\\(["\\/])/g, "$1").replace(/\\n/g, "\n").replace(/\\t/g, "\t"), quoted: true };
  if (t.length >= 2 && t[0] === "'" && t[t.length - 1] === "'") return { value: t.slice(1, -1).replace(/''/g, "'"), quoted: true };
  return { value: t, quoted: false };
}

/** The index of the ":" that ends a key ("key: value" or "key:"), or -1. */
function keyEnd(text: string): number {
  if (text[0] === '"' || text[0] === "'") {
    const q = text[0];
    for (let i = 1; i < text.length; i++) {
      if (text[i] === "\\" && q === '"') { i++; continue; }
      if (text[i] === q) { const rest = text.slice(i + 1); return /^\s*:(?:\s|$)/.test(rest) ? i + 1 + rest.indexOf(":") : -1; }
    }
    return -1;
  }
  if (/^[[{]/.test(text)) return -1;
  const m = /:(?:\s|$)/.exec(text);
  return m ? m.index : -1;
}

/** Split a one-line flow body ("a, b: c, [d]") at the commas of its own level. */
function splitFlow(body: string): string[] {
  const out: string[] = [];
  let depth = 0, q: string | null = null, start = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (q) { if (ch === "\\" && q === '"') i++; else if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === "[" || ch === "{") depth++;
    else if (ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) { out.push(body.slice(start, i)); start = i + 1; }
  }
  if (q || depth !== 0) throw new YamlUnsupported("flow collection over several lines");
  if (body.slice(start).trim()) out.push(body.slice(start));
  return out;
}

function scalarOrFlow(text: string, line: number): YNode {
  const t = text.trim();
  if (/^[&*!]/.test(t)) throw new YamlUnsupported("anchor, alias or tag");
  if (t.includes("{{")) throw new YamlUnsupported("template");
  if (t.startsWith("[")) {
    if (!t.endsWith("]")) throw new YamlUnsupported("flow collection over several lines");
    return { t: "seq", line, items: splitFlow(t.slice(1, -1)).map((x) => scalarOrFlow(x, line)) };
  }
  if (t.startsWith("{")) {
    if (!t.endsWith("}")) throw new YamlUnsupported("flow collection over several lines");
    const entries = splitFlow(t.slice(1, -1)).map((part) => {
      const p = part.trim();
      const at = keyEnd(p);
      if (at === -1) return { key: unquote(p).value, line, value: null };
      const rest = p.slice(at + 1).trim();
      return { key: unquote(p.slice(0, at)).value, line, value: rest ? scalarOrFlow(rest, line) : null };
    });
    return { t: "map", line, entries };
  }
  return { t: "str", line, ...unquote(t) };
}

function parseDoc(lines: Line[]): YNode | null {
  let i = 0;
  const isSeqItem = (l: Line) => l.text === "-" || l.text.startsWith("- ");

  function node(indent: number): YNode | null {
    const l = lines[i];
    if (!l || l.indent < indent) return null;
    if (isSeqItem(l)) return seq(l.indent);
    if (keyEnd(l.text) !== -1) return map(l.indent);
    i++;
    return scalarOrFlow(l.text, l.line);
  }

  function seq(indent: number): YNode {
    const out: YNode = { t: "seq", line: lines[i]!.line, items: [] };
    while (i < lines.length && lines[i]!.indent === indent && isSeqItem(lines[i]!)) {
      const l = lines[i]!;
      const rest = l.text.slice(1);
      const body = rest.trimStart();
      if (!body) { i++; out.items.push(lines[i] && lines[i]!.indent > indent ? node(lines[i]!.indent) : null); continue; }
      // the item's content starts on this line: read it as if it stood alone at its own column
      lines[i] = { indent: indent + 1 + (rest.length - body.length), text: body, line: l.line };
      out.items.push(node(lines[i]!.indent));
    }
    return out;
  }

  function map(indent: number): YNode {
    const out: YNode = { t: "map", line: lines[i]!.line, entries: [] };
    while (i < lines.length && lines[i]!.indent === indent && !isSeqItem(lines[i]!)) {
      const l = lines[i]!;
      const at = keyEnd(l.text);
      if (at === -1) throw new YamlUnsupported(`line ${l.line}: not a key`);
      const key = unquote(l.text.slice(0, at)).value;
      if (key === "<<" || /^[&*!?]/.test(key)) throw new YamlUnsupported("merge key, anchor or tag");
      const rest = l.text.slice(at + 1).trim();
      i++;
      let value: YNode | null;
      if (!rest) {
        const next = lines[i];
        if (next && next.indent > indent) value = node(next.indent);
        else if (next && next.indent === indent && isSeqItem(next)) value = seq(indent);
        else value = null;
      } else if (/^[|>][+-]?\d*$/.test(rest)) {
        const parts: string[] = [];
        while (i < lines.length && lines[i]!.indent > indent) { parts.push(lines[i]!.text); i++; }
        value = { t: "str", line: l.line, value: parts.join(rest[0] === "|" ? "\n" : " "), quoted: true };
      } else value = scalarOrFlow(rest, l.line);
      out.entries.push({ key, line: l.line, value });
    }
    if (i < lines.length && lines[i]!.indent > indent) throw new YamlUnsupported(`line ${lines[i]!.line}: unexpected indentation`);
    return out;
  }

  const root = lines.length ? node(lines[0]!.indent) : null;
  if (i < lines.length) throw new YamlUnsupported(`line ${lines[i]!.line}: could not be read`);
  return root;
}

/** Every document of a YAML text. A document that could not be read exactly is `null` (never a guess). */
export function parseYaml(text: string): (YNode | null)[] {
  const docs: Line[][] = [[]];
  const bad = new Set<number>();
  const raw = text.split(/\r?\n/);
  for (let n = 0; n < raw.length; n++) {
    const r = raw[n]!;
    if (/^---(?:\s|$)/.test(r) || /^\.\.\.\s*$/.test(r)) { docs.push([]); continue; }
    if (/^%/.test(r)) continue;
    const s = stripComment(r).replace(/\s+$/, "");
    if (!s.trim()) continue;
    const lead = /^[ \t]*/.exec(s)![0];
    if (lead.includes("\t")) { bad.add(docs.length - 1); continue; }
    docs[docs.length - 1]!.push({ indent: lead.length, text: s.slice(lead.length), line: n + 1 });
  }
  return docs.filter((d) => d.length).map((d) => {
    if (bad.has(docs.indexOf(d))) return null;
    try { return parseDoc(d.map((l) => ({ ...l }))); } catch (e) { if (e instanceof YamlUnsupported) return null; throw e; }
  });
}

// ── reading helpers ──────────────────────────────────────────────────────────────────────────────────────────────
export const yGet = (n: YNode | null | undefined, key: string): YNode | null => (n && n.t === "map" ? n.entries.find((e) => e.key === key)?.value ?? null : null);
export const yPath = (n: YNode | null | undefined, ...keys: string[]): YNode | null => { let cur: YNode | null = n ?? null; for (const k of keys) cur = yGet(cur, k); return cur; };
export const yStr = (n: YNode | null | undefined): string | null => (n && n.t === "str" ? n.value : null);
export const yItems = (n: YNode | null | undefined): YNode[] => (n && n.t === "seq" ? n.items.filter((x): x is YNode => !!x) : []);
/** true / false as YAML writes them (an unquoted yes or on counts as true, as Docker and Kubernetes read it). */
export function yBool(n: YNode | null | undefined): boolean | null {
  if (!n || n.t !== "str") return null;
  if (/^(?:true|yes|on)$/i.test(n.value)) return true;
  if (/^(?:false|no|off)$/i.test(n.value)) return false;
  return null;
}
