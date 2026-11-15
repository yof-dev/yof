/**
 * A careful reader for Terraform's HCL (no dependency): blocks with their labels, attributes with their raw value
 * text, nested blocks, comments (#, //, slash-star) and heredocs. It does not evaluate anything: an attribute's value
 * is kept as written, and the helpers below read it only when it is a plain literal ("text", true, 22, ["a", "b"]).
 * A value that is a variable, a function call or an interpolation is NOT a literal, and no rule fires on it.
 * A file that does not balance its brackets gives no blocks at all.
 */
export interface HclAttr { raw: string; line: number }
export interface HclBlock { type: string; labels: string[]; line: number; attrs: Map<string, HclAttr>; blocks: HclBlock[] }

/** The text with comments blanked out (same length, same lines) and heredoc bodies blanked too. */
function clean(src: string): string {
  const out = src.split("");
  const blank = (a: number, b: number) => { for (let k = a; k < b; k++) if (out[k] !== "\n") out[k] = " "; };
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '"') {
      i++;
      while (i < src.length && src[i] !== '"' && src[i] !== "\n") { if (src[i] === "\\") i++; i++; }
      i++;
      continue;
    }
    if (ch === "#" || (ch === "/" && src[i + 1] === "/")) { const e = src.indexOf("\n", i); const end = e === -1 ? src.length : e; blank(i, end); i = end; continue; }
    if (ch === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); const end = e === -1 ? src.length : e + 2; blank(i, end); i = end; continue; }
    if (ch === "<" && src[i + 1] === "<") {
      const m = /^<<-?\s*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n/.exec(src.slice(i, i + 80));
      if (m) {
        const bodyStart = i + m[0].length;
        const endRe = new RegExp(`^[ \\t]*${m[1]}[ \\t]*\\r?$`, "m");
        const rel = endRe.exec(src.slice(bodyStart));
        const end = rel ? bodyStart + rel.index + rel[0].length : src.length;
        blank(i, end);
        out[i] = '"'; out[i + 1] = '"';   // the heredoc reads as an (unknown) text value
        i = end;
        continue;
      }
    }
    i++;
  }
  return out.join("");
}

function lineAt(src: string, index: number): number { let n = 1; for (let k = 0; k < index; k++) if (src.charCodeAt(k) === 10) n++; return n; }

/** The blocks of a Terraform file, or [] when it could not be read exactly. */
export function parseHcl(src: string): HclBlock[] {
  const text = clean(src);
  let i = 0;
  const ws = () => { while (i < text.length && /\s/.test(text[i]!)) i++; };

  function value(): string {
    // an expression runs to the end of the line at bracket depth 0
    const start = i;
    let depth = 0;
    while (i < text.length) {
      const ch = text[i]!;
      if (ch === '"') { i++; while (i < text.length && text[i] !== '"' && text[i] !== "\n") { if (text[i] === "\\") i++; i++; } i++; continue; }
      if (ch === "(" || ch === "[" || ch === "{") depth++;
      else if (ch === ")" || ch === "]" || ch === "}") { if (depth === 0) break; depth--; }
      else if (ch === "\n" && depth === 0) break;
      i++;
    }
    return src.slice(start, i).trim().replace(/,$/, "").trim();
  }

  function body(top: boolean): { attrs: Map<string, HclAttr>; blocks: HclBlock[] } | null {
    const attrs = new Map<string, HclAttr>();
    const blocks: HclBlock[] = [];
    for (;;) {
      ws();
      if (i >= text.length) return top ? { attrs, blocks } : null;
      if (text[i] === "}") { if (top) return null; i++; return { attrs, blocks }; }
      const id = /^[A-Za-z_][\w.-]*/.exec(text.slice(i, i + 200));
      if (!id) return null;
      const line = lineAt(text, i);
      i += id[0].length;
      const labels: string[] = [];
      for (;;) {
        while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
        if (text[i] === '"') {
          const e = text.indexOf('"', i + 1);
          if (e === -1) return null;
          labels.push(src.slice(i + 1, e));
          i = e + 1;
          continue;
        }
        break;
      }
      if (text[i] === "=" && text[i + 1] !== "=") {
        if (labels.length) return null;
        i++;
        while (i < text.length && (text[i] === " " || text[i] === "\t")) i++;
        if (!attrs.has(id[0])) attrs.set(id[0], { raw: value(), line }); else value();
        continue;
      }
      if (text[i] === "{") {
        i++;
        const inner = body(false);
        if (!inner) return null;
        blocks.push({ type: id[0], labels, line, attrs: inner.attrs, blocks: inner.blocks });
        continue;
      }
      return null;
    }
  }
  return body(true)?.blocks ?? [];
}

// ── literal readers (anything that is not a plain literal gives null) ────────────────────────────────────────────
/** "text" with no interpolation. */
export function hclStr(a: HclAttr | undefined): string | null {
  if (!a) return null;
  const m = /^"((?:[^"\\]|\\.)*)"$/.exec(a.raw);
  if (!m || m[1]!.includes("${") || m[1]!.includes("%{")) return null;
  return m[1]!.replace(/\\(["\\])/g, "$1");
}
/** true / false (also written as "true" / "false"). */
export function hclBool(a: HclAttr | undefined): boolean | null {
  if (!a) return null;
  const r = a.raw.replace(/^"|"$/g, "");
  return r === "true" ? true : r === "false" ? false : null;
}
/** 22 or "22". */
export function hclNum(a: HclAttr | undefined): number | null {
  if (!a) return null;
  const r = a.raw.replace(/^"|"$/g, "");
  return /^-?\d+$/.test(r) ? Number(r) : null;
}
/** ["a", "b"]: every item must be a plain text literal, or the whole list is null. */
export function hclList(a: HclAttr | undefined): string[] | null {
  if (!a) return null;
  const m = /^\[([\s\S]*)\]$/.exec(a.raw);
  if (!m) return null;
  const inner = m[1]!.trim().replace(/,$/, "");
  if (!inner) return [];
  const out: string[] = [];
  for (const part of inner.split(",")) {
    const s = /^\s*"((?:[^"\\$%]|\\.)*)"\s*$/.exec(part);
    if (!s) return null;
    out.push(s[1]!);
  }
  return out;
}
/** Every block of a type inside a block. */
export const hclBlocks = (b: HclBlock, type: string): HclBlock[] => b.blocks.filter((x) => x.type === type);
