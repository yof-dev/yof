/**
 * yof attack: what may be kept of a request or an answer. Two helpers, used by the runner and by the engagement
 * evidence (./engage/evidence.ts). Pure.
 *
 *   maskEvidence   a sentence in yof's own words, with keys, email addresses and long numbers masked, 200 characters
 *   answerShape    what an answer looked like WITHOUT what it said: its kind, its size and the names of its fields
 */
import { maskAll } from "../secrets";

const EMAIL_G = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const maskEmail = (e: string) => { const [u, d] = e.split("@"); return `${(u ?? "").slice(0, 1)}•••@${d ?? ""}`; };
/** A phone number or another long run of digits (a card, an account number): only its last two digits are kept. */
const DIGITS_G = /\+?\d[\d\s().-]{6,}\d/g;
const maskDigits = (d: string) => `•••${d.replace(/\D/g, "").slice(-2)}`;
/** Keys, email addresses and long numbers masked; the length and the line breaks are the caller's business. */
export const maskText = (s: string) => maskAll(s.replace(EMAIL_G, maskEmail)).replace(DIGITS_G, maskDigits);
/** Evidence as it may be shown or stored: keys, emails and long numbers masked, whitespace folded, 200 characters at most. */
export const maskEvidence = (s: string) => maskText(s).replace(/\s+/g, " ").trim().slice(0, 200);

/** A field name that is safe to show: a plain identifier. A name, an address or an id used as a key is not shown. */
const FIELD = /^[A-Za-z_][A-Za-z0-9_-]{0,29}$/;
/**
 * What an answer looked like, WITHOUT what it said. Evidence used to hold the first 200 characters of the answer, and
 * masking only knows keys and email addresses: a name, a phone number or a home address from a real record went into
 * the report, the upload and the yof app (security audit, 11 Nov 2026). Now only the shape is kept: the kind of answer,
 * its size and the names of its fields. Never a value. Pure.
 */
export function answerShape(body: string): string {
  const size = `${body.length} characters`;
  let v: unknown;
  try { v = JSON.parse(body); } catch { return `text, ${size}`; }
  const fields = (o: object) => {
    const keys = Object.keys(o);
    const shown = keys.filter((k) => FIELD.test(k)).slice(0, 8);
    return `${keys.length} ${keys.length === 1 ? "field" : "fields"}${shown.length ? ` (${shown.join(", ")}${keys.length > shown.length ? ", ..." : ""})` : ""}`;
  };
  if (Array.isArray(v)) {
    const first = v.find((x) => x && typeof x === "object" && !Array.isArray(x)) as object | undefined;
    return `a JSON list of ${v.length} ${v.length === 1 ? "item" : "items"}${first ? `, the first with ${fields(first)}` : ""}, ${size}`;
  }
  if (v && typeof v === "object") return `a JSON object with ${fields(v)}, ${size}`;
  return `a JSON ${v === null ? "null" : typeof v}, ${size}`;
}
