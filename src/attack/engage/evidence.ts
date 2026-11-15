/**
 * yof engagement, open core: the evidence bundle. What is kept of a proof, and nothing more.
 *
 * For every request of the chain: who sent it (the ROLE, never a credential), the method and the path, the NAMES of
 * the request headers (never a value), the request body with keys, email addresses and long numbers masked, the
 * status, and of the answer only its SHAPE (kind, size, field names), which of the run's markers it held, and a few
 * cache headers. The answer's text is never kept: only the marker is read from another account's record.
 *
 * With the exchanges go the marker ids, the replay spec (the chain as data: no secret is ever in one) and a hash over
 * all of it, so a stored bundle can be shown to be the one the run made.
 *
 * Masking uses the same helpers as every yof attack report (../mask.ts). The run's own markers are kept whole: they
 * are the proof, and they are letters only so no masking rule can change them.
 */
import { createHash } from "node:crypto";
import type { As, HttpAnswer, Method } from "../http";
import { answerShape, maskText } from "../mask";
import type { ReplaySpec } from "../replay";
import { MARKER_SHAPE, findMarkers, type EngageInit, type EngageIo } from "./markers";

export const EVIDENCE_SCHEMA = 1 as const;
export const MAX_EXCHANGES = 200;
export const MAX_BODY_CHARS = 500;
/** Answer headers that say whether a cache was involved, or how to read the answer. Nothing else is kept. */
export const KEPT_ANSWER_HEADERS = ["content-type", "cache-control", "age", "x-cache", "cf-cache-status", "vary", "retry-after"] as const;

export interface EvidenceExchange {
  n: number;
  as: As;
  method: Method;
  /** The path as sent, masked. */
  path: string;
  leg?: string;
  request: { headers: string[]; body: string | null };
  /** 0 = no answer. */
  status: number;
  answer: { shape: string; markers: string[]; headers: Record<string, string> };
}

export interface EvidenceVerifier { stands: boolean | null; refuted_by: string | null; undecided: string | null; notes: string[] }

export interface EvidenceBundle {
  schema: typeof EVIDENCE_SCHEMA;
  rule_id: string;
  /** Who ran it. A run from this command line is the owner's own: yof did not see it. */
  reported_by: "owner_run" | "yof_run";
  run_nonce: string;
  created_at: string;
  markers: string[];
  exchanges: EvidenceExchange[];
  replay: ReplaySpec;
  verifier: EvidenceVerifier | null;
  /** sha256 over the canonical form of everything above. */
  hash: string;
}

const MARKER_SPLIT = new RegExp(`(${MARKER_SHAPE.source})`, "g");
const MARKER_ONLY = new RegExp(`^${MARKER_SHAPE.source}$`);
/** Mask a text, keeping the run's markers whole. Whitespace folded, cut to `max`. Pure. */
export function maskKeepingMarkers(text: string, max = MAX_BODY_CHARS): string {
  return text.split(MARKER_SPLIT).map((part) => (MARKER_ONLY.test(part) ? part : maskText(part))).join("").replace(/\s+/g, " ").trim().slice(0, max);
}

/** One exchange as it may be kept. Pure. */
export function exchangeOf(n: number, as: As, method: Method, path: string, init: EngageInit | undefined, r: HttpAnswer | null): EvidenceExchange {
  const headers: Record<string, string> = {};
  if (r) for (const h of KEPT_ANSWER_HEADERS) { const v = r.headers.get(h); if (v) headers[h] = maskKeepingMarkers(v, 120); }
  return {
    n, as, method, path: maskKeepingMarkers(path, 300), ...(init?.leg ? { leg: init.leg } : {}),
    request: { headers: Object.keys(init?.headers ?? {}).map((k) => k.toLowerCase()).sort(), body: init?.body === undefined ? null : maskKeepingMarkers(init.body) },
    status: r ? r.status : 0,
    answer: { shape: r ? answerShape(r.body) : "no answer", markers: r ? findMarkers(r.body) : [], headers },
  };
}

/** Wrap an io so every exchange is recorded, already masked. The raw answer is never stored. */
export function recordingIo(io: EngageIo): { io: EngageIo; exchanges: EvidenceExchange[] } {
  const exchanges: EvidenceExchange[] = [];
  return {
    exchanges,
    io: {
      own: (id) => io.own(id),
      ...(io.pathAllowed ? { pathAllowed: io.pathAllowed } : {}),
      send: async (as, method, path, init) => {
        const r = await io.send(as, method, path, init);
        if (exchanges.length < MAX_EXCHANGES) exchanges.push(exchangeOf(exchanges.length + 1, as, method, path, init, r));
        return r;
      },
    },
  };
}

function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
}
/** The hash of a bundle: sha256 over its canonical form (sorted keys), the hash field itself left out. Pure. */
export const bundleHash = (b: Omit<EvidenceBundle, "hash">): string => {
  const { hash: _ignored, ...rest } = b as EvidenceBundle;
  return createHash("sha256").update(`yof-evidence:v${EVIDENCE_SCHEMA}\n${canonical(rest)}`, "utf8").digest("hex");
};

export interface BundleInput {
  ruleId: string;
  reportedBy: "owner_run" | "yof_run";
  runNonce: string;
  createdAt: string;
  markers: readonly string[];
  exchanges: readonly EvidenceExchange[];
  replay: ReplaySpec;
  verifier?: EvidenceVerifier | null;
}
export function buildEvidenceBundle(i: BundleInput): EvidenceBundle {
  const body: Omit<EvidenceBundle, "hash"> = {
    schema: EVIDENCE_SCHEMA, rule_id: i.ruleId, reported_by: i.reportedBy, run_nonce: i.runNonce, created_at: i.createdAt,
    markers: [...new Set(i.markers)], exchanges: i.exchanges.slice(0, MAX_EXCHANGES).map((e) => ({ ...e })), replay: i.replay, verifier: i.verifier ?? null,
  };
  return { ...body, hash: bundleHash(body) };
}
/** Is the bundle the one its hash names? */
export const bundleIntact = (b: EvidenceBundle): boolean => typeof b.hash === "string" && b.hash === bundleHash(b);
