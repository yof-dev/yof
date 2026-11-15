/**
 * Helpers for the engagement tests: a fake clock, a rules-of-engagement record, a scripted HTTP client for the
 * governor, and a tiny notes app in memory with switchable flaws. No network and no real waiting anywhere.
 */
import type { As, HttpAnswer, Method } from "../src/attack/http";
import type { GovernedClient } from "../src/attack/engage/governor";
import type { EngageInit, EngageIo } from "../src/attack/engage/markers";
import { FORBIDDEN_ACTIONS, SEED_FORBIDDEN_PATHS, type EngageRoe, type EngageRoeHost } from "../src/attack/engage/roe";

export const HOST = "shop.example.com";
/** 02:00 UTC: inside the night window. */
export const NIGHT = Date.parse("2026-11-12T02:00:00Z");

export function fakeClock(start = NIGHT) {
  let t = start;
  return { now: () => t, sleep: async (ms: number) => { t += ms; }, advance: (ms: number) => { t += ms; }, set: (v: number) => { t = v; } };
}
export type Clock = ReturnType<typeof fakeClock>;

export const answer = (status: number, body: unknown = { ok: true }, headers: Record<string, string> = {}): HttpAnswer =>
  ({ status, body: typeof body === "string" ? body : JSON.stringify(body), headers: new Headers(headers), location: headers.location ?? null });

export const roe = (host: Partial<EngageRoeHost> = {}, budgets: EngageRoe["budgets"] = { total_requests: 2000, max_minutes: 60 }): EngageRoe => ({
  schema: 1,
  hosts: [{ host: HOST, environment: "staging", proof: "meta", classes: ["read", "write_own_test_records"], windows: [], requests_per_second: 2, ...host }],
  budgets, forbidden_paths: [...SEED_FORBIDDEN_PATHS].sort(), forbidden_actions: [...FORBIDDEN_ACTIONS],
  data: { marker_only: true, retention_days: 180, after_retention: "hashes_and_replay_steps" }, stop_contact: { email: null },
});

export interface Sent { as: As; method: Method; path: string; purpose?: string; at: number }
/** A client that answers from a script: `next(sent)` gives the answer and how long it took. */
export function scriptedClient(clock: Clock, next: (s: Sent, n: number) => { answer?: HttpAnswer; ms?: number } | void = () => {}, origin = `https://${HOST}`) {
  const sent: Sent[] = [];
  const owned: string[] = [];
  const client: GovernedClient = {
    origin,
    own: (id) => { owned.push(id); },
    send: async (as, method, path, init) => {
      const s: Sent = { as, method, path, purpose: init?.purpose, at: clock.now() };
      sent.push(s);
      const r = next(s, sent.length) ?? {};
      clock.advance(r.ms ?? 20);
      return r.answer ?? answer(200);
    },
  };
  return { client, sent, owned };
}

export const TOKEN: Record<Exclude<As, "anon">, string> = { a: "Bearer a", b: "Bearer b", admin: "Bearer admin", viewer: "Bearer viewer" };
export interface NotesFlaws {
  /** Any signed-in account reads any note by id. */
  leak?: boolean;
  /** A URL-keyed cache in front: once the owner has read a note, the same URL gives everyone the owner's answer. */
  cache?: boolean;
  /** An unknown id answers 200 with a page instead of a refusal. */
  softMissing?: boolean;
  /** The owner's own read does not return the title. */
  ownerBlind?: boolean;
  /** /api/admin/notes (every note) is open to every signed-in account. */
  adminOpen?: boolean;
  /** Reads answer 429. */
  slowDown?: boolean;
}
export interface NotesRequest { as: As; method: Method; path: string; body?: string }

/** A notes app in memory. `io` talks to it directly, as the governor would. */
export function notesApp(flaws: NotesFlaws = {}) {
  const notes = new Map<string, { owner: As; title: string }>();
  const cached = new Map<string, string>();
  const requests: NotesRequest[] = [];
  const owned: string[] = [];
  let next = 1;
  const handle = (as: As, method: Method, path: string, body?: string): HttpAnswer => {
    requests.push({ as, method, path, ...(body === undefined ? {} : { body }) });
    const url = new URL(path, "http://x");
    const p = url.pathname;
    if (p === "/") return answer(200, { ok: true });
    if (p === "/api/search") return answer(200, { q: url.searchParams.get("q"), results: [] });
    if (as === "anon") return answer(401, { error: "unauthorized" });
    if (p === "/api/notes" && method === "POST") {
      const id = `n${next++}`;
      notes.set(id, { owner: as, title: String((JSON.parse(body ?? "{}") as { title?: unknown }).title ?? "") });
      return answer(201, { id });
    }
    if (p === "/api/admin/notes" && method === "GET") {
      if (as !== "admin" && !flaws.adminOpen) return answer(403, { error: "forbidden" });
      return answer(200, { notes: [...notes.entries()].map(([id, n]) => ({ id, title: n.title })) });
    }
    const m = /^\/api\/notes\/([\w-]+)$/.exec(p);
    if (m) {
      const id = m[1]!;
      const n = notes.get(id);
      if (method === "GET") {
        if (flaws.slowDown) return answer(429, { error: "slow down" });
        const key = `${p}${url.search}`;
        if (flaws.cache && cached.has(key)) return answer(200, cached.get(key)!, { age: "5", "x-cache": "HIT" });
        if (!n) return flaws.softMissing ? answer(200, { page: "Welcome to the notes demo. Nothing is stored under this address yet." }) : answer(404, { error: "not found" });
        if (n.owner !== as && !flaws.leak) return answer(404, { error: "not found" });
        const out = JSON.stringify(n.owner === as && flaws.ownerBlind ? { id } : { id, title: n.title });
        if (flaws.cache && n.owner === as) cached.set(key, out);
        return answer(200, out);
      }
      if (method === "DELETE") {
        if (!n || n.owner !== as) return answer(404, { error: "not found" });
        notes.delete(id);
        return answer(204, "");
      }
    }
    return answer(404, { error: "not found" });
  };
  const io: EngageIo = {
    own: (id) => { owned.push(id); },
    send: async (as: As, method: Method, path: string, init?: EngageInit) => handle(as, method, path, init?.body),
  };
  return { io, notes, requests, owned, handle };
}

export const NOTE_OBJECT = { create: { path: "/api/notes", body: '{"title":"{{marker}}"}' }, idPath: "id", read: "/api/notes/{id}", delete: "/api/notes/{id}" };
export const readId = (body: string, path: string): string => { try { const v = (JSON.parse(body) as Record<string, unknown>)[path]; return typeof v === "string" ? v : ""; } catch { return ""; } };
let seq = 0;
/** Deterministic "random" hex. */
export const counterRandom = () => (++seq).toString(16).padStart(12, "0");
