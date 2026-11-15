/**
 * yof engagement, open core: planted markers.
 *
 * "The same data came back" is a guess: a public list, a plan name or an empty answer is shared by every visitor. A
 * marker is not a guess. It is a text only this run knows, written by one test account into ITS OWN test record:
 *
 *     YOF-MRK-<run nonce>-<role>-<n>        for example YOF-MRK-QWHRTPLKXZMB-A-1
 *
 * When another account, or nobody signed in, gets an answer that holds A's marker, that answer came from A's record.
 *
 * The registry knows every record the run planted (who planted it, its id, how to delete it). Clean-up deletes exactly
 * those records and nothing else: the path is built from the registered id only, and where the record can be read,
 * it is read first and deleted only if it still holds its marker. A record that was never registered is never touched.
 */
import { randomBytes } from "node:crypto";
import { fill } from "../config";
import type { As, HttpAnswer, Method, Purpose } from "../http";
import type { SafetyClass } from "./roe";

export const MARKER_PREFIX = "YOF-MRK";
/** Roles that can plant a marker. Nobody signed in ("anon") owns no record, so it never plants. */
export type MarkerRole = Exclude<As, "anon">;
const ROLE_TAG: Record<MarkerRole, string> = { a: "A", b: "B", admin: "ADMIN", viewer: "VIEWER" };
const TAG_ROLE: Record<string, MarkerRole> = { A: "a", B: "b", ADMIN: "admin", VIEWER: "viewer" };
/** Letters only, so no masking rule (long numbers, keys) can ever touch a marker. */
const NONCE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ";
export const NONCE_LENGTH = 12;
export const MARKER_SHAPE = /YOF-MRK-[A-Z]{12}-(?:A|B|ADMIN|VIEWER)-[1-9]\d{0,3}/;
const MARKER_ONLY = new RegExp(`^${MARKER_SHAPE.source}$`);
const MARKER_G = new RegExp(MARKER_SHAPE.source, "g");

/** A fresh run nonce: 12 letters from the system's random source (about 55 bits). */
export function newRunNonce(random: (n: number) => Uint8Array = (n) => randomBytes(n)): string {
  const bytes = random(NONCE_LENGTH * 2);
  let out = "";
  // rejection sampling, so every letter is equally likely
  for (let i = 0; i < bytes.length && out.length < NONCE_LENGTH; i++) { const b = bytes[i]!; if (b < 240) out += NONCE_ALPHABET[b % NONCE_ALPHABET.length]; }
  while (out.length < NONCE_LENGTH) out += NONCE_ALPHABET[randomBytes(1)[0]! % NONCE_ALPHABET.length];
  return out;
}

export const markerText = (nonce: string, role: MarkerRole, n: number): string => `${MARKER_PREFIX}-${nonce}-${ROLE_TAG[role]}-${n}`;
export function parseMarker(text: string): { nonce: string; role: MarkerRole; n: number } | null {
  if (!MARKER_ONLY.test(text)) return null;
  const [, , nonce, tag, n] = text.split("-");
  return { nonce: nonce!, role: TAG_ROLE[tag!]!, n: Number(n) };
}
/** Every marker-shaped text in a body, once each. */
export const findMarkers = (body: string): string[] => [...new Set(body.match(MARKER_G) ?? [])];

/** The one way engagement code sends a request (the governor implements it). null = the role has no usable account. */
export interface EngageInit {
  body?: string;
  headers?: Record<string, string>;
  purpose?: Purpose;
  /** The kind of test this request belongs to (the rules-of-engagement record allows it per host, or not). */
  cls?: SafetyClass;
  /** What the step does, when it is one of the record's forbidden actions. */
  actions?: readonly string[];
  /** Which part of a differential this request is; only the evidence recorder reads it. */
  leg?: "plant" | "positive" | "test" | "negative" | "cleanup";
}
export type EngageSend = (as: As, method: Method, path: string, init?: EngageInit) => Promise<HttpAnswer | null>;
export interface EngageIo {
  send: EngageSend;
  /** Tell the HTTP client that this id belongs to a record the run created (it then allows PATCH, PUT and DELETE on it). */
  own: (id: string) => void;
  /** May this path be requested at all? (The rules' forbidden paths.) Default: yes. */
  pathAllowed?: (path: string) => boolean;
}

/** How to make, read and delete one kind of test record (the config's object, or a library technique's). */
export interface PlantSpec {
  create: { path: string; body: string };
  idPath: string;
  /** With {id}. When given, clean-up reads the record first and deletes it only if it still holds its marker. */
  read?: string;
  /** With {id}. */
  delete: string;
}

export interface PlantedRecord {
  marker: string;
  role: MarkerRole;
  id: string;
  /** Routes as written in the spec (with {id}), never a real id. */
  createRoute: string;
  readRoute: string | null;
  deleteRoute: string;
  state: "planted" | "deleted" | "gone" | "left";
  /** Why it was left, when it was. */
  left?: string;
}

const withId = (p: string, id: string) => p.split("{id}").join(encodeURIComponent(id));
const ok = (s: number) => s >= 200 && s < 300;

export class MarkerRegistry {
  private readonly counters = new Map<MarkerRole, number>();
  private readonly records: PlantedRecord[] = [];
  private readonly issued = new Set<string>();
  constructor(readonly nonce: string = newRunNonce()) {
    if (!/^[A-Z]{12}$/.test(nonce)) throw new Error("A run nonce is 12 capital letters.");
  }

  /** The next marker text for a role. It is not planted yet: register() says where it went. */
  next(role: MarkerRole): string {
    if (!(role in ROLE_TAG)) throw new Error("Only a signed-in test account can plant a marker.");
    const n = (this.counters.get(role) ?? 0) + 1;
    this.counters.set(role, n);
    const m = markerText(this.nonce, role, n);
    this.issued.add(m);
    return m;
  }
  /** Is this marker one of this run's? */
  mine(marker: string): boolean { return this.issued.has(marker); }
  /** Record where a marker was planted. Only a marker this registry issued, in a record of the role that owns it. */
  register(marker: string, r: { id: string; createRoute: string; readRoute?: string | null; deleteRoute: string }): PlantedRecord {
    const p = parseMarker(marker);
    if (!p || !this.issued.has(marker)) throw new Error("This marker was not issued by this run.");
    if (!r.id || r.id.length > 200) throw new Error("A planted record needs its id.");
    if (!r.deleteRoute.includes("{id}")) throw new Error("A planted record needs a delete route with {id}.");
    if (this.records.some((x) => x.marker === marker)) throw new Error("This marker is planted already.");
    const rec: PlantedRecord = { marker, role: p.role, id: r.id, createRoute: r.createRoute, readRoute: r.readRoute ?? null, deleteRoute: r.deleteRoute, state: "planted" };
    this.records.push(rec);
    return rec;
  }
  get(marker: string): PlantedRecord | null { return this.records.find((r) => r.marker === marker) ?? null; }
  all(): readonly PlantedRecord[] { return this.records; }
  /** The markers planted so far (for the evidence bundle). */
  markers(): string[] { return this.records.map((r) => r.marker); }
  /** What clean-up still has to delete, newest first. */
  pending(): PlantedRecord[] { return this.records.filter((r) => r.state === "planted").reverse(); }
  summary(): { planted: number; deleted: number; left: { route: string; why: string }[] } {
    return {
      planted: this.records.length,
      deleted: this.records.filter((r) => r.state === "deleted" || r.state === "gone").length,
      left: this.records.filter((r) => r.state === "left" || r.state === "planted").map((r) => ({ route: r.deleteRoute, why: r.left ?? "not deleted yet" })),
    };
  }
}

export type PlantResult = { ok: true; record: PlantedRecord } | { ok: false; why: "no_account" | "forbidden_path" | "create_failed" | "no_id"; status?: number };

/** Role `role` creates its own test record with a fresh marker in it. The record is registered for clean-up at once. */
export async function plantMarker(io: EngageIo, registry: MarkerRegistry, role: MarkerRole, spec: PlantSpec, readId: (body: string, path: string) => string): Promise<PlantResult> {
  // A record that could not be deleted again is never created.
  const allowed = io.pathAllowed ?? (() => true);
  if (!allowed(spec.create.path) || !allowed(spec.delete) || (spec.read && !allowed(spec.read))) return { ok: false, why: "forbidden_path" };
  const marker = registry.next(role);
  const r = await io.send(role, "POST", spec.create.path, { body: fill(spec.create.body, { marker }), purpose: "create", cls: "write_own_test_records", leg: "plant" });
  if (r === null) return { ok: false, why: "no_account" };
  if (!ok(r.status)) return { ok: false, why: "create_failed", status: r.status };
  const id = readId(r.body, spec.idPath);
  if (!id || id.length > 200) return { ok: false, why: "no_id", status: r.status };
  io.own(id);
  return { ok: true, record: registry.register(marker, { id, createRoute: spec.create.path, readRoute: spec.read ?? null, deleteRoute: spec.delete }) };
}

/**
 * Delete what this run planted, newest first, and nothing else. Each record is deleted by the role that created it.
 * Where the record can be read, it is read first: a 404 or 410 means it is gone already; an answer without the marker
 * means the id no longer names the run's record, and it is LEFT (never deleted on a guess).
 */
export async function cleanUpMarkers(io: EngageIo, registry: MarkerRegistry, opts: { deadline?: number; now?: () => number } = {}): Promise<ReturnType<MarkerRegistry["summary"]>> {
  const now = opts.now ?? Date.now;
  for (const rec of registry.pending()) {
    if (opts.deadline !== undefined && now() >= opts.deadline) { rec.state = "left"; rec.left = "the clean-up ran out of time"; continue; }
    try {
      if (rec.readRoute) {
        const seen = await io.send(rec.role, "GET", withId(rec.readRoute, rec.id), { purpose: "cleanup", cls: "read", leg: "cleanup" });
        if (seen && (seen.status === 404 || seen.status === 410)) { rec.state = "gone"; continue; }
        if (seen && ok(seen.status) && !seen.body.includes(rec.marker)) { rec.state = "left"; rec.left = "the record no longer holds the run's marker, so it was not deleted"; continue; }
      }
      const d = await io.send(rec.role, "DELETE", withId(rec.deleteRoute, rec.id), { purpose: "cleanup", cls: "write_own_test_records", leg: "cleanup" });
      if (d && (ok(d.status) || d.status === 404 || d.status === 410)) rec.state = d.status === 404 || d.status === 410 ? "gone" : "deleted";
      else { rec.state = "left"; rec.left = d ? `the delete request answered ${d.status}` : "the account that created it could not be used"; }
    } catch (e) {
      rec.state = "left"; rec.left = e instanceof Error ? e.message.slice(0, 160) : "the delete request failed";
    }
  }
  return registry.summary();
}
