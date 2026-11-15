/**
 * yof engagement, attack library: MASS ASSIGNMENT. Extra fields sent when the tester creates or changes its OWN
 * test record: role, is_admin, the owner id, price, the verified flags (the fixed list in ./payloads.ts, plus field
 * NAMES the app model says are locked; a value is never taken from anywhere but the list).
 *
 *   mass_assign.update   the fields ride along with an ordinary change of the record
 *   mass_assign.create   the fields ride along when the record is created
 *
 * THE ORACLE: the owner reads the record again, and a field shows the value the request set, which it did not have
 * before. What that is worth depends on the field, by rule:
 *   a rights or trust field the record already had (role, is_admin, verified, the owner id), or any field the app
 *   model says is locked                                        -> violated
 *   a money or state field the model does not list (price, status, plan): some apps let the owner set those
 *                                                               -> needs validation
 *   a field the record did not have before and the app simply stored  -> needs validation
 *
 * An owner field is sent only when the record already shows it, and is put back afterwards so the record can be
 * deleted. What this cannot show: what the changed field lets the account do afterwards. Nothing is tried with it.
 */
import type { ReplaySpec } from "../../replay";
import { missingIdLike } from "../differential";
import { deleteStep, fillRequest, notTestable, ok, plant, plantStep, replayPath, result, sendRequest, specOf, unusable } from "./kit";
import { PAYLOADS, payload } from "./payloads";
import type { ImpactFacts, Technique, TechniqueContext, TechniqueResult, TechniqueTarget, TestObject } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "privilege_gain", position: "self_registered", reach: "one_object", data: "ordinary" };
const FIELD_PAYLOADS = PAYLOADS.filter((p) => p.family === "locked_field" || p.family === "owner_field" || p.family === "value_field").filter((p) => p.id !== "field.model");
/** Sent even when the record does not show them yet. */
const ALWAYS = ["role", "is_admin", "verified", "price"];
export const MAX_FIELDS = 12;

/** A field of a JSON answer by name: at the top, or one or two objects down (data, record, item). JSON text, or undefined. */
export function fieldIn(body: string, name: string): string | undefined {
  let v: unknown;
  try { v = JSON.parse(body); } catch { return undefined; }
  const look = (x: unknown, depth: number): string | undefined => {
    if (!x || typeof x !== "object" || Array.isArray(x)) return undefined;
    const o = x as Record<string, unknown>;
    if (name in o) return JSON.stringify(o[name]);
    if (depth >= 2) return undefined;
    for (const k of Object.keys(o).slice(0, 20)) { const r = look(o[k], depth + 1); if (r !== undefined) return r; }
    return undefined;
  };
  return look(v, 0);
}

export interface FieldPlan { name: string; payload: string; value: string; kind: "locked" | "owner" | "value" | "model" }
/** Which fields to send, and with which value, given what the record shows now. Pure. */
export function planFields(baseline: string, modelFields: readonly string[], random: () => string): FieldPlan[] {
  const out: FieldPlan[] = [];
  const add = (name: string, id: string, kind: FieldPlan["kind"], raw: string) => {
    if (out.length >= MAX_FIELDS || out.some((x) => x.name === name)) return;
    const now = fieldIn(baseline, name);
    let value = raw;
    if (raw === "{missing}") {
      if (now === undefined) return;
      let cur: unknown; try { cur = JSON.parse(now); } catch { return; }
      if (typeof cur !== "string" && typeof cur !== "number") return;
      const gone = missingIdLike(String(cur), random);
      value = typeof cur === "number" ? String(Number(gone.slice(0, 12))) : JSON.stringify(gone);
    } else if (now === value) {
      // The record already holds the list's value: a number moves on by 7, anything else cannot show a change.
      let cur: unknown; try { cur = JSON.parse(now); } catch { return; }
      if (typeof cur !== "number") return;
      value = String(cur + 7);
    }
    out.push({ name, payload: id, value, kind });
  };
  for (const name of modelFields.filter((n) => /^[A-Za-z_][A-Za-z0-9_]{0,39}$/.test(n))) {
    const known = FIELD_PAYLOADS.find((p) => p.note === name);
    add(name, known?.id ?? "field.model", "model", known && known.value !== "{missing}" ? known.value : known ? "{missing}" : payload("field.model").value);
  }
  for (const p of FIELD_PAYLOADS) {
    const present = fieldIn(baseline, p.note) !== undefined;
    if (!present && (p.family === "owner_field" || !ALWAYS.includes(p.note))) continue;
    add(p.note, p.id, p.family === "owner_field" ? "owner" : p.family === "value_field" ? "value" : "locked", p.value);
  }
  return out;
}

export type FieldVerdict = "set" | "added" | "unchanged";
/** Did the field take the value the request set? Pure. */
export function fieldVerdict(before: string, after: string, f: FieldPlan): FieldVerdict {
  const was = fieldIn(before, f.name), is = fieldIn(after, f.name);
  if (is === undefined || is !== f.value || was === is) return "unchanged";
  return was === undefined ? "added" : "set";
}
/** A JSON body template with extra fields merged in ({{marker}} kept). null when the template is not a JSON object. */
export function withFields(template: string, fields: readonly FieldPlan[]): string | null {
  const SLOT = "YOFSLOT7331";
  try {
    const names: string[] = [];
    const v = JSON.parse(template.replace(/\{\{(\w+)\}\}/g, (_m, k: string) => { names.push(k); return `${SLOT}${names.length - 1}${SLOT}`; })) as unknown;
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    const merged = { ...(v as Record<string, unknown>) };
    for (const f of fields) merged[f.name] = JSON.parse(f.value) as unknown;
    return JSON.stringify(merged).replace(new RegExp(`${SLOT}(\\d+)${SLOT}`, "g"), (_m, i: string) => `{{${names[Number(i)]}}}`);
  } catch { return null; }
}

function judge(t: Technique | Omit<Technique, "run" | "chain">, o: TestObject, fields: FieldPlan[], before: string, after: string, status: number, route: string, method: "POST" | "PATCH" | "PUT", accounts: ReplaySpec["accounts"] | undefined): TechniqueResult {
  const seen = fields.map((f) => ({ f, v: fieldVerdict(before, after, f) })).filter((x) => x.v !== "unchanged");
  if (!seen.length) return result(t, "held", { reason: "no extra field took the value the request set", method, route, as: "a", status });
  const locked = new Set(o.lockedFields ?? []);
  const strong = seen.find((x) => x.v === "set" && (x.f.kind === "locked" || x.f.kind === "owner" || locked.has(x.f.name))) ?? seen.find((x) => locked.has(x.f.name));
  const pick = strong ?? seen[0]!;
  const names = seen.map((x) => x.f.name).join(", ").slice(0, 200);
  return result(t, strong ? "violated" : "needs_validation", {
    reason: strong ? "a field a member may not set took the value the request set, read back by the owner" : pick.v === "added" ? "the app stored a field the record did not have; whether that matters depends on what the app does with it" : "the field changed, but the app model does not say it is locked: some apps let the owner set it",
    method, route, as: "a", status, payload: pick.f.payload, evidence: pick.v === "added" ? EVIDENCE.fieldAdded(pick.f.name) : EVIDENCE.fieldSet(pick.f.name),
    meta: { field: pick.f.name, payload: pick.f.payload, kind: names }, replay: chainFor(t, o, method === "POST" ? "create" : "update", pick.f.name, accounts), impact: IMPACT,
  });
}

function chainFor(t: Pick<Technique, "ruleId" | "title">, o: TestObject, how: "create" | "update", field: string, accounts?: ReplaySpec["accounts"]): ReplaySpec | null {
  const extra: FieldPlan[] = [{ name: field, payload: "field.model", value: JSON.stringify("YOFCHANGEDSLOT"), kind: "model" }];
  const put = (body: string | null) => body?.split("YOFCHANGEDSLOT").join("{{changed}}") ?? null;
  if (how === "create") {
    const body = put(withFields(o.create.body, extra));
    if (!body) return null;
    return specOf(t, ["marker", "changed"], accounts, [
      { ...plantStep("a", o), body },
      { as: "a", method: "GET", path: replayPath(o.read), expect: { kind: "not_contains", value: "{{changed}}" } },
      deleteStep("a", o),
    ]);
  }
  const body = o.update ? put(withFields(o.update.body, extra)) : null;
  if (!o.update || !body) return null;
  return specOf(t, ["marker", "changed"], accounts, [
    plantStep("a", o),
    { as: "a", method: o.update.method, path: replayPath(o.update.path), body },
    { as: "a", method: "GET", path: replayPath(o.read), expect: { kind: "not_contains", value: "{{changed}}" } },
    deleteStep("a", o),
  ]);
}
const CHAIN_LIMIT = "The replay sets the field to a text value. An app that accepts only the field's own type (a number, yes or no) is not re-tested by the replay.";

const HEAD = {
  ruleId: "attack.mass_assignment", title: "A member can set fields that only the server should set",
  invariants: ["field_locked"] as const, safetyClass: "write_own_test_records" as const, classes: ["read", "write_own_test_records"] as const,
  payloads: FIELD_PAYLOADS.map((p) => p.id).concat("field.model"), best: "confirmed" as const, impact: IMPACT, owasp: "A04 / API3", chainLimit: CHAIN_LIMIT,
  shows: "that the server stores a field the request should not be able to set", cannotShow: "what the changed field allows afterwards: nothing is tried with it",
};

async function readOwn(ctx: TechniqueContext, o: TestObject, id: string): Promise<{ status: number; body: string } | null> {
  const r = await ctx.io.send("a", "GET", o.read.split("{id}").join(encodeURIComponent(id)), { purpose: "read", cls: "read", leg: "positive" });
  return unusable(r) ? null : { status: r!.status, body: r!.body };
}

export const MASS_ASSIGN_TECHNIQUES: readonly Technique[] = [
  {
    ...HEAD, id: "mass_assign.update", prerequisites: ["account_a", "test_object", "object_update"],
    oracle: "The owner changes its own test record with extra fields in the request, reads it again, and a field shows the value the request set, which it did not have before.",
    chain: (target, accounts) => (target.object ? chainFor(HEAD, target.object, "update", "role", accounts) : null),
    run: async (ctx, target) => {
      const t = MASS_ASSIGN_TECHNIQUES[0]!;
      const o = target.object;
      if (!o?.update) return notTestable(t, "the app model names no way to change the test record");
      const planted = await plant(ctx, "a", o);
      if (!planted.ok) return notTestable(t, (planted as { why: string }).why);
      const rec = planted.record;
      const before = await readOwn(ctx, o, rec.id);
      if (!before || !ok(before.status)) return notTestable(t, "the owner could not read its own new record");
      const fields = planFields(before.body, o.lockedFields ?? [], ctx.random);
      const body = withFields(o.update.body, fields);
      if (!fields.length || !body) return notTestable(t, "the change request is not a JSON object the fields could ride along with");
      const route = o.update.path.split("?")[0]!;
      const vars = { id: rec.id, marker: rec.marker };
      let sent = await sendRequest(ctx, "a", fillRequest({ ...o.update, body }, vars), { cls: "write_own_test_records", leg: "test" }, [rec.id]);
      let used = fields;
      if (sent && !ok(sent.status)) {
        // The app refused the whole request. One field at a time, the first few: a strict app refuses each of them too.
        for (const f of fields.slice(0, 4)) {
          const one = withFields(o.update.body, [f]);
          if (!one) continue;
          const r = await sendRequest(ctx, "a", fillRequest({ ...o.update, body: one }, vars), { cls: "write_own_test_records", leg: "test" }, [rec.id]);
          if (r && ok(r.status)) { sent = r; used = [f]; break; }
        }
      }
      if (sent === null) return notTestable(t, "the test account is not set, or its sign-in failed");
      const after = await readOwn(ctx, o, rec.id);
      let out: TechniqueResult;
      if (!after) out = notTestable(t, "the owner's own read got no usable answer");
      else if (!ok(after.status)) out = result(t, "needs_validation", { reason: "the owner could no longer read its record after the request; the record may have been moved to another owner", method: o.update.method, route, as: "a", status: sent.status, evidence: EVIDENCE.fieldSet(used.find((f) => f.kind === "owner")?.name ?? used[0]!.name), meta: { field: used[0]!.name }, impact: IMPACT });
      else out = judge(t, o, used, before.body, after.body, sent.status, route, o.update.method, ctx.accounts);
      // Put an owner field back, so the record is the test account's again and the clean-up can delete it.
      const moved = after && ok(after.status) ? used.filter((f) => f.kind === "owner" && fieldVerdict(before.body, after.body, f) !== "unchanged") : [];
      if (moved.length) {
        const back = withFields(o.update.body, moved.map((f) => ({ ...f, value: fieldIn(before.body, f.name) ?? "null" })));
        if (back) await sendRequest(ctx, "a", fillRequest({ ...o.update, body: back }, vars), { cls: "write_own_test_records", leg: "cleanup" }, [rec.id]).catch(() => null);
      }
      return out;
    },
  },
  {
    ...HEAD, id: "mass_assign.create", prerequisites: ["account_a", "test_object"],
    oracle: "The owner creates one test record the ordinary way and one with extra fields in the request, reads both, and a field of the second shows the value the request set where the first does not.",
    chain: (target, accounts) => (target.object ? chainFor(HEAD, target.object, "create", "role", accounts) : null),
    run: async (ctx, target) => {
      const t = MASS_ASSIGN_TECHNIQUES[1]!;
      const o = target.object;
      if (!o) return notTestable(t, "the app model names no test record for this");
      const plain = await plant(ctx, "a", o);
      if (!plain.ok) return notTestable(t, (plain as { why: string }).why);
      const before = await readOwn(ctx, o, plain.record.id);
      if (!before || !ok(before.status)) return notTestable(t, "the owner could not read its own new record");
      // An owner field is never sent at creation: a record created for somebody else could not be deleted again.
      const fields = planFields(before.body, o.lockedFields ?? [], ctx.random).filter((f) => f.kind !== "owner" && !/(?:^|_)(?:owner|user|workspace|tenant|org)_?id$/i.test(f.name));
      const body = withFields(o.create.body, fields);
      if (!fields.length || !body) return notTestable(t, "the create request is not a JSON object the fields could ride along with");
      const extra = await plant(ctx, "a", { ...o, create: { path: o.create.path, body } });
      if (!extra.ok) return result(t, "held", { reason: "the app refused to create a record with the extra fields", method: "POST", route: o.create.path, as: "a" });
      const after = await readOwn(ctx, o, extra.record.id);
      if (!after || !ok(after.status)) return notTestable(t, "the owner could not read the record it created with the extra fields");
      return judge(t, o, fields, before.body, after.body, 201, o.create.path, "POST", ctx.accounts);
    },
  },
];
