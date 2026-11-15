/**
 * yof engagement, attack library: ACCESS. Who may read and change whose records.
 *
 *   access.id_swap          another tenant's account asks for the owner's record by its id
 *   access.anon_read        nobody signed in asks for it
 *   access.role_swap        a member asks an admin route for the admin's record
 *   access.sequential_id    the same swap, where ids are numbers that follow each other (so any record can be asked for)
 *   access.id_moved         the id travels somewhere else: a query or a body instead of the path
 *   access.cross_write      another tenant's account changes the owner's record
 *   access.method_override  the change is refused, then sent again as a POST with a method-override header
 *   access.content_type     the change is refused as JSON, then sent again as a form or as plain text
 *
 * THE ORACLE is a planted marker with both controls (../differential.ts): the owner reads its own marker, the other
 * account gets it with the identical request, an id that does not exist is refused in a different way, and it shows
 * twice. For a write, the proof is what the OWNER reads afterwards: the other account's own new marker in the owner's
 * record, with the same write refused when nobody is signed in.
 *
 * What these cannot show: anything about records the run did not create. Only the run's own test records are read
 * and changed, and they are deleted at the end.
 */
import type { ReplaySpec } from "../../replay";
import type { MarkerRole } from "../markers";
import { deleteStep, notTestable, plant, plantStep, readDifferential, replayPath, result, specOf, stepOf, writeDifferential, type Filled, type ReadSeen, type WriteSeen } from "./kit";
import { payload, payloadsOf } from "./payloads";
import type { ImpactFacts, RequestSpec, Technique, TechniqueContext, TechniqueResult, TechniqueTarget, TestObject } from "./types";
import { EVIDENCE } from "./words";

const READ_OTHER: ImpactFacts = { what: "read", position: "self_registered", reach: "one_object", data: "ordinary" };
const WRITE_OTHER: ImpactFacts = { what: "write", position: "self_registered", reach: "one_object", data: "ordinary" };
type Head = Omit<Technique, "run" | "chain">;

const readChain = (t: Pick<Technique, "ruleId" | "title">, owner: MarkerRole, other: "a" | "b" | "anon", o: TestObject, req: RequestSpec, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, ["marker"], accounts, [
    plantStep(owner, o),
    stepOf(other, req, { leg: "test", expect: { kind: "marker_absent", value: "{{marker}}" } }),
    stepOf(owner, req, { leg: "positive", expect: { kind: "marker_present", value: "{{marker}}" } }),
    deleteStep(owner, o),
  ]);
const writeChain = (t: Pick<Technique, "ruleId" | "title">, o: TestObject, write: RequestSpec, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, ["marker", "changed"], accounts, [
    plantStep("a", o),
    stepOf("b", { ...write, body: (write.body ?? "").split("{{marker}}").join("{{changed}}") }),
    { as: "a", method: "GET", path: replayPath(o.read), expect: { kind: "not_contains", value: "{{changed}}" } },
    deleteStep("a", o),
  ]);

function fromRead(t: Head, seen: ReadSeen, as: "a" | "b" | "anon", evidence: (shape: string) => string, replay: ReplaySpec | null, impact: ImpactFacts, meta: Record<string, string> = {}): TechniqueResult {
  const shown = seen.outcome === "violated" || seen.outcome === "needs_validation";
  return result(t, seen.outcome, {
    reason: seen.reason, demonstrated: seen.demonstrated, method: seen.method, route: seen.route, as, status: seen.status, marker: seen.marker,
    evidence: evidence(seen.shape), meta: { proof: "marker", ...meta }, replay: shown ? replay : null, impact,
  });
}
function fromWrite(t: Head, seen: WriteSeen, evidence: string, replay: ReplaySpec | null, payloadId: string | null = null): TechniqueResult {
  return result(t, seen.outcome, {
    reason: seen.reason, demonstrated: seen.demonstrated, method: seen.method, route: seen.route, as: "b", status: seen.status, marker: seen.marker,
    evidence, meta: { proof: "marker", ...(seen.controls ? { controls: seen.controls } : {}), ...(payloadId ? { payload: payloadId } : {}) }, replay, payload: payloadId, impact: WRITE_OTHER,
  });
}

const ID_SWAP: Head = {
  id: "access.id_swap", ruleId: "attack.tenant_read", title: "One user can read another user's records by changing the id",
  invariants: ["tenant_read"], prerequisites: ["account_a", "account_b", "test_object"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: [],
  oracle: "Account B's request for account A's test record returns A's planted marker; A reads it too; an id that does not exist is refused differently; it shows twice.",
  shows: "that another tenant's account can read a record by its id", cannotShow: "which other records can be read: only the run's own test record is asked for",
  best: "confirmed", markerRead: true, impact: READ_OTHER, owasp: "A01 / API1",
};
const ANON_READ: Head = {
  id: "access.anon_read", ruleId: "attack.auth_bypass", title: "A signed-in route answers without a sign-in",
  invariants: ["auth_required"], prerequisites: ["account_a", "test_object"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: [],
  oracle: "A request with no sign-in for account A's test record returns A's planted marker, with both controls, twice.",
  shows: "that the record can be read by anyone who has its address", cannotShow: "whether other routes need a sign-in",
  best: "confirmed", markerRead: true, impact: { ...READ_OTHER, position: "anonymous" }, owasp: "A07 / API2",
};
const ROLE_SWAP: Head = {
  id: "access.role_swap", ruleId: "attack.rbac_escalation", title: "A normal member can open admin routes",
  invariants: ["role_gate"], prerequisites: ["account_a", "account_admin", "test_object", "admin_route"], safetyClass: "write_own_test_records", classes: ["read", "write_own_test_records"], payloads: [],
  oracle: "A member's request to the admin route returns a marker the admin account planted in its own test record, with both controls, twice.",
  shows: "that a member gets the admin route's answer", cannotShow: "what else the admin route would let a member do",
  best: "confirmed", markerRead: true, impact: { what: "privilege_gain", position: "same_tenant_member", reach: "all_tenants", data: "ordinary" }, owasp: "A01 / API5",
};
const SEQUENTIAL: Head = {
  ...ID_SWAP, id: "access.sequential_id",
  oracle: "Two test records of account A get ids that follow each other, and account B reads the second one by counting on from the first, with both controls, twice.",
  shows: "that record ids can be guessed by counting, and a guessed id is answered", cannotShow: "how many records exist",
  impact: { ...READ_OTHER, reach: "any_object_by_id" },
};
const ID_MOVED: Head = {
  ...ID_SWAP, id: "access.id_moved", classes: ["read", "write_own_test_records", "write_cross_account_test_records"],
  oracle: "Account B's request with account A's id in a query or a body (instead of the path) returns A's planted marker, with both controls, twice.",
  shows: "that the check on the path is missing where the id travels another way", cannotShow: "routes the app model does not list",
};
const CROSS_WRITE: Head = {
  id: "access.cross_write", ruleId: "attack.tenant_write", title: "One user can change another user's records",
  invariants: ["tenant_write"], prerequisites: ["account_a", "account_b", "test_object", "object_update"], safetyClass: "write_cross_account_test_records", classes: ["read", "write_own_test_records", "write_cross_account_test_records"], payloads: [],
  oracle: "Account A reads account B's new marker in A's own test record after B's request; the same request with no sign-in is refused; it shows twice.",
  shows: "that another tenant's account can change a record by its id", cannotShow: "whether it can also be deleted (a delete of another account's record is never sent)",
  best: "confirmed", impact: WRITE_OTHER, owasp: "A01 / API1",
};
const OVERRIDE: Head = {
  ...CROSS_WRITE, id: "access.method_override", invariants: ["tenant_write", "role_gate"], payloads: payloadsOf("method_override"),
  oracle: "Account B's plain change of account A's test record is refused; the same change as a POST with a method-override header is then seen by A in its own record; with no sign-in it is refused; twice.",
  shows: "that the access check looks at the method and a header changes the method after it", cannotShow: "other headers than the three in the payload list",
};
const CONTENT_TYPE: Head = {
  ...CROSS_WRITE, id: "access.content_type", payloads: payloadsOf("content_type"),
  oracle: "Account B's JSON change of account A's test record is refused; the same change sent as a form or as plain text is then seen by A in its own record; with no sign-in it is refused; twice.",
  shows: "that the access check runs only for JSON requests", cannotShow: "content types outside the payload list",
};

/** The first top-level field of a JSON body template whose value is the marker: the field a form carries. */
export function markerField(body: string): string | null {
  try {
    const v = JSON.parse(body.split("{{marker}}").join("YOFMARKERSLOT").replace(/\{\{\w+\}\}/g, "x")) as Record<string, unknown>;
    return Object.keys(v).find((k) => v[k] === "YOFMARKERSLOT") ?? null;
  } catch { return null; }
}
const asForm = (field: string) => (f: Filled): Filled => {
  let value = "";
  try { value = String((JSON.parse(f.body ?? "{}") as Record<string, unknown>)[field] ?? ""); } catch { value = ""; }
  return { ...f, body: `${encodeURIComponent(field)}=${encodeURIComponent(value)}` };
};

async function runRead(t: Head, ctx: TechniqueContext, target: TechniqueTarget, owner: MarkerRole, other: "a" | "b" | "anon", evidence: (s: string) => string): Promise<TechniqueResult> {
  if (!target.object) return notTestable(t, "the app model names no test record for this");
  const seen = await readDifferential(ctx, { owner, other, object: target.object });
  return fromRead(t, seen, other, evidence, readChain(t, owner, other, target.object, { method: "GET", path: target.object.read }, ctx.accounts), t.impact);
}

export const ACCESS_TECHNIQUES: readonly Technique[] = [
  {
    ...ID_SWAP,
    chain: (target, accounts) => (target.object ? readChain(ID_SWAP, "a", "b", target.object, { method: "GET", path: target.object.read }, accounts) : null),
    run: (ctx, target) => runRead(ID_SWAP, ctx, target, "a", "b", EVIDENCE.tenantRead),
  },
  {
    ...ANON_READ,
    chain: (target, accounts) => (target.object ? readChain(ANON_READ, "a", "anon", target.object, { method: "GET", path: target.object.read }, accounts) : null),
    run: (ctx, target) => runRead(ANON_READ, ctx, target, "a", "anon", EVIDENCE.anonRead),
  },
  {
    ...ROLE_SWAP,
    chain: (target, accounts) => (target.object && target.adminRoute ? readChain(ROLE_SWAP, "admin", "a", target.object, { method: "GET", path: target.adminRoute }, accounts) : null),
    run: async (ctx, target) => {
      if (!target.object || !target.adminRoute) return notTestable(ROLE_SWAP, "the app model names no admin route that shows a test record");
      const req: RequestSpec = { method: "GET", path: target.adminRoute };
      const seen = await readDifferential(ctx, { owner: "admin", other: "a", object: target.object, request: req });
      return fromRead(ROLE_SWAP, seen, "a", EVIDENCE.adminRead, readChain(ROLE_SWAP, "admin", "a", target.object, req, ctx.accounts), ROLE_SWAP.impact, { adminRoute: target.adminRoute });
    },
  },
  {
    ...SEQUENTIAL,
    chain: (target, accounts) => (target.object ? readChain(SEQUENTIAL, "a", "b", target.object, { method: "GET", path: target.object.read }, accounts) : null),
    run: async (ctx, target) => {
      if (!target.object) return notTestable(SEQUENTIAL, "the app model names no test record for this");
      const first = await plant(ctx, "a", target.object);
      if (!first.ok) return notTestable(SEQUENTIAL, (first as { why: string }).why);
      const second = await plant(ctx, "a", target.object);
      if (!second.ok) return notTestable(SEQUENTIAL, (second as { why: string }).why);
      const a = first.record.id, b = second.record.id;
      const gap = /^\d{1,15}$/.test(a) && /^\d{1,15}$/.test(b) ? Number(b) - Number(a) : NaN;
      if (!(gap >= 1 && gap <= 3)) return result(SEQUENTIAL, "held", { reason: "the ids of two new records do not follow each other, so an id cannot be found by counting", route: target.object.read });
      // Account B counts on from the first id; the request it sends is for the id it computed, not one it was given.
      const computed = String(Number(a) + gap);
      const seen = await readDifferential(ctx, { owner: "a", other: "b", object: target.object, record: { ...second.record, id: computed } });
      return fromRead(SEQUENTIAL, seen, "b", EVIDENCE.sequentialIds, readChain(SEQUENTIAL, "a", "b", target.object, { method: "GET", path: target.object.read }, ctx.accounts), SEQUENTIAL.impact, { kind: "sequential ids" });
    },
  },
  {
    ...ID_MOVED,
    chain: (target, accounts) => (target.object?.alternates?.[0] ? readChain(ID_MOVED, "a", "b", target.object, target.object.alternates[0], accounts) : null),
    run: async (ctx, target) => {
      const alts = target.object?.alternates ?? [];
      if (!target.object || !alts.length) return notTestable(ID_MOVED, "the app model names no route that takes the id in a query or a body");
      let last: TechniqueResult | null = null;
      for (const req of alts.slice(0, 4)) {
        const seen = await readDifferential(ctx, { owner: "a", other: "b", object: target.object, request: req });
        last = fromRead(ID_MOVED, seen, "b", EVIDENCE.tenantRead, readChain(ID_MOVED, "a", "b", target.object, req, ctx.accounts), ID_MOVED.impact, { param: req.body !== undefined ? "id in the body" : "id in the query" });
        if (last.outcome === "violated" || last.outcome === "needs_validation") return last;
      }
      return last!;
    },
  },
  {
    ...CROSS_WRITE,
    chain: (target, accounts) => (target.object?.update ? writeChain(CROSS_WRITE, target.object, target.object.update, accounts) : null),
    run: async (ctx, target) => {
      const o = target.object;
      if (!o?.update) return notTestable(CROSS_WRITE, "the app model names no way to change the test record");
      const seen = await writeDifferential(ctx, { owner: "a", other: "b", object: o, write: o.update });
      return fromWrite(CROSS_WRITE, seen, EVIDENCE.crossWrite(seen.controls), writeChain(CROSS_WRITE, o, o.update, ctx.accounts));
    },
  },
  {
    ...OVERRIDE,
    chain: (target, accounts) => {
      const u = target.object?.update;
      return target.object && u ? writeChain(OVERRIDE, target.object, { method: "POST", path: u.path, body: u.body, headers: { [payload(OVERRIDE.payloads[0]!).value]: u.method } }, accounts) : null;
    },
    run: async (ctx, target) => {
      const o = target.object;
      if (!o?.update) return notTestable(OVERRIDE, "the app model names no way to change the test record");
      let last: TechniqueResult | null = null;
      for (const id of OVERRIDE.payloads) {
        const header = payload(id).value;
        const write: RequestSpec = { method: "POST", path: o.update.path, body: o.update.body, headers: { [header]: o.update.method } };
        const seen = await writeDifferential(ctx, { owner: "a", other: "b", object: o, write, direct: o.update });
        last = fromWrite(OVERRIDE, seen, EVIDENCE.overrideWrite(header), writeChain(OVERRIDE, o, write, ctx.accounts), id);
        if (seen.outcome !== "held") return last;
      }
      return last!;
    },
  },
  {
    ...CONTENT_TYPE, chainLimit: "A generated regression test sends every body as JSON, so it repeats the plain change only. `yof attack replay` sends the other content type.",
    chain: (target, accounts) => {
      const u = target.object?.update;
      return target.object && u ? writeChain(CONTENT_TYPE, target.object, { ...u, headers: { "Content-Type": payload("ctype.text").value } }, accounts) : null;
    },
    run: async (ctx, target) => {
      const o = target.object;
      if (!o?.update) return notTestable(CONTENT_TYPE, "the app model names no way to change the test record");
      const field = markerField(o.update.body);
      let last: TechniqueResult | null = null;
      for (const id of CONTENT_TYPE.payloads) {
        if (id === "ctype.form" && !field) continue;
        const type = payload(id).value;
        const write: RequestSpec = { ...o.update, headers: { "Content-Type": type } };
        const seen = await writeDifferential(ctx, { owner: "a", other: "b", object: o, write, direct: o.update, ...(id === "ctype.form" ? { shape: asForm(field!) } : {}) });
        last = fromWrite(CONTENT_TYPE, seen, EVIDENCE.contentTypeWrite(type), writeChain(CONTENT_TYPE, o, write, ctx.accounts), id);
        if (seen.outcome !== "held") return last;
      }
      return last ?? notTestable(CONTENT_TYPE, "the change carries no field a form could hold");
    },
  },
];
