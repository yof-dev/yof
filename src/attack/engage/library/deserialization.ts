/**
 * yof engagement, attack library: UNSAFE DESERIALIZATION. A content type or a body shape that a known unsafe
 * deserializer recognises, sent to a route that takes a body. Nothing here executes code: the payloads are a harmless
 * object stream (one text, an empty object, the value None) or a type hint for a plain object. A hit is a recognisable
 * ERROR SIGNATURE of an object deserializer that an ordinary value did not bring, or a type hint the server answered.
 *
 *   deserial.object_stream   a serialized blob (Java, PHP, Python pickle, YAML tag) with its own content type
 *   deserial.type_hint       a JSON body that names a type ($type, a Jackson type array) with a unique word
 *
 * WHAT THIS CANNOT SHOW: that a crafted object would run. It never sends a gadget chain, a class that does anything,
 * or anything that reads a file or the environment. So every result is "needs validation": the sign is that the
 * value reached a deserializer, not that the deserializer can be driven. The record forbids running anything on the
 * server; these payloads carry nothing to run.
 */
import type { HttpAnswer } from "../../http";
import type { ReplaySpec } from "../../replay";
import { notTestable, ok, replayPath, result, routeOf, specOf, unusable } from "./kit";
import { DESERIALIZATION_TYPES, fillPayload, payloadsOf } from "./payloads";
import type { ImpactFacts, InputSpec, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" };
const NEEDS_INPUT = "the app model names no route that takes a body for this";

/** The error messages a known unsafe object deserializer prints when it is handed a shape it half-understands. Pure. */
export const DESERIALIZER_ERRORS: readonly { name: string; re: RegExp }[] = [
  { name: "java_object_stream", re: /java\.io\.(?:StreamCorrupted|InvalidClass|OptionalData|WriteAborted)Exception|invalid stream header|ObjectInputStream|readObject/ },
  { name: "php_unserialize", re: /unserialize\(\)[^\n]{0,80}(?:Error at offset|expects parameter)|__PHP_Incomplete_Class/ },
  { name: "python_pickle", re: /_?pickle\.(?:Unpickling|Pickling)Error|UnpicklingError|invalid load key|STACK_GLOBAL/ },
  { name: "yaml_constructor", re: /yaml\.(?:constructor|parser|scanner)|could not determine a constructor for the tag|ConstructorError/ },
  { name: "dotnet_type", re: /Newtonsoft\.Json[^\n]{0,80}(?:TypeNameHandling|JsonSerializationException)|Could not load (?:type|assembly)|System\.Runtime\.Serialization/ },
  { name: "jackson_type", re: /com\.fasterxml\.jackson[^\n]{0,80}|could not resolve type id|InvalidTypeIdException|default typing/ },
];
/** The deserializer whose error an answer holds, or null. Pure. */
export const deserializerError = (body: string): string | null => DESERIALIZER_ERRORS.find((s) => s.re.test(body.slice(0, 60_000)))?.name ?? null;

type Head = Omit<Technique, "run" | "chain">;
const base = {
  ruleId: "attack.unsafe_deserializer", title: "The app hands a request body to an unsafe reader of objects",
  invariants: ["input_is_data"] as const, prerequisites: ["account_a", "text_input"] as const,
  safetyClass: "write_own_test_records" as const, classes: ["read", "write_own_test_records"] as const,
  best: "needs_validation" as const, impact: IMPACT, owasp: "A08 / API8",
  shows: "that the body reached a reader that tries to rebuild objects from it",
  cannotShow: "that a crafted object would run: no gadget, no class that does anything, nothing that reads a file is ever sent",
  chainLimit: "A generated regression test sends every body as JSON and cannot set a content type, so it only checks that a plain value is not answered with a deserializer error. `yof attack replay` sends the typed body.",
};
const OBJECT_STREAM: Head = {
  ...base, id: "deserial.object_stream", payloads: payloadsOf("object_stream"),
  oracle: "A harmless object stream (Java, PHP, pickle or a YAML tag), sent with the content type that reader expects, brings back a deserializer's own error message that an ordinary value does not; shown twice.",
};
const TYPE_HINT: Head = {
  ...base, id: "deserial.type_hint", payloads: payloadsOf("type_hint"),
  oracle: "A JSON body that names a type ($type or a Jackson type array) with a unique word brings back a deserializer's own error message, or the unique word parsed through the typed structure, that an ordinary value does not; shown twice.",
};

/** Send one serialized body to the input's route, with the content type the payload declares. */
async function sendBlob(ctx: TechniqueContext, input: InputSpec, id: string, body: string): Promise<HttpAnswer | null> {
  const r = input.request;
  const type = DESERIALIZATION_TYPES[id] ?? "application/octet-stream";
  return ctx.io.send(input.as ?? "a", r.method === "GET" || r.method === "HEAD" ? "POST" : r.method, routeOf(r.path), {
    body, headers: { "Content-Type": type }, purpose: "create", cls: "write_own_test_records", leg: "test",
  });
}
const chain = (t: Pick<Technique, "ruleId" | "title">, input: InputSpec, id: string, accounts?: ReplaySpec["accounts"]): ReplaySpec =>
  specOf(t, [], accounts, [{
    as: input.as ?? "a", method: input.request.method === "GET" || input.request.method === "HEAD" ? "POST" : input.request.method,
    path: replayPath(routeOf(input.request.path)), body: fillPayload(id), headers: { "Content-Type": DESERIALIZATION_TYPES[id] ?? "application/octet-stream" },
    expect: { kind: "denied" },
  }]);

async function runDeserial(t: Head, ctx: TechniqueContext, target: TechniqueTarget): Promise<TechniqueResult> {
  const input = target.input;
  if (!input) return notTestable(t, NEEDS_INPUT);
  const route = routeOf(input.request.path), method = input.request.method === "GET" || input.request.method === "HEAD" ? "POST" : input.request.method, as = input.as ?? "a";
  // The control: a plain JSON body with a unique word. It must not already bring a deserializer error.
  const word = `yof${ctx.random()}`;
  const plain = await ctx.io.send(as, method, route, { body: `{"yof":"${word}"}`, headers: { "Content-Type": "application/json" }, purpose: "create", cls: "write_own_test_records", leg: "positive" });
  if (plain === null) return notTestable(t, "the test account is not set, or its sign-in failed");
  if (unusable(plain)) return notTestable(t, "a plain body got no usable answer");
  if (deserializerError(plain.body)) return notTestable(t, "a plain body already brings a deserializer's error message, so the test would show nothing");
  for (const id of t.payloads) {
    const token = `yofd${ctx.random()}`;
    const body = fillPayload(id, { token });
    const r = await sendBlob(ctx, input, id, body);
    if (!r || unusable(r)) continue;
    const sig = deserializerError(r.body);
    // A type hint that comes back with its unique word parsed out of the typed wrapper is the second kind of sign.
    const parsedBack = !sig && id.startsWith("deser.") && body.includes(token) && r.body.includes(token) && !r.body.includes(body);
    if (!sig && !parsedBack) continue;
    const again = await sendBlob(ctx, input, id, body);
    const twice = !!again && !unusable(again) && (sig ? deserializerError(again.body) === sig : again.body.includes(token));
    return result(t, "needs_validation", {
      reason: twice
        ? sig ? "the body brought a deserializer's own error message twice, which a plain body did not; it is a sign the value reached a reader of objects, not a proof it can be driven" : "the typed body's word came back parsed out of its wrapper twice; a crafted object was never sent, so it is not shown that the reader can be driven"
        : "it showed once and not a second time",
      method, route, as, status: r.status, payload: id, evidence: EVIDENCE.deserializer(sig ?? "type_hint"),
      meta: { payload: id, signature: sig ?? "type parsed", proof: "error signature", kind: sig ? "error" : "type hint" },
      replay: chain(t, input, id, ctx.accounts),
    });
  }
  return result(t, "held", { reason: "no typed body brought a deserializer's error message or a parsed type hint", method, route, as, status: plain.status });
}

export const DESERIALIZATION_TECHNIQUES: readonly Technique[] = [
  { ...OBJECT_STREAM, chain: (target, accounts) => (target.input ? chain(OBJECT_STREAM, target.input, OBJECT_STREAM.payloads[0]!, accounts) : null), run: (ctx, target) => runDeserial(OBJECT_STREAM, ctx, target) },
  { ...TYPE_HINT, chain: (target, accounts) => (target.input ? chain(TYPE_HINT, target.input, TYPE_HINT.payloads[0]!, accounts) : null), run: (ctx, target) => runDeserial(TYPE_HINT, ctx, target) },
];
