/**
 * yof engagement, open core: the evidence sentences of the library. What a result says it saw is one of these fixed
 * sentences, in yof's own words, with a count, a field name or the SHAPE of an answer filled in. Never a piece of an
 * answer. The yof app keeps an uploaded sentence only when it reads like one of these (its stored-evidence patterns),
 * and a test in the private repository runs every example below through that check.
 */
const n = (v: number) => String(Math.max(0, Math.floor(v)));
/** A name that is safe to print: a plain identifier, cut short. */
export const plainName = (s: string): string => s.replace(/[^A-Za-z0-9_.$-]/g, "").slice(0, 40) || "field";

export const EVIDENCE = {
  tenantRead: (shape: string) => `the answer held the test record of account A: ${shape}`,
  anonRead: (shape: string) => `nobody signed in got an answer that holds the test record of account A: ${shape}`,
  adminRead: (shape: string) => `a member got an answer that holds the admin account's test record: ${shape}`,
  sequentialIds: (shape: string) => `the answer held the test record of account A, whose id follows the one before it: ${shape}`,
  crossWrite: (controls: string) => `another test account changed a test record of account A, and A read the change (${controls})`,
  overrideWrite: (header: string) => `another test account changed a test record of account A with the header ${plainName(header)}, after the plain request was refused`,
  contentTypeWrite: (type: string) => `another test account changed a test record of account A by sending the change as ${type.replace(/[^a-z/+.-]/g, "").slice(0, 60)}, after the JSON request was refused`,
  fieldSet: (field: string) => `the owner's own read showed the field ${plainName(field)} changed to the value the request set`,
  fieldAdded: (field: string) => `the owner's own read showed a new field ${plainName(field)} that the request added`,
  booleanPair: (pairs: number) => `a search for the run's own marker found it with a true condition added and lost it with a false one (${n(pairs)} pairs)`,
  databaseError: (signature: string) => `the answer held a database error message (${plainName(signature)}) only when an unbalanced quote was sent`,
  timedWait: (seconds: number) => `the answer came about ${n(seconds)} seconds later only when a wait was added to the value`,
  templateSum: () => "the answer held the result of a sum the request sent, not the text of the sum",
  markupReflected: (context: string) => `the marker came back unescaped in an HTML context (${plainName(context)})`,
  markupStored: (context: string) => `a stored marker came back unescaped in an HTML context when the record was read again (${plainName(context)})`,
  commandEcho: () => "the answer held the output of an echo the request sent, not the text of the command",
  forgedChange: (how: string, cookie: string) => `the run's own test record was changed ${how}, and the session cookie ${cookie}`,
  forgeryObserved: (what: string) => `observation only, nothing was changed: ${what}`,
  sessionAlive: () => "the old session still worked after sign-out",
  resetReused: (times: number) => `the same reset link worked ${n(times)} times`,
  tokenUnsigned: () => "a token with its signature removed and its label set to unsigned was accepted",
  tokenBadSignature: () => "a token with its signature replaced was accepted",
  cookieFlags: (missing: string) => `the sign-in cookie is set without ${missing.replace(/[^A-Za-z, ]/g, "").slice(0, 60)}`,
  noPasswordLimit: (tries: number) => `${n(tries)} wrong passwords on the run's own test account were all answered the same way; no limit was seen within them`,
  numberOutOfBounds: (field: string, which: string) => `the record showed ${plainName(field)} outside its bounds after the request (${plainName(which)})`,
  stepSkipped: (step: string) => `the record reached the state of the step ${plainName(step)} without the step before it`,
  usedTwice: (times: number, bound: number) => `the same single-use request worked ${n(times)} times (the limit is ${n(bound)})`,
  race: (wins: number, sent: number, bound: number) => `${n(wins)} of ${n(sent)} identical requests sent at once succeeded (the limit is ${n(bound)})`,
  uploadServed: (type: string) => `an uploaded test file was served back as ${type.replace(/[^a-z/+.-]/g, "").slice(0, 60)}, in a way a browser renders`,
  uploadPathKept: () => "an uploaded test file kept the folder part of the name the request chose",
  canaryCalled: (restricted: boolean) => `the server called the yof canary address the request named${restricted ? ", although this parameter should only fetch listed hosts" : "; internal addresses were not tried"}`,
  deserializer: (signature: string) => `the answer held an error message of an object deserializer (${plainName(signature)})`,
  idsInOrder: (gap: number) => `two ids of the run's own records follow each other (${n(gap)} apart)`,
  shortToken: (chars: number, floor: number) => `a session value of the run's own test account is ${n(chars)} characters long (the floor is ${n(floor)})`,
  tokensAlike: (shared: number) => `two session values of the same test account share their first ${n(shared)} characters`,
} as const;

const SHAPE = "a JSON object with 2 fields (id, title), 58 characters";
/** One example of every sentence, per rule id. The yof app's stored-evidence check must keep each of them. */
export const EVIDENCE_EXAMPLES: Readonly<Record<string, readonly string[]>> = {
  "attack.tenant_read": [EVIDENCE.tenantRead(SHAPE), EVIDENCE.sequentialIds(SHAPE)],
  "attack.auth_bypass": [EVIDENCE.anonRead(SHAPE)],
  "attack.rbac_escalation": [EVIDENCE.adminRead(SHAPE)],
  "attack.tenant_write": [EVIDENCE.crossWrite("refused with no sign-in"), EVIDENCE.overrideWrite("X-HTTP-Method-Override"), EVIDENCE.contentTypeWrite("text/plain")],
  "attack.mass_assignment": [EVIDENCE.fieldSet("is_admin"), EVIDENCE.fieldAdded("role")],
  "attack.query_injection": [EVIDENCE.booleanPair(2), EVIDENCE.databaseError("sqlite"), EVIDENCE.timedWait(2)],
  "attack.template_injection": [EVIDENCE.templateSum()],
  "attack.unescaped_markup": [EVIDENCE.markupReflected("element"), EVIDENCE.markupStored("element")],
  "attack.command_injection": [EVIDENCE.commandEcho()],
  "attack.csrf": [EVIDENCE.forgedChange("without its anti-forgery token", "has no SameSite protection"), EVIDENCE.forgeryObserved("the session cookie has no SameSite protection")],
  "attack.session_not_ended": [EVIDENCE.sessionAlive()],
  "attack.single_use_reuse": [EVIDENCE.resetReused(2), EVIDENCE.usedTwice(2, 1)],
  "attack.token_unverified": [EVIDENCE.tokenUnsigned(), EVIDENCE.tokenBadSignature()],
  "attack.weak_session_cookie": [EVIDENCE.cookieFlags("HttpOnly, SameSite")],
  "attack.no_rate_limit": [EVIDENCE.noPasswordLimit(8)],
  "attack.number_out_of_bounds": [EVIDENCE.numberOutOfBounds("quantity", "num.negative")],
  "attack.step_skipped": [EVIDENCE.stepSkipped("ship")],
  "attack.race_condition": [EVIDENCE.race(4, 6, 1)],
  "attack.unsafe_upload": [EVIDENCE.uploadServed("text/html"), EVIDENCE.uploadPathKept()],
  "attack.server_fetch": [EVIDENCE.canaryCalled(true), EVIDENCE.canaryCalled(false)],
  "attack.unsafe_deserializer": [EVIDENCE.deserializer("java_object_stream")],
  "attack.predictable_token": [EVIDENCE.idsInOrder(1), EVIDENCE.shortToken(8, 20), EVIDENCE.tokensAlike(24)],
};
