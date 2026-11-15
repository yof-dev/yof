/**
 * yof engagement, attack library: FILE UPLOADS. An uploaded file must never be served back as a page or a script.
 *
 *   files.content_mismatch   a tiny HTML page with a marker, named .png and declared an image
 *   files.active_type        the same page named .html, and a drawing (.svg, no script) with a marker
 *   files.path_name          a text file whose name holds a folder (yof-dir/name.txt)
 *
 * THE ORACLE: the test file is fetched again from where the app serves it. It is a finding when the marker comes back
 * AND the answer is one a browser renders: served as text/html (or as image/svg+xml for the drawing), not as a
 * download (no "Content-Disposition: attachment"). Served with no type at all and without "nosniff", a browser may
 * guess: that case needs validation. The file is the run's own test record and is deleted in clean-up, after a read
 * that shows it still holds the run's marker.
 *
 * NEVER SENT: a name that climbs out of a folder ("..", in any spelling), a file with a script in it, anything that
 * could run on the server. The record forbids writing files on the server beyond the app's own upload of a test file.
 * So files.path_name can only show that the app keeps the folder part of a name the client chose (needs validation);
 * whether a name could leave the upload folder is not tested.
 */
import type { HttpAnswer } from "../../http";
import type { ReplaySpec } from "../../replay";
import { notTestable, ok, readId, replayPath, result, routeOf, specOf, unusable } from "./kit";
import { fillPayload } from "./payloads";
import type { ImpactFacts, Technique, TechniqueContext, TechniqueResult, UploadSpec } from "./types";
import { EVIDENCE } from "./words";

const IMPACT: ImpactFacts = { what: "rule_broken", position: "self_registered", reach: "one_object", data: "ordinary" };
type Head = Omit<Technique, "run" | "chain">;

export interface TestFile { payload: string; name: string; type: string }
/** The file of a payload id: its name and the type it is declared as. The name is fixed apart from the run's own word. Pure. */
export function testFile(payloadId: string, word: string): TestFile {
  const w = word.replace(/[^a-z0-9]/gi, "").slice(0, 16) || "x";
  if (payloadId === "file.html_as_png") return { payload: payloadId, name: `yof-${w}.png`, type: "image/png" };
  if (payloadId === "file.html") return { payload: payloadId, name: `yof-${w}.html`, type: "text/html" };
  if (payloadId === "file.svg") return { payload: payloadId, name: `yof-${w}.svg`, type: "image/svg+xml" };
  return { payload: payloadId, name: `yof-dir/yof-${w}.txt`, type: "text/plain" };
}
/** One form-data body with one file. Text only: the test files are text. Pure. */
export function formBody(field: string, file: TestFile, content: string, boundary: string): { body: string; contentType: string } {
  const safe = (s: string) => s.replace(/["\r\n]/g, "");
  return {
    body: `--${boundary}\r\nContent-Disposition: form-data; name="${safe(field)}"; filename="${safe(file.name)}"\r\nContent-Type: ${file.type}\r\n\r\n${content}\r\n--${boundary}--\r\n`,
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}
export type Served = "renders" | "may_be_guessed" | "inert" | "not_returned";
/** How a served test file reaches a browser. Pure. */
export function servedAs(status: number, header: (name: string) => string | null, body: string, marker: string, svg: boolean): { how: Served; type: string } {
  const type = (header("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (status < 200 || status >= 300 || !body.includes(marker)) return { how: "not_returned", type };
  if (/\battachment\b/i.test(header("content-disposition") ?? "")) return { how: "inert", type };
  if (type === "text/html" || type === "application/xhtml+xml" || (svg && type === "image/svg+xml")) return { how: "renders", type };
  if (!type && !/\bnosniff\b/i.test(header("x-content-type-options") ?? "")) return { how: "may_be_guessed", type: "no type" };
  return { how: "inert", type };
}

interface Uploaded { answer: HttpAnswer; id: string; marker: string }
async function upload(ctx: TechniqueContext, u: UploadSpec, file: TestFile): Promise<Uploaded | { refused: number } | string> {
  const allowed = ctx.io.pathAllowed ?? (() => true);
  // A file that could not be deleted again is never uploaded.
  if (!allowed(u.path) || !allowed(u.delete) || !allowed(u.served)) return "the rules forbid a path this needs";
  const marker = ctx.registry.next("a");
  const form = formBody(u.field, file, fillPayload(file.payload, { marker }), `----yof${ctx.random()}`);
  const r = await ctx.io.send("a", "POST", u.path, { body: form.body, headers: { "Content-Type": form.contentType }, purpose: "create", cls: "write_own_test_records", leg: "plant" });
  if (r === null) return "the test account is not set, or its sign-in failed";
  if (unusable(r)) return "the upload got no usable answer";
  if (!ok(r.status)) return { refused: r.status };
  const id = readId(r.body, u.idPath);
  if (!id) return "the uploaded file's id could not be read";
  ctx.io.own(id);
  ctx.registry.register(marker, { id, createRoute: u.path, readRoute: u.served, deleteRoute: u.delete });
  return { answer: r, id, marker };
}
const chain = (t: Pick<Technique, "ruleId" | "title">, u: UploadSpec, payloadId: string, accounts?: ReplaySpec["accounts"]): ReplaySpec => {
  const file = testFile(payloadId, "replay");
  const form = formBody(u.field, file, fillPayload(payloadId, { marker: "{{marker}}" }), "----yofreplay");
  return specOf(t, ["marker"], accounts, [
    { as: "a", method: "POST", path: u.path, body: form.body, headers: { "Content-Type": form.contentType }, save: { name: "id", from: u.idPath }, setup: true, leg: "plant" },
    { as: "a", method: "GET", path: replayPath(u.served) },
    { as: "a", method: "DELETE", path: replayPath(u.delete), cleanup: true },
  ]);
};
const CHAIN_LIMIT = "A generated regression test sends every body as JSON and cannot read a content type, so it cannot repeat an upload. `yof attack replay` sends the file; run the technique again to re-test how it is served.";
const head = { ruleId: "attack.unsafe_upload", title: "An uploaded file is served back as a page a browser runs", invariants: ["upload_safe"] as const, prerequisites: ["account_a", "upload_route"] as const, safetyClass: "write_own_test_records" as const, classes: ["read", "write_own_test_records"] as const, impact: IMPACT, owasp: "A04 / A05", chainLimit: CHAIN_LIMIT };

async function runServed(t: Head, ctx: TechniqueContext, u: UploadSpec | undefined): Promise<TechniqueResult> {
  if (!u) return notTestable(t, "the app model names no upload route");
  const route = routeOf(u.path);
  let refused = 0, weak: TechniqueResult | null = null;
  for (const id of t.payloads) {
    const file = testFile(id, ctx.random());
    const up = await upload(ctx, u, file);
    if (typeof up === "string") return notTestable(t, up);
    if ("refused" in up) { refused = up.refused; continue; }
    const path = u.served.split("{id}").join(encodeURIComponent(up.id));
    const look = async () => { const r = await ctx.io.send("a", "GET", path, { purpose: "read", cls: "read", leg: "test" }); return r ? servedAs(r.status, (n) => r.headers.get(n), r.body, up.marker, id === "file.svg") : null; };
    const seen = await look();
    if (!seen || seen.how === "inert" || seen.how === "not_returned") continue;
    const twice = seen.how === "renders" && (await look())?.how === "renders";
    const out = result(t, twice ? "violated" : "needs_validation", {
      reason: twice ? "the test file came back with the run's marker, as a type a browser renders and not as a download, twice" : seen.how === "may_be_guessed" ? "the test file came back with no content type and without nosniff: a browser may guess that it is a page" : "it showed once and not a second time",
      method: "POST", route, as: "a", status: up.answer.status, marker: up.marker, payload: id, evidence: EVIDENCE.uploadServed(seen.type), meta: { payload: id, kind: seen.type, proof: "marker" }, replay: chain(t, u, id, ctx.accounts),
    });
    if (twice) return out;
    weak ??= out;
  }
  return weak ?? result(t, "held", { reason: refused ? "the app refused the test file" : "the test file was served as a download or as a type a browser does not render", method: "POST", route, as: "a", status: refused });
}

const MISMATCH: Head = {
  ...head, id: "files.content_mismatch", payloads: ["file.html_as_png"],
  oracle: "A tiny HTML page with a marker, named .png and declared an image, is uploaded and then served back as text/html (not as a download) with the marker in it, twice.",
  shows: "that the app serves a file by what it holds, whatever it was declared as", cannotShow: "that a script in such a file would run: the test file holds none",
  best: "confirmed",
};
const ACTIVE: Head = {
  ...head, id: "files.active_type", payloads: ["file.html", "file.svg"],
  oracle: "A tiny HTML page (.html) or a drawing with no script (.svg), each with a marker, is uploaded and then served back from the app as a page or a drawing a browser renders (not as a download), twice.",
  shows: "that the app accepts and serves file types a browser runs", cannotShow: "whether the files are served from a separate, cookie-less address in production (then the risk is smaller): check the address it came from",
  best: "confirmed",
};
const PATH_NAME: Head = {
  ...head, id: "files.path_name", payloads: ["file.sub_path"],
  oracle: "A text file named yof-dir/name.txt is uploaded, and the app's answer or the served address keeps the folder part of that name.",
  shows: "that the client's file name decides where the file is stored", cannotShow: "that a name can leave the upload folder: a name that climbs out of a folder is never sent",
  best: "needs_validation",
};

export const FILE_TECHNIQUES: readonly Technique[] = [
  { ...MISMATCH, chain: (target, accounts) => (target.upload ? chain(MISMATCH, target.upload, "file.html_as_png", accounts) : null), run: (ctx, target) => runServed(MISMATCH, ctx, target.upload) },
  { ...ACTIVE, chain: (target, accounts) => (target.upload ? chain(ACTIVE, target.upload, "file.html", accounts) : null), run: (ctx, target) => runServed(ACTIVE, ctx, target.upload) },
  {
    ...PATH_NAME,
    chain: (target, accounts) => (target.upload ? chain(PATH_NAME, target.upload, "file.sub_path", accounts) : null),
    run: async (ctx, target): Promise<TechniqueResult> => {
      const t = PATH_NAME, u = target.upload;
      if (!u) return notTestable(t, "the app model names no upload route");
      const file = testFile("file.sub_path", ctx.random());
      const up = await upload(ctx, u, file);
      if (typeof up === "string") return notTestable(t, up);
      if ("refused" in up) return result(t, "held", { reason: "the app refused a file name with a folder in it", method: "POST", route: routeOf(u.path), as: "a", status: up.refused });
      const kept = up.answer.body.includes(file.name) || up.answer.body.includes(file.name.replace("/", "\\/")) || up.id.includes("yof-dir");
      if (!kept) return result(t, "held", { reason: "the app gave the file its own name", method: "POST", route: routeOf(u.path), as: "a", status: up.answer.status });
      return result(t, "needs_validation", {
        reason: "the app kept the folder part of the name; whether a name could leave the upload folder was not tested, because such a name is never sent", method: "POST", route: routeOf(u.path), as: "a", status: up.answer.status,
        marker: up.marker, payload: "file.sub_path", evidence: EVIDENCE.uploadPathKept(), meta: { payload: "file.sub_path", kind: "folder kept" }, replay: chain(t, u, "file.sub_path", ctx.accounts),
      });
    },
  },
];
