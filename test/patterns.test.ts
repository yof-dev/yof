/**
 * yof check, code and config patterns (the second rule set, src/rules2): what the CLI prints, when it fails, what it
 * says when the TypeScript compiler is missing, accepted risks, and the two machine formats.
 * The rules themselves are tried case by case in the main repository's tests, on the same bytes as src/rules2.
 * Every value that looks like a password is put together at run time (see helpers.ts), so this file holds none.
 */
import * as ts from "typescript";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { acceptFingerprint, withEntry } from "../src/accepted";
import { patternFailsIn, patternVisibleIn, runCheck } from "../src/check";
import { main } from "../src/cli";
import { checkToFindingsJson } from "../src/findings-format";
import { fromFindingsJson } from "../src/findings-json";
import { formatJson, formatText } from "../src/format";
import { loadTypescript, patternFindings, verdictOf } from "../src/patterns";
import { BASE_IMAGE_TABLE_DATE, R2_FAMILIES, R2_RULES, runRules2 } from "../src/rules2/index";
import { R2_WORDS } from "../src/rules2/words-en";
import { captureIo, mockFetcher, rand, tempDir } from "./helpers";

const PASS = `Qx${rand(6, undefined, 91)}7!`;
const SQL = "export async function h(req, res) {\n  res.json(await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`));\n}\n";
const COMPOSE = "services:\n  web:\n    image: acme/web:1.4.2\n    privileged: true\n";
const JWT_NONE = 'import jwt from "jsonwebtoken";\nexport const read = (t, k) => jwt.verify(t, k, { algorithms: ["HS256", "none"] });\n';
const K8S = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: acme/web:1.4.2\n";
const FILES = { "src/users.ts": SQL, "docker-compose.yml": COMPOSE, "src/config.ts": `export const dbPassword = "${PASS}";\n`, "k8s/web.yaml": K8S };
const check = (files: Record<string, string>, opts: Parameters<typeof runCheck>[0] = {}) => runCheck({ path: tempDir(files), offline: true, ts, ...opts });

describe("yof check: code and config patterns", () => {
  it("lists each pattern with its verdict, in its own section, and never prints a value", async () => {
    const r = await check(FILES);
    const by = Object.fromEntries(r.patterns.map((p) => [p.rule, p]));
    expect(by["inside.code_sql_injection"]).toMatchObject({ file: "src/users.ts", line: 2, verdict: "needs_validation", severity: "fix_now", family: "injection" });
    expect(by["inside.compose_privileged"]).toMatchObject({ verdict: "confirmed", severity: "fix_week", family: "containers" });
    expect(by["inside.cred_password_literal"]).toMatchObject({ verdict: "needs_validation", masked: "Q••••" });
    expect(by["inside.k8s_no_limits"]).toMatchObject({ verdict: "note", severity: "note" });
    const text = formatText(r);
    expect(text).toContain("Code and config patterns (yof found these patterns in your files; it did not run the code)");
    expect(text).toContain("src/users.ts:2  SQL text is built from request input  (needs validation, fix now)");
    expect(text).toContain("docker-compose.yml:4  A compose service runs with the host's privileges  (confirmed, fix this week)");
    expect(text).toMatch(/3 code or config patterns: 1 confirmed, 2 to validate\./);
    expect(text).toContain("built images, the running cluster and the cloud account are not checked");
    expect(text).not.toContain("hardening note");                     // notes are shown with --profile strict only
    expect(text).toMatch(/patterns? hidden by profile balanced/);
    expect(text.includes(PASS)).toBe(false);
    expect(formatJson(r, { version: "0" }).includes(PASS)).toBe(false);
    expect(r.patternRun).toMatchObject({ astRan: true, unreadable: [] });
  });

  it("a pattern that needs validation never fails a balanced check; a confirmed 'fix now' one does; strict fails on both", async () => {
    expect((await check(FILES)).failed).toBe(false);
    expect((await check({ "src/auth.ts": JWT_NONE })).failed).toBe(true);
    expect((await check(FILES, { profile: "strict" })).failed).toBe(true);
    expect((await check({ "k8s/web.yaml": K8S }, { profile: "strict" })).failed).toBe(false);       // notes never fail
    expect(patternFailsIn("balanced", { severity: "fix_now", verdict: "needs_validation" })).toBe(false);
    expect(patternFailsIn("relaxed", { severity: "fix_now", verdict: "confirmed" })).toBe(true);
    expect(patternFailsIn("strict", { severity: "note", verdict: "note" })).toBe(false);
    expect(patternVisibleIn("relaxed", { severity: "fix_week" })).toBe(false);
    expect(patternVisibleIn("strict", { severity: "note" })).toBe(true);
    // the key and package counts are untouched: patterns are counted apart
    expect((await check(FILES)).counts).toEqual({ fix_now: 0, fix_week: 0, info: 0 });
  });

  it("the exit code and --no-patterns through the command line", async () => {
    const dir = tempDir({ "src/auth.ts": JWT_NONE, "package.json": "{}" });
    const a = captureIo(dir, { fetcher: mockFetcher({}) });
    expect(await main(["check", "--offline"], a.io)).toBe(1);
    expect(a.cap.out.join("\n")).toContain("A sign-in token is accepted without checking its signature  (confirmed, fix now)");
    const b = captureIo(dir, { fetcher: mockFetcher({}) });
    expect(await main(["check", "--offline", "--no-patterns"], b.io)).toBe(0);
    expect(b.cap.out.join("\n")).not.toContain("Code and config patterns");
    const off = await check(FILES, { patterns: false });
    expect(off.patterns).toEqual([]);
    expect(off.patternRun).toBeNull();
  });

  it("without the TypeScript compiler the syntax rules do not run, the output says so, and the text rules still do", async () => {
    const r = await check(FILES, { ts: null });
    expect(r.patternRun).toMatchObject({ astRan: false, scripts: 2 });
    expect(r.patterns.map((p) => p.rule)).not.toContain("inside.code_sql_injection");
    expect(r.patterns.map((p) => p.rule)).toEqual(expect.arrayContaining(["inside.compose_privileged", "inside.cred_password_literal"]));
    expect(formatText(r)).toContain("The JavaScript and TypeScript syntax rules did not run (no typescript package found next to yof): nothing is claimed for them.");
    // a folder with no JavaScript or TypeScript does not get that line
    expect(formatText(await check({ "docker-compose.yml": COMPOSE }, { ts: null }))).not.toContain("syntax rules did not run");
  });

  it("finds the compiler when it is installed next to yof, and never bundles it", async () => {
    const found = await loadTypescript();
    expect(typeof found?.createSourceFile).toBe("function");
    const src = readFileSync(join(__dirname, "../src/patterns.ts"), "utf8");
    expect(src).not.toMatch(/import\(\s*"typescript"\s*\)/);
    expect(src).not.toMatch(/^import (?!type)[^;]*from "typescript"/m);
    const pkg = JSON.parse(readFileSync(join(__dirname, "../package.json"), "utf8")) as { dependencies?: unknown; peerDependencies?: unknown };
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.peerDependencies).toBeUndefined();
  });

  it("an accepted risk is listed with its reason and no longer fails the check", async () => {
    const line = JWT_NONE.split("\n")[1]!;
    const entry = { rule: "inside.code_jwt_unverified", file: "src/auth.ts", fingerprint: acceptFingerprint("inside.code_jwt_unverified", "src/auth.ts", line), reason: "legacy verifier, removed in the next release", acceptedBy: "Ada", acceptedAt: "2026-11-12T10:00:00.000Z" };
    const r = await check({ "src/auth.ts": JWT_NONE, ".yof/accepted.json": withEntry(null, entry) });
    expect(r.failed).toBe(false);
    expect(r.patterns[0]?.accepted?.reason).toBe("legacy verifier, removed in the next release");
    const text = formatText(r);
    expect(text).toContain("Accepted risks (.yof/accepted.json)");
    expect(text).toContain("accepted by Ada on 2026-11-12: legacy verifier, removed in the next release");
    expect(text).not.toContain("Code and config patterns (");
  });

  it("findings.json: valid records, a pattern that needs validation says what yof did not do, notes are not written", async () => {
    const r = await check({ ...FILES, "src/auth.ts": JWT_NONE });
    const json = checkToFindingsJson(r);
    const back = fromFindingsJson(JSON.stringify(json));
    expect(back.errors).toEqual([]);
    expect(back.findings.map((f) => f.fingerprint.split("/")[1]).sort()).toEqual(["inside.code_jwt_unverified", "inside.code_sql_injection", "inside.compose_privileged", "inside.cred_password_literal"]);
    const sql = back.findings.find((f) => f.fingerprint.includes("code_sql_injection"))!;
    expect(sql.verdict).toBe("needs_validation");
    expect(sql.blockers?.[0]).toContain("did not run the code");
    const jwt = back.findings.find((f) => f.fingerprint.includes("code_jwt_unverified"))!;
    expect(jwt.verdict).toBe("confirmed");
    expect(jwt.severity?.overall).toBe("high");                          // never critical: nothing was run
    expect(JSON.stringify(json).includes(PASS)).toBe(false);
  });

  it("--json carries the patterns, their fix prompt and what ran", async () => {
    const out = JSON.parse(formatJson(await check(FILES), { version: "0" })) as { patterns: { rule: string; fixPrompt: string; verdict: string }[]; patternRun: { astRan: boolean } };
    const sql = out.patterns.find((p) => p.rule === "inside.code_sql_injection")!;
    expect(sql.fixPrompt).toContain("In src/users.ts at line 2");
    expect(sql.fixPrompt).toContain("parameterised query");
    expect(out.patternRun.astRan).toBe(true);
  });

  it("is offline and reads only shipping files: tests, docs, examples and vendored code are left alone", async () => {
    const fetcher = async () => { throw new Error("no network in a pattern check"); };
    const r = await runCheck({ path: tempDir({ "src/__tests__/users.test.ts": SQL, "examples/users.ts": SQL, "docs/compose.md": COMPOSE, "vendor/lib/users.js": SQL }), offline: true, ts, fetcher });
    expect(r.patterns).toEqual([]);
  });
});

describe("the rule list the CLI carries", () => {
  it("43 rules in seven families, every one with its English words, and a verdict that follows its basis", () => {
    expect(R2_RULES).toHaveLength(43);
    expect([...R2_FAMILIES]).toEqual(["injection", "csrf", "deserialization", "crypto", "passwords", "uploads", "containers"]);
    for (const r of R2_RULES) {
      const w = R2_WORDS[r.id]!;
      expect(w.title.length, r.id).toBeGreaterThan(8);
      expect(w.fix.length, r.id).toBeGreaterThan(40);
      expect(verdictOf(r.id), r.id).toBe(r.basis === "exact" ? "confirmed" : r.basis === "practice" ? "note" : "needs_validation");
      if (r.basis === "pattern") expect(w.why.endsWith("yof found this pattern in your files; it did not run the code or look at the live system."), r.id).toBe(true);
      for (const s of [w.title, w.why, w.fix, w.expected]) expect(s, r.id).not.toMatch(/[—–]|\b(?:secure|safe|certified|compliant)\b/i);
    }
  });
  it("the end-of-life table is dated and the date is printed on the finding", async () => {
    expect(BASE_IMAGE_TABLE_DATE).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    const f = runRules2([{ path: "Dockerfile", content: "FROM node:16\n" }]).findings.find((x) => x.ruleId === "inside.docker_base_eol");
    expect(f?.meta.table_date).toBe(BASE_IMAGE_TABLE_DATE);
    const p = await patternFindings([{ path: "Dockerfile", content: "FROM node:16\n" }], [], { ts: null });
    expect(p.findings.find((x) => x.rule === "inside.docker_base_eol")?.facts.not_checked).toContain("not scanned");
  });
  it("the README names the families and says what is not done", () => {
    const readme = readFileSync(join(__dirname, "../README.md"), "utf8");
    for (const s of ["Code and config patterns", "Injection", "Unsafe loaders", "Weak cryptography", "Passwords in code", "Containers and infrastructure", "--no-patterns", "needs validation", "scan built container images"]) expect(readme, s).toContain(s);
  });
});
