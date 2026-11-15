import { describe, expect, it } from "vitest";
import { scanText, isPlaceholder, KEY_RULES } from "../src/secrets";
import { checkPackages, packageMessage, privateNpmNames, npmScopeOf } from "../src/packages";
import { runCheck } from "../src/check";
import { checkToFindingsJson } from "../src/findings-format";
import { packageFixPrompt } from "../src/words";
import { mockFetcher, tempDir } from "./helpers";

/**
 * 0.4.0 (yof finish list Y20, 13 Nov 2026): the CLI learns what the yof app already knew, so the two agree on a repo.
 *   - Supabase's newer keys: sb_secret_... is the service-role key (fix now), sb_publishable_... the browser key (info).
 *   - A scoped npm name the public registry does not know is "may be private" unless its scope is public: fix this
 *     week and "needs validation", never "fix now". Names served by a private registry (.npmrc) or published by the
 *     repository itself are never asked.
 * The app-side parity test is packages/api/src/__tests__/yof-finish-s1-2026-11-13.test.ts. Keys are built at run time.
 */
const body = (seed: string) => Array.from({ length: 32 }, (_, i) => "Q7x2Lm9Pz4Rk8Vn3Wd6Yf1Hb5Tc0JaUe"[(i + seed.length) % 32]).join("");
const SB_SECRET = ["sb", "secret", body("s")].join("_");
const SB_PUB = ["sb", "publishable", body("pp")].join("_");

describe("Supabase's newer keys", () => {
  it("sb_secret_ fires as the service-role key, fix now, masked to its prefix and four characters", () => {
    const m = scanText(`const admin = createClient(url, "${SB_SECRET}");`);
    expect(m.map((x) => [x.ruleId, x.meta?.format])).toEqual([["secret.supabase_service_role", "sb_secret"]]);
    expect(KEY_RULES[m[0]!.ruleId]!.severity).toBe("fix_now");
    expect(m[0]!.masked).toBe(`${SB_SECRET.slice(0, 14)}${"•".repeat(8)}`);
    expect(m[0]!.snippet).not.toContain(SB_SECRET.slice(14));
  });
  it("sb_publishable_ is the public browser key: info, never an alarm", () => {
    const m = scanText(`createClient(url, "${SB_PUB}")`);
    expect(m.map((x) => [x.ruleId, x.meta?.format])).toEqual([["public.supabase_anon", "sb_publishable"]]);
    expect(KEY_RULES["public.supabase_anon"]!.severity).toBe("info");
  });
  it("look-alikes stay quiet: too short, glued to another word, the prefix in prose, a placeholder", () => {
    for (const t of ["sb_secret_short", `my_${SB_SECRET}`, "Keep sb_secret_ keys on the server.", `x${SB_PUB}`]) expect(scanText(t), t).toEqual([]);
    expect(isPlaceholder(`sb_secret_${"x".repeat(30)}`)).toBe(true);
    expect(scanText(`"sb_secret_${"x".repeat(30)}"`)).toEqual([]);
  });
});

describe("a scoped package that may be private", () => {
  const search = (scope: string, names: string[]) => [`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(`scope:${scope}`)}&size=1`, { status: 200, json: { objects: names.map((n) => ({ package: { name: n } })) } }] as const;
  it("unknown name, scope not public: fix this week, unconfirmed, in words that say it may be private", async () => {
    const r = await checkPackages([{ name: "@acme/ui", ecosystem: "npm", spec: "^1" }], { fetcher: mockFetcher(Object.fromEntries([["https://registry.npmjs.org/@acme%2Fui", { status: 404 }], search("acme", [])])) });
    expect(r.findings).toEqual([{ name: "@acme/ui", ecosystem: "npm", issue: "made_up", severity: "fix_week", unconfirmed: true }]);
    expect(packageMessage(r.findings[0]!)).toMatch(/may be a private package of yours/);
    expect(packageMessage(r.findings[0]!)).toContain("(@acme)");
  });
  it("unknown name under a PUBLIC scope is made up: fix now (the scope's answer must name that very scope)", async () => {
    const r = await checkPackages([{ name: "@types/nope-nope", ecosystem: "npm", spec: "^1" }], { fetcher: mockFetcher(Object.fromEntries([["https://registry.npmjs.org/@types%2Fnope-nope", { status: 404 }], search("types", ["@types/node"])])) });
    expect(r.findings.map((f) => [f.severity, f.unconfirmed])).toEqual([["fix_now", undefined]]);
    // a search answer about ANOTHER scope does not make this one public
    const other = await checkPackages([{ name: "@corp/x", ecosystem: "npm", spec: "1" }], { fetcher: mockFetcher(Object.fromEntries([["https://registry.npmjs.org/@corp%2Fx", { status: 404 }], search("corp", ["@corporate/y"])])) });
    expect(other.findings.map((f) => f.unconfirmed)).toEqual([true]);
  });
  it("an unscoped name the registry does not know stays made up, fix now (look-alike)", async () => {
    const r = await checkPackages([{ name: "reqeusts-helper", ecosystem: "npm", spec: "1.0.0" }], { fetcher: mockFetcher({ "https://registry.npmjs.org/reqeusts-helper": { status: 404 } }) });
    expect(r.findings.map((f) => [f.issue, f.severity, f.unconfirmed])).toEqual([["made_up", "fix_now", undefined]]);
    expect(npmScopeOf("reqeusts-helper")).toBeNull();
  });
  it("the fix prompt and the findings file say 'may be private' and 'needs validation'", async () => {
    const dir = tempDir({ "package.json": JSON.stringify({ name: "shop", dependencies: { "@acme/ui": "^1.0.0" } }) });
    const fetcher = mockFetcher(Object.fromEntries([["https://registry.npmjs.org/@acme%2Fui", { status: 404 }], search("acme", [])]));
    const r = await runCheck({ cwd: dir, fetcher, patterns: false });
    expect(r.packages.map((p) => [p.name, p.severity, p.unconfirmed])).toEqual([["@acme/ui", "fix_week", true]]);
    expect(packageFixPrompt(r.packages[0]!)).toMatch(/may be a private package of mine or a made-up name/);
    const vf = checkToFindingsJson(r) as { verdict: string; title: string }[];
    expect(vf.find((x) => x.title.startsWith("@acme/ui"))!.verdict).toBe("needs_validation");
  });
  it("names behind a private registry, or published by the repo itself, are never asked", async () => {
    const dir = tempDir({
      ".npmrc": "@corp:registry=https://registry.example.com/\n",
      "package.json": JSON.stringify({ name: "shop", dependencies: { "@corp/design": "^2.0.0", "@shop/utils": "^1.0.0" } }),
      "packages/utils/package.json": JSON.stringify({ name: "@shop/utils" }),
    });
    const calls: string[] = [];
    const r = await runCheck({ cwd: dir, fetcher: mockFetcher({}, calls), patterns: false });
    expect(calls).toEqual([]);
    expect(r.packages).toEqual([]);
    expect(privateNpmNames([{ path: ".npmrc", content: "registry=https://registry.example.com/" }]).skip("lodash")).toBe(true);
    expect(privateNpmNames([{ path: ".npmrc", content: "registry=https://registry.npmjs.org/" }]).skip("lodash")).toBe(false);
  });
});
