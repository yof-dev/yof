import { describe, expect, it, vi } from "vitest";
import {
  checkPackages, editDistance, isManifest, lookalikeOf, packageFetcher, packageMessage, parseManifest,
  parsePackageJson, parsePyproject, parseRequirements, pinnedVersion,
} from "../src/packages";
import { mockFetcher } from "./helpers";

describe("manifest parsers", () => {
  it("package.json: registry deps from all three fields, aliases resolved, local/git/workspace skipped", () => {
    const deps = parsePackageJson(JSON.stringify({
      dependencies: { React: "^18.0.0", "@scope/pkg": "1.2.3", local: "file:../local", ws: "workspace:*", gh: "user/repo", alias: "npm:lodash@^4" },
      devDependencies: { vitest: "^2.0.0", "git-dep": "git+https://example.com/x.git" },
      optionalDependencies: { fsevents: "^2" },
    }));
    expect(deps.map((d) => d.name)).toEqual(["react", "@scope/pkg", "lodash", "vitest", "fsevents"]);
    expect(deps.find((d) => d.name === "lodash")!.spec).toBe("^4");
    expect(parsePackageJson("{ not json")).toEqual([]);
  });

  it("requirements.txt: names normalised, options, URLs, markers and comments handled", () => {
    const deps = parseRequirements([
      "# comment", "Flask==2.3.3", "requests[socks] >= 2.0  # inline", "Django_REST.framework", "-r other.txt", "-e .",
      "git+https://example.com/x.git", "pkg @ https://example.com/p.whl", "numpy; python_version > '3.8'", "flask==3",
    ].join("\n"));
    expect(deps.map((d) => d.name)).toEqual(["flask", "requests", "django-rest-framework", "numpy"]);
    expect(deps[0]!.spec).toBe("==2.3.3");
  });

  it("pyproject.toml: PEP 621 arrays and poetry tables, python skipped", () => {
    const deps = parsePyproject([
      "[project]", 'name = "x"', "dependencies = [", '  "httpx>=0.27",', '  "pydantic==2.8.2",', "]",
      "[tool.poetry.dependencies]", 'python = "^3.11"', 'fastapi = "^0.110"',
      "[tool.poetry.group.dev.dependencies]", 'pytest = "^8"',
    ].join("\n"));
    expect(deps.map((d) => d.name)).toEqual(["httpx", "pydantic", "fastapi", "pytest"]);
  });

  it("parseManifest picks the parser by file name", () => {
    expect(isManifest("a/package.json")).toBe(true);
    expect(isManifest("requirements-dev.txt")).toBe(true);
    expect(isManifest("pyproject.toml")).toBe(true);
    expect(isManifest("notes.txt")).toBe(false);
    expect(parseManifest("requirements.txt", "flask\n").map((d) => d.name)).toEqual(["flask"]);
  });

  it("pinnedVersion only accepts exact pins", () => {
    expect(pinnedVersion("4.17.20", "npm")).toBe("4.17.20");
    expect(pinnedVersion("^4.17.20", "npm")).toBeNull();
    expect(pinnedVersion("==2.3.3", "pypi")).toBe("2.3.3");
    expect(pinnedVersion(">=2", "pypi")).toBeNull();
  });
});

describe("lookalikes", () => {
  it("edit distance", () => {
    expect(editDistance("express", "expres")).toBe(1);
    expect(editDistance("requests", "reqeusts")).toBe(2);
    expect(editDistance("abc", "abcdefgh", 2)).toBe(3);
  });
  it("finds the popular package a name imitates; popular and short names are not lookalikes", () => {
    expect(lookalikeOf("expres", "npm")).toBe("express");
    expect(lookalikeOf("reqeusts", "pypi")).toBe("requests");
    expect(lookalikeOf("express", "npm")).toBeNull();
    expect(lookalikeOf("reakt", "npm")).toBe("react");
    expect(lookalikeOf("vue", "npm")).toBeNull();
    expect(lookalikeOf("totally-unrelated-name", "npm")).toBeNull();
  });
});

describe("checkPackages (mocked registry, no network)", () => {
  const now = new Date("2026-10-30T00:00:00Z");
  const old = { time: { created: "2015-01-01T00:00:00Z" }, versions: Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`1.0.${i}`, {}])) };

  it("made-up, lookalike, brand-new, vulnerable and unknown", async () => {
    const calls: string[] = [];
    const fetcher = mockFetcher({
      "https://registry.npmjs.org/reqeusts-helper": { status: 404 },
      "https://registry.npmjs.org/expres": { status: 200, json: { time: { created: "2024-01-01T00:00:00Z" }, versions: { "1.0.0": {} } } },
      "https://api.npmjs.org/downloads/point/last-week/expres": { status: 200, json: { downloads: 12 } },
      "https://registry.npmjs.org/react": { status: 200, json: old },
      "https://registry.npmjs.org/fresh-thing": { status: 200, json: { time: { created: "2026-10-27T00:00:00Z" }, versions: { "0.0.1": {} } } },
      "https://registry.npmjs.org/lodash": { status: 200, json: old },
      "https://api.osv.dev/v1/querybatch": { status: 200, json: { results: [{ vulns: [{ id: "GHSA-test-0001" }] }] } },
      "https://api.osv.dev/v1/vulns/GHSA-test-0001": { status: 200, json: { database_specific: { severity: "HIGH" }, affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] } },
      "https://pypi.org/pypi/reqeusts/json": { status: 200, json: { releases: { "0.1": [{ upload_time_iso_8601: "2025-01-01T00:00:00Z" }] } } },
      "https://registry.npmjs.org/flaky": { status: 503 },
    }, calls);
    const r = await checkPackages([
      { name: "reqeusts-helper", ecosystem: "npm" }, { name: "expres", ecosystem: "npm" }, { name: "react", ecosystem: "npm", spec: "^18" },
      { name: "fresh-thing", ecosystem: "npm" }, { name: "lodash", ecosystem: "npm", spec: "4.17.20" }, { name: "reqeusts", ecosystem: "pypi" },
      { name: "flaky", ecosystem: "npm" },
    ], { fetcher, now });

    const by = (n: string) => r.findings.filter((f) => f.name === n).map((f) => `${f.issue}:${f.severity}`);
    expect(by("reqeusts-helper")).toEqual(["made_up:fix_now"]);
    expect(by("expres")).toEqual(["lookalike:fix_week"]);
    expect(by("react")).toEqual([]);
    expect(by("fresh-thing")).toEqual(["brand_new:fix_week"]);
    expect(by("lodash")).toEqual(["vulnerable:fix_now"]);
    expect(by("reqeusts")).toEqual(["lookalike:fix_week"]);
    expect(r.unknown).toEqual([{ name: "flaky", ecosystem: "npm" }]);
    expect(r.findings[0]!.issue).toBe("made_up");
    const lodash = r.findings.find((f) => f.name === "lodash")!;
    expect(packageMessage(lodash)).toBe("This version has a known security problem (GHSA-test-0001). Update it. Fixed in 4.17.21.");
    expect(packageMessage(r.findings.find((f) => f.name === "reqeusts-helper")!)).toMatch(/^This package doesn't exist on npm\./);
    // The OSV batch only asked about the exact pin, never the range.
    const osv = calls.filter((c) => c.includes("querybatch"));
    expect(osv).toHaveLength(1);
    // Every request went to one of the four public hosts.
    for (const c of calls) expect(new URL(c.split(" ")[1]!).hostname).toMatch(/^(registry\.npmjs\.org|api\.npmjs\.org|pypi\.org|api\.osv\.dev)$/);
  });

  it("an established package is not called a lookalike", async () => {
    const fetcher = mockFetcher({ "https://registry.npmjs.org/expres": { status: 200, json: old } });
    const r = await checkPackages([{ name: "expres", ecosystem: "npm" }], { fetcher, now });
    expect(r.findings).toEqual([]);
  });

  it("the real fetcher refuses any host outside the four registries, and plain http", async () => {
    const f = vi.fn();
    const fetcher = packageFetcher(f as unknown as typeof fetch);
    expect(await fetcher("https://example.com/anything")).toEqual({ status: 0 });
    expect(await fetcher("http://registry.npmjs.org/react")).toEqual({ status: 0 });
    expect(await fetcher("not a url")).toEqual({ status: 0 });
    expect(f).not.toHaveBeenCalled();
  });

  it("the real fetcher passes allowed requests through with no redirects and a timeout", async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ ok: 1 }), { status: 200 }));
    const r = await packageFetcher(f as unknown as typeof fetch)("https://registry.npmjs.org/react");
    expect(r).toEqual({ status: 200, json: { ok: 1 } });
    const init = (f.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(init.redirect).toBe("error");
    expect(init.signal).toBeDefined();
  });
});
