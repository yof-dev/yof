import { describe, expect, it } from "vitest";
import { matchesGitignore, matchesIgnore, parseGitignore, parseYofYml } from "../src/config";

describe(".yof.yml", () => {
  it("defaults to balanced with nothing ignored", () => {
    expect(parseYofYml(null)).toEqual({ profile: "balanced", ignore: [] });
    expect(parseYofYml("")).toEqual({ profile: "balanced", ignore: [] });
  });
  it("reads profile and a block ignore list, with comments and quotes", () => {
    const cfg = parseYofYml(["# yof settings", "profile: strict  # tight", "ignore:", "  - fixtures/", '  - "**/*.snap"', "  - 'docs/old.md'", "other: 1", "  - not-this"].join("\n"));
    expect(cfg).toEqual({ profile: "strict", ignore: ["fixtures/", "**/*.snap", "docs/old.md"] });
  });
  it("reads an inline ignore list", () => {
    expect(parseYofYml('profile: "relaxed"\nignore: [a, "b/c", \'*.txt\']').ignore).toEqual(["a", "b/c", "*.txt"]);
  });
  it("ignores unknown profiles and caps the list at 50", () => {
    const cfg = parseYofYml(`profile: paranoid\nignore:\n${Array.from({ length: 60 }, (_, i) => `  - f${i}`).join("\n")}`);
    expect(cfg.profile).toBe("balanced");
    expect(cfg.ignore).toHaveLength(50);
  });
});

describe("ignore matching", () => {
  it(".yof.yml entries: paths, folders and globs", () => {
    expect(matchesIgnore("fixtures/a.ts", "fixtures/")).toBe(true);
    expect(matchesIgnore("fixtures/a.ts", "fixtures")).toBe(true);
    expect(matchesIgnore("fixturesX/a.ts", "fixtures")).toBe(false);
    expect(matchesIgnore("src/a.snap", "**/*.snap")).toBe(true);
    expect(matchesIgnore("a.snap", "*.snap")).toBe(true);
    expect(matchesIgnore("src/a.snap", "*.snap")).toBe(false);
    expect(matchesIgnore("./docs/x.md", "./docs/x.md")).toBe(false);
    expect(matchesIgnore("docs/x.md", "./docs/x.md")).toBe(true);
  });
  it(".gitignore: plain names at any depth, anchored paths, folder-only entries; negations skipped", () => {
    const g = parseGitignore("# c\n*.log\n/out\nsecrets/\n!keep.log\n\n");
    expect(g).toEqual(["*.log", "/out", "secrets/"]);
    expect(matchesGitignore("a/b/debug.log", "*.log")).toBe(true);
    expect(matchesGitignore("out/x.js", "/out")).toBe(true);
    expect(matchesGitignore("src/out/x.js", "/out")).toBe(false);
    expect(matchesGitignore("a/secrets/k.txt", "secrets/")).toBe(true);
    expect(matchesGitignore("a/secrets", "secrets/")).toBe(false);
  });
});
