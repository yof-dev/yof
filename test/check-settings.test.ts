/**
 * yof audit 3.10 (11 Nov 2026):
 *   - a pull request could silence the check on itself (ignore its own folder, relax the profile, "accept" its own
 *     key). On a pull request in CI the settings now come from the base branch;
 *   - a committed file that .gitignore names was never scanned. Tracked files are scanned whatever .gitignore says.
 * Real git in temporary folders, isolated from this machine's git config (helpers.ts testGit).
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { acceptFingerprint } from "../src/accepted";
import { baseSettings, pullRequestBase, runCheck } from "../src/check";
import { main } from "../src/cli";
import { trackedPaths, walkFiles } from "../src/files";
import { formatText } from "../src/format";
import { captureIo, fakeStripeLive, tempDir, testGit } from "./helpers";

const KEY_LINE = `const k = "${fakeStripeLive()}";`;
const git = (dir: string, ...args: string[]) => testGit(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], dir);
const write = (dir: string, files: Record<string, string>) => { for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), c); } };
const PR = (base = "main") => ({ GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: base });

/** A clone whose origin/main is the base branch, checked out on a pull-request branch with `change` on top. */
function pullRequest(base: Record<string, string>, change: Record<string, string>): string {
  const origin = tempDir(base);
  git(origin, "init", "-q", "-b", "main");
  git(origin, "add", "-A", "-f");
  git(origin, "commit", "-q", "-m", "base");
  const work = tempDir();
  git(work, "clone", "-q", origin, "repo");
  const repo = join(work, "repo");
  git(repo, "checkout", "-q", "-b", "feature");
  write(repo, change);
  git(repo, "add", "-A", "-f");
  git(repo, "commit", "-q", "-m", "change");
  return repo;
}
const check = (repo: string, env: Record<string, string> = PR()) => runCheck({ cwd: repo, offline: true, git: testGit, env });

describe("a pull request cannot switch the check off for itself", () => {
  it("knows a pull-request run from GitHub's own variables, and nothing else", () => {
    expect(pullRequestBase(PR())).toBe("main");
    expect(pullRequestBase({ GITHUB_EVENT_NAME: "pull_request_target", GITHUB_BASE_REF: "release/1.x" })).toBe("release/1.x");
    for (const env of [{}, { GITHUB_EVENT_NAME: "push", GITHUB_BASE_REF: "main" }, { GITHUB_EVENT_NAME: "pull_request" }, { GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "--upload-pack=x" }, { GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "a..b" }, { GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "main; rm -rf ." }]) {
      expect(pullRequestBase(env), JSON.stringify(env)).toBeNull();
    }
  });

  it("ignoring its own folder in .yof.yml does not hide the key it adds", async () => {
    const repo = pullRequest({ "src/ok.ts": "export {};\n" }, { "src/leak.ts": KEY_LINE, ".yof.yml": "ignore:\n  - src/\n" });
    // Outside a pull request the folder's own file is read, as before: a person's own settings on their own branch.
    const local = await check(repo, {});
    expect(local).toMatchObject({ failed: false, settings: { from: "folder" } });
    expect(local.ignoredByConfig).toBe(1);
    const pr = await check(repo);
    expect(pr.settings).toEqual({ from: "base", base: "main" });
    expect(pr.failed).toBe(true);
    expect(pr.keys.map((k) => k.file)).toEqual(["src/leak.ts"]);
    expect(pr.ignoredByConfig).toBe(0);
    expect(formatText(pr)).toContain("Pull request: .yof.yml and the accepted risks were read from the base branch (main). Changes to them in this pull request count once it is merged.");
  });

  it("relaxing the profile, or accepting its own key, in the same pull request changes nothing", async () => {
    const accepted = JSON.stringify({ version: 1, accepted: [{ rule: "secret.stripe_live", file: "src/leak.ts", fingerprint: acceptFingerprint("secret.stripe_live", "src/leak.ts", KEY_LINE), reason: "trust me", acceptedBy: "pr", acceptedAt: "2026-11-11T10:00:00.000Z" }] });
    const repo = pullRequest({ "src/ok.ts": "export {};\n", ".yof.yml": "profile: strict\n" }, { "src/leak.ts": KEY_LINE, ".yof.yml": "profile: relaxed\n", ".yof/accepted.json": accepted });
    const local = await check(repo, {});
    expect(local.keys.find((k) => k.file === "src/leak.ts")?.rule).toBe("secret.stripe_live");   // the entry above names the right rule
    expect(local).toMatchObject({ profile: "relaxed", failed: false, acceptedCount: 1 });
    const pr = await check(repo);
    expect(pr).toMatchObject({ profile: "strict", failed: true, acceptedCount: 0, settings: { from: "base", base: "main" } });
  });

  it("the base branch's own ignore list and accepted risks still apply to a pull request", async () => {
    const accepted = JSON.stringify({ version: 1, accepted: [{ rule: "secret.stripe_live", file: "src/known.ts", fingerprint: acceptFingerprint("secret.stripe_live", "src/known.ts", KEY_LINE), reason: "a sample key in the docs", acceptedBy: "Ada", acceptedAt: "2026-11-01T10:00:00.000Z" }] });
    const repo = pullRequest({ "fixtures/a.ts": KEY_LINE, "src/known.ts": KEY_LINE, ".yof.yml": "ignore:\n  - fixtures/\n", ".yof/accepted.json": accepted }, { "src/new.ts": "export const n = 1;\n" });
    const pr = await check(repo);
    expect(pr).toMatchObject({ failed: false, acceptedCount: 1, ignoredByConfig: 1, settings: { from: "base" } });
    expect(formatText(pr)).toContain("1 path left out by the ignore list in .yof.yml.");
  });

  it("a base branch git cannot read: no ignore list, no accepted risks, and the output says how to fetch it", async () => {
    const repo = pullRequest({ "src/ok.ts": "export {};\n" }, { "src/leak.ts": KEY_LINE, ".yof.yml": "ignore:\n  - src/\n" });
    expect(baseSettings(repo, "release", testGit)).toBeNull();
    const pr = await check(repo, PR("release"));
    expect(pr.settings).toEqual({ from: "base_unavailable", base: "release" });
    expect(pr.failed).toBe(true);
    expect(formatText(pr)).toContain('git fetch --no-tags --depth=1 origin "+refs/heads/release:refs/remotes/origin/release"');
  });

  it("works from a subfolder of the repository, and through the command line", async () => {
    const repo = pullRequest({ "app/src/ok.ts": "export {};\n", "app/.yof.yml": "profile: strict\n" }, { "app/src/leak.ts": KEY_LINE, "app/.yof.yml": "ignore:\n  - src/\n" });
    expect(baseSettings(join(repo, "app"), "main", testGit)).toEqual({ yml: "profile: strict\n", accepted: null });
    const { io, cap } = captureIo(join(repo, "app"));
    expect(await main(["check", "--offline"], { ...io, env: PR() })).toBe(1);
    expect(cap.out.join("\n")).toContain("read from the base branch (main)");
    expect(await main(["check", "--offline"], { ...io, env: {} })).toBe(0);
  });

  it("the Action fetches the base branch before it checks a pull request", () => {
    const yml = readFileSync(join(__dirname, "..", "action.yml"), "utf8");
    const fetch = yml.indexOf('git fetch --no-tags --depth=1 origin "+refs/heads/${BASE}:refs/remotes/origin/${BASE}"');
    expect(fetch).toBeGreaterThan(0);
    expect(fetch).toBeLessThan(yml.indexOf('npx --yes "@yof/cli@${YOF_VERSION}"'));
    expect(yml).toContain("if: startsWith(github.event_name, 'pull_request')");
    expect(yml).toContain("BASE: ${{ github.base_ref }}");
  });
});

describe("committed files are scanned whatever .gitignore says", () => {
  it("a committed .env that .gitignore names is found; an untracked one is skipped as before", async () => {
    const repo = tempDir({ ".gitignore": ".env\nsecrets/\n*.local\n", "src/ok.ts": "export {};\n" });
    git(repo, "init", "-q", "-b", "main");
    write(repo, { ".env": KEY_LINE, "secrets/prod.txt": KEY_LINE });
    git(repo, "add", "-A", "-f");
    git(repo, "commit", "-q", "-m", "all");
    write(repo, { "notes.local": KEY_LINE, "secrets/scratch.txt": KEY_LINE });   // ignored AND untracked: not in the repository
    expect([...trackedPaths(repo, testGit)!].sort()).toEqual([".env", ".gitignore", "secrets/prod.txt", "src/ok.ts"]);
    const r = await runCheck({ cwd: repo, offline: true, git: testGit, env: {} });
    expect(r.keys.map((k) => k.file).sort()).toEqual([".env", "secrets/prod.txt"]);
    expect(r.failed).toBe(true);
  });

  it("outside a git repository .gitignore is followed as before", async () => {
    const dir = tempDir({ ".gitignore": ".env\n", ".env": KEY_LINE, "src/ok.ts": "export {};\n" });
    expect(trackedPaths(dir, testGit)).toBeNull();
    const r = await runCheck({ cwd: dir, offline: true, git: testGit, env: {} });
    expect(r.keys).toEqual([]);
    expect(walkFiles(dir, [], [".env"]).files.map((f) => f.path).sort()).toEqual([".gitignore", "src/ok.ts"]);
    expect(walkFiles(dir, [], [".env"], new Set([".env"])).files.map((f) => f.path).sort()).toEqual([".env", ".gitignore", "src/ok.ts"]);
  });

  it("tracked files still honour the skip list and .yof.yml", () => {
    const dir = tempDir({ "node_modules/x/a.js": KEY_LINE, "fixtures/a.ts": KEY_LINE, "src/ok.ts": "export {};\n" });
    const set = walkFiles(dir, ["fixtures/"], [], new Set(["node_modules/x/a.js", "fixtures/a.ts", "src/ok.ts"]));
    expect(set.files.map((f) => f.path)).toEqual(["src/ok.ts"]);
    expect(set.ignored).toBe(1);
  });
});
