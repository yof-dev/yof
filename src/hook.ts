/** `yof hook install` / `yof hook uninstall`: a git pre-commit hook that runs `yof check --staged`. */
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { runGit, type GitRunner } from "./files";

export const HOOK_MARKER = "# yof pre-commit hook";
export const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER} (added by \`yof hook install\`, removed by \`yof hook uninstall\`).
# Checks the staged files for leaked keys and made-up packages. Skip once with: git commit --no-verify
exec npx --yes @yof/cli check --staged
`;

export interface HookResult { ok: boolean; message: string; path?: string }

/** Where git looks for the pre-commit hook (respects core.hooksPath and worktrees). */
export function hookPath(cwd: string, git: GitRunner = runGit): string {
  const p = git(["rev-parse", "--git-path", "hooks/pre-commit"], cwd).toString("utf8").trim();
  return isAbsolute(p) ? p : join(cwd, p);
}

function locate(cwd: string, git: GitRunner): string | HookResult {
  try { return hookPath(cwd, git); } catch { return { ok: false, message: "This is not a git repository (run it inside one, or `git init` first)." }; }
}

export function installHook(cwd: string, git: GitRunner = runGit): HookResult {
  const path = locate(cwd, git);
  if (typeof path !== "string") return path;
  if (existsSync(path)) {
    const current = readFileSync(path, "utf8");
    if (!current.includes(HOOK_MARKER)) {
      return { ok: false, path, message: `A pre-commit hook already exists at ${path} and it is not yof's. yof left it alone. To run yof from it, add this line to it:\n  npx --yes @yof/cli check --staged` };
    }
    if (current === HOOK_SCRIPT) return { ok: true, path, message: `The yof pre-commit hook is already installed (${path}).` };
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, HOOK_SCRIPT, "utf8");
  chmodSync(path, 0o755);
  return { ok: true, path, message: `Installed the yof pre-commit hook (${path}). Every commit now checks the staged files first.` };
}

export function uninstallHook(cwd: string, git: GitRunner = runGit): HookResult {
  const path = locate(cwd, git);
  if (typeof path !== "string") return path;
  if (!existsSync(path)) return { ok: true, path, message: "No pre-commit hook is installed. Nothing to remove." };
  if (!readFileSync(path, "utf8").includes(HOOK_MARKER)) return { ok: false, path, message: `The pre-commit hook at ${path} is not yof's. yof left it alone.` };
  unlinkSync(path);
  return { ok: true, path, message: `Removed the yof pre-commit hook (${path}).` };
}
