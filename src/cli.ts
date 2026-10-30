/** The `yof` command. main() returns the exit code: 0 nothing to fix, 1 something to fix, 2 a usage or setup error. */
import { CheckError, runCheck } from "./check";
import { PROFILES, type Profile } from "./config";
import type { GitRunner } from "./files";
import { formatJson, formatText } from "./format";
import { installHook, uninstallHook } from "./hook";
import type { PackageFetcher } from "./packages";

declare const __YOF_VERSION__: string | undefined;
export const VERSION: string = typeof __YOF_VERSION__ === "string" ? __YOF_VERSION__ : "0.0.0-dev";

export const HELP = `yof: catch leaked keys and made-up packages before they ship.

Usage
  yof check [path]          Check a folder (default: the current one)
  yof check --staged        Check only the files staged for the next commit
  yof hook install          Run "yof check --staged" before every commit
  yof hook uninstall        Remove that pre-commit hook

Options
  --offline                 Skip the package-registry lookups (keys only, no network at all)
  --json                    Print machine-readable JSON
  --profile <name>          relaxed | balanced | strict (overrides .yof.yml)
  -v, --version             Print the version
  -h, --help                Print this help

Exit codes: 0 nothing to fix, 1 something to fix, 2 usage or setup error.
Runs on your machine. Your code is never sent anywhere; the only network calls are
package-registry lookups (npm, PyPI, OSV), which --offline turns off.

More: https://yof.io`;

export interface Io {
  cwd: string;
  out: (s: string) => void;
  err: (s: string) => void;
  fetcher?: PackageFetcher;
  git?: GitRunner;
  now?: Date;
}

const defaultIo = (): Io => ({ cwd: process.cwd(), out: (s) => process.stdout.write(`${s}\n`), err: (s) => process.stderr.write(`${s}\n`) });

export async function main(argv: string[], io: Io = defaultIo()): Promise<number> {
  const flags = new Set<string>();
  const positional: string[] = [];
  let profile: Profile | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--profile" || a.startsWith("--profile=")) {
      const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[++i];
      if (!v || !(PROFILES as readonly string[]).includes(v)) { io.err(`--profile must be one of: ${PROFILES.join(", ")}`); return 2; }
      profile = v as Profile;
    } else if (a.startsWith("-")) flags.add(a);
    else positional.push(a);
  }
  const known = new Set(["--offline", "--json", "--staged", "--version", "-v", "--help", "-h"]);
  for (const f of flags) if (!known.has(f)) { io.err(`Unknown option: ${f}\n\n${HELP}`); return 2; }

  if (flags.has("--version") || flags.has("-v")) { io.out(VERSION); return 0; }
  const [cmd, ...rest] = positional;
  if (flags.has("--help") || flags.has("-h") || !cmd || cmd === "help") { io.out(HELP); return 0; }

  if (cmd === "hook") {
    const sub = rest[0];
    if (sub !== "install" && sub !== "uninstall") { io.err("Usage: yof hook install | yof hook uninstall"); return 2; }
    const r = sub === "install" ? installHook(io.cwd, io.git) : uninstallHook(io.cwd, io.git);
    (r.ok ? io.out : io.err)(r.message);
    return r.ok ? 0 : 2;
  }

  if (cmd === "check") {
    if (rest.length > 1) { io.err("yof check takes one path at most."); return 2; }
    try {
      const report = await runCheck({
        path: rest[0] ?? ".", cwd: io.cwd, staged: flags.has("--staged"), offline: flags.has("--offline"),
        profile, fetcher: io.fetcher, git: io.git, now: io.now,
      });
      io.out(flags.has("--json") ? formatJson(report, { version: VERSION }) : formatText(report));
      return report.failed ? 1 : 0;
    } catch (e) {
      if (e instanceof CheckError) { io.err(e.message); return 2; }
      throw e;
    }
  }

  io.err(`Unknown command: ${cmd}\n\n${HELP}`);
  return 2;
}
