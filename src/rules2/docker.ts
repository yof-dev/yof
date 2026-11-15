/**
 * Family 7, Dockerfiles, beyond the two existing rules (inside.docker_root, inside.docker_latest in ../config.ts).
 *
 *   inside.docker_secret_env         ENV or ARG with a name that says password / secret / token / key and a literal
 *                                    value (it stays in the image's layers and history). needs_validation.
 *   inside.docker_remote_script      ADD from a URL with no --checksum, or a download piped straight into a shell
 *                                    (curl ... | sh). needs_validation.
 *   inside.docker_ssh                an SSH server in the image: EXPOSE 22, openssh-server installed, or sshd started.
 *                                    A hardening note.
 *   inside.docker_no_digest          FROM with a version tag but no @sha256 digest. A hardening note, one per file.
 *   inside.docker_unpinned_packages  package installs without a version (apt-get, apk, pip, npm -g, gem). A note,
 *                                    one per file.
 *   inside.docker_base_eol           FROM an official image whose release line is past its end of life, by the dated
 *                                    table in ./base-images.ts (the table's date is on the finding). needs_validation.
 * yof reads the Dockerfile only. It does not pull or scan images or their operating-system packages.
 * GUARDS: ARG with no default; values that are placeholders or ${VAR}; names that end in _FILE, _PATH, _URL, _NAME;
 * build stages (FROM builder), scratch and FROM $ARG; a FROM that inside.docker_latest already reports; a RUN that
 * installs from a lock file or a requirements file.
 * KNOWN RISKS of a false alarm: a non-secret build argument with a secret-sounding name; a vendor install script the
 * team trusts on purpose.
 */
import { BASE_IMAGE_TABLE_DATE, eolOf } from "./base-images";
import { finding, isPlaceholderValue, maskValue, maskedLine, nameWords, type R2File, type R2Finding } from "./types";

export const isDockerfile = (p: string): boolean => /(?:^|\/)(?:Dockerfile(?:\.[\w-]+)?|[\w.-]+\.dockerfile|Containerfile)$/i.test(p);

/** Does a setting's name say it holds a credential (wider than a password: tokens and keys too)? */
export function isCredName(name: string): boolean {
  const w = nameWords(name);
  if (!w.length) return false;
  const last = w[w.length - 1]!;
  if (/^(?:file|path|dir|url|uri|name|header|ttl|expiry|expires|length|len|type|rounds|algorithm|alg|id|ids|prefix|suffix|enabled|required|version|timeout|size|count|limit|policy|regex|pattern|format|field|label|placeholder)$/.test(last)) return false;
  const joined = w.join("_");
  if (/(?:^|_)(?:public|pub)_key$|publishable|(?:^|_)key_(?:id|name|file|path)$|(?:^|_)no_|(?:^|_)(?:use|has|is|allow|enable|disable|skip)_/.test(joined)) return false;
  if (/(?:passw(?:or)?d|passwd|pwd|secret|token|apikey|credentials?|passphrase)$/.test(last)) return true;
  return /(?:^|_)(?:api|access|private|secret|auth|signing|encryption|master|license|licence)_key$/.test(joined);
}
export const literalSecret = (v: string): boolean => v.length >= 4 && !isPlaceholderValue(v) && !/[${}<>]|^\$|^%/.test(v) && !/^(?:true|false|yes|no|on|off|\d{1,3})$/i.test(v);

interface Instr { op: string; args: string; line: number }

/** The instructions of a Dockerfile, with line continuations joined and comments dropped. */
export function dockerInstructions(content: string): Instr[] {
  const out: Instr[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    let text = lines[i]!.replace(/\r$/, "");
    if (/^\s*#/.test(text) || !text.trim()) continue;
    const start = i;
    while (/\\\s*$/.test(text) && i + 1 < lines.length) {
      i++;
      const next = lines[i]!.replace(/\r$/, "");
      if (/^\s*#/.test(next)) { continue; }
      text = `${text.replace(/\\\s*$/, " ")}${next}`;
    }
    const m = /^\s*([A-Za-z]+)\s+([\s\S]*)$/.exec(text);
    if (m) out.push({ op: m[1]!.toUpperCase(), args: m[2]!.trim(), line: start + 1 });
  }
  return out;
}

/** KEY=value pairs of an ENV or ARG line (also the old `ENV KEY value` form). */
function pairs(op: string, args: string): [string, string][] {
  const out: [string, string][] = [];
  const re = /([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)/g;
  for (let m = re.exec(args); m; m = re.exec(args)) out.push([m[1]!, m[2]!.replace(/^["']|["']$/g, "")]);
  if (!out.length && op === "ENV") { const m = /^([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$/.exec(args); if (m) out.push([m[1]!, m[2]!.trim().replace(/^["']|["']$/g, "")]); }
  return out;
}

const PIPE_TO_SHELL = /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+-c\s+["']\$\(\s*(?:curl|wget)\b|\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b/;

export function dockerFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  const ins = dockerInstructions(f.content);
  const lines = f.content.split("\n");
  const aliases = new Set<string>();
  const noDigest: { image: string; line: number }[] = [];
  const unpinned: { tool: string; names: string[]; line: number }[] = [];
  let ssh: { what: string; line: number } | null = null;

  for (const i of ins) {
    if (i.op === "FROM") {
      const m = /^(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(i.args);
      if (!m) continue;
      const image = m[1]!;
      const isStage = aliases.has(image.toLowerCase());
      if (m[2]) aliases.add(m[2].toLowerCase());
      if (isStage || image.toLowerCase() === "scratch" || image.includes("$")) continue;
      const name = image.split("@")[0]!;
      const tag = name.lastIndexOf(":") > name.lastIndexOf("/") ? name.slice(name.lastIndexOf(":") + 1) : "";
      for (const hit of eolOf(image)) {
        out.push(finding("inside.docker_base_eol", f, i.line, {
          image: image.slice(0, 120), release: `${hit.image} ${hit.line}`, end_of_life: hit.eol, table_date: BASE_IMAGE_TABLE_DATE,
          part: hit.part === "os" ? "the operating system in the tag" : "the image", not_checked: "built images and their operating-system packages are not scanned",
        }, { key: `${name}|${hit.image}|${hit.line}` }));
      }
      if (tag && tag !== "latest" && !image.includes("@sha256:")) noDigest.push({ image, line: i.line });
      continue;
    }
    if (i.op === "ENV" || i.op === "ARG") {
      for (const [k, v] of pairs(i.op, i.args)) {
        if (!isCredName(k) || !literalSecret(v)) continue;
        out.push(finding("inside.docker_secret_env", f, i.line, { name: k.slice(0, 80), instruction: i.op }, { key: `${i.op}|${k}`, masked: maskValue(v), snippet: maskedLine(lines[i.line - 1] ?? "", v) }));
      }
      continue;
    }
    if (i.op === "ADD") {
      const src = i.args.split(/\s+/).filter((a) => !a.startsWith("--"));
      if (/^https?:\/\//i.test(src[0] ?? "") && !/--checksum=/.test(i.args)) out.push(finding("inside.docker_remote_script", f, i.line, { what: "ADD from a URL with no checksum", url: (src[0] ?? "").slice(0, 120) }, { key: `ADD|${src[0]}` }));
      continue;
    }
    if (i.op === "EXPOSE") { if (!ssh && /(?:^|\s)22(?:\/tcp)?(?:\s|$)/.test(i.args)) ssh = { what: "EXPOSE 22", line: i.line }; continue; }
    if (i.op === "CMD" || i.op === "ENTRYPOINT") { if (!ssh && /\bsshd\b/.test(i.args)) ssh = { what: "sshd is started", line: i.line }; continue; }
    if (i.op !== "RUN") continue;
    const cmd = i.args.replace(/^(?:--\S+\s+)+/, "");
    if (PIPE_TO_SHELL.test(cmd)) out.push(finding("inside.docker_remote_script", f, i.line, { what: "a download is piped into a shell" }, { key: `RUN|${cmd.replace(/\s+/g, " ").slice(0, 120)}` }));
    if (!ssh && /\b(?:openssh-server|sshd)\b/.test(cmd)) ssh = { what: /openssh-server/.test(cmd) ? "openssh-server is installed" : "sshd is started", line: i.line };
    for (const part of cmd.split(/&&|;|\|\|/)) {
      const words = part.trim().split(/\s+/);
      const take = (from: number, ok: (w: string) => boolean): string[] => words.slice(from).filter((w) => w && !w.startsWith("-") && !/^[<>|&]/.test(w) && !w.includes("$") && !ok(w));
      let tool = "", names: string[] = [];
      const idx = (re: RegExp) => words.findIndex((w) => re.test(w));
      if (/^(?:sudo\s+)?apt(?:-get)?\s/.test(part.trim()) && idx(/^install$/) !== -1) { tool = "apt"; names = take(idx(/^install$/) + 1, (w) => w.includes("=") || /\.deb$/.test(w)); }
      else if (/^(?:sudo\s+)?apk\s/.test(part.trim()) && idx(/^add$/) !== -1) { tool = "apk"; names = take(idx(/^add$/) + 1, (w) => /[=~<>]/.test(w) || w.startsWith(".")); }
      else if (/^(?:python3?\s+-m\s+)?pip3?\s/.test(part.trim()) && idx(/^install$/) !== -1) {
        if (/\s(?:-r|--requirement|-e|--editable|-c|--constraint|--require-hashes)\b/.test(part)) continue;
        tool = "pip"; names = take(idx(/^install$/) + 1, (w) => /[=<>~@]/.test(w) || /^[./]/.test(w) || /\.(?:whl|tar\.gz|zip)$/.test(w) || /^(?:pip|setuptools|wheel)$/.test(w));
      }
      else if (/^(?:npm\s+(?:install|i|add)|yarn\s+global\s+add|pnpm\s+add)\s/.test(part.trim()) && /\s(?:-g|--global|global)\b/.test(part)) { tool = "npm"; names = take(words[0] === "yarn" ? 3 : 2, (w) => /.@/.test(w) || /^(?:install|i|add|global)$/.test(w)); }
      else if (/^gem\s+install\s/.test(part.trim())) { if (/\s(?:-v|--version)\b/.test(part)) continue; tool = "gem"; names = take(2, (w) => w.includes(":")); }
      if (tool && names.length) unpinned.push({ tool, names, line: i.line });
    }
  }
  if (ssh) out.push(finding("inside.docker_ssh", f, ssh.line, { what: ssh.what }, { key: "ssh" }));
  if (noDigest.length) out.push(finding("inside.docker_no_digest", f, noDigest[0]!.line, { images: [...new Set(noDigest.map((x) => x.image))].slice(0, 6).join(", "), count: String(noDigest.length) }, { key: "no-digest" }));
  if (unpinned.length) {
    const tools = [...new Set(unpinned.map((u) => u.tool))];
    const names = [...new Set(unpinned.flatMap((u) => u.names))];
    out.push(finding("inside.docker_unpinned_packages", f, unpinned[0]!.line, { tools: tools.join(", "), packages: names.slice(0, 8).join(", "), count: String(names.length) }, { key: "unpinned-packages" }));
  }
  return out;
}
