/**
 * Family 7, docker-compose files (read with ./yaml-lite.ts; a file it cannot read exactly gives no finding).
 *
 *   inside.compose_privileged     a service with privileged: true, network_mode / pid / ipc: host, cap_add ALL or
 *                                 SYS_ADMIN, or security_opt with seccomp or apparmor unconfined. The file says so:
 *                                 confirmed.
 *   inside.compose_docker_socket  a service that mounts the Docker socket (also read-only: the API still answers).
 *                                 confirmed.
 *   inside.compose_secret_env     an environment entry whose name says password / secret / token / key with a
 *                                 literal value. needs_validation.
 * GUARDS: values from the environment (${VAR}), placeholders, entries with no value (passed through from the shell);
 * for compose_secret_env, files named for local work (dev, local, test, override, example, ci).
 * KNOWN RISKS of a false alarm: a tool that needs the socket on purpose (a reverse proxy, a CI runner, a monitor);
 * a throwaway database password in a compose file that is only ever run on a laptop.
 */
import { isCredName, literalSecret } from "./docker";
import { finding, lineText, maskValue, maskedLine, type R2File, type R2Finding } from "./types";
import { parseYaml, yBool, yGet, yItems, yStr, type YNode } from "./yaml-lite";

export const isComposeFile = (p: string): boolean => /(?:^|\/)(?:docker-)?compose(?:[.\-][\w.-]+)?\.ya?ml$/i.test(p);
const LOCAL_ONLY = /(?:^|[.\-/])(?:dev|develop|development|local|test|tests|testing|override|example|sample|ci|e2e)(?:[.\-]|$)/i;

export function composeFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  const localOnly = LOCAL_ONLY.test(f.path.split("/").pop() ?? "");
  for (const doc of parseYaml(f.content)) {
    const services = yGet(doc, "services");
    if (!services || services.t !== "map") continue;
    for (const svc of services.entries) {
      const s = svc.value;
      if (!s || s.t !== "map") continue;
      const hit = (rule: string, node: YNode | { line: number }, what: string, extra: Record<string, string> = {}) =>
        out.push(finding(rule, f, node.line, { service: svc.key.slice(0, 60), what, ...extra }, { key: `${svc.key}|${what}` }));

      if (yBool(yGet(s, "privileged")) === true) hit("inside.compose_privileged", yGet(s, "privileged")!, "privileged: true");
      for (const k of ["network_mode", "pid", "ipc"]) if (yStr(yGet(s, k)) === "host") hit("inside.compose_privileged", yGet(s, k)!, `${k}: host`);
      for (const c of yItems(yGet(s, "cap_add"))) { const v = (yStr(c) ?? "").toUpperCase(); if (v === "ALL" || v === "SYS_ADMIN") hit("inside.compose_privileged", c, `cap_add: ${v}`); }
      for (const o of yItems(yGet(s, "security_opt"))) { const v = (yStr(o) ?? "").replace(/\s+/g, ""); if (/^(?:seccomp|apparmor)[:=]unconfined$/i.test(v)) hit("inside.compose_privileged", o, `security_opt: ${v}`); }

      for (const v of yItems(yGet(s, "volumes"))) {
        const src = v.t === "str" ? v.value.split(":")[0]! : yStr(yGet(v, "source")) ?? "";
        if (/^\/(?:var\/)?run\/docker\.sock$/.test(src.trim())) hit("inside.compose_docker_socket", v, "the Docker socket is mounted", { read_only: v.t === "str" ? (/:ro\b/.test(v.value) ? "yes" : "no") : yBool(yGet(v, "read_only")) === true ? "yes" : "no" });
      }

      if (localOnly) continue;
      const env = yGet(s, "environment");
      const pairs: { name: string; value: string; line: number }[] = [];
      if (env?.t === "map") for (const e of env.entries) { const v = yStr(e.value); if (v !== null) pairs.push({ name: e.key, value: v, line: e.line }); }
      else for (const e of yItems(env)) { const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(yStr(e) ?? ""); if (m) pairs.push({ name: m[1]!, value: m[2]!, line: e.line }); }
      for (const p of pairs) {
        if (!isCredName(p.name) || !literalSecret(p.value)) continue;
        out.push(finding("inside.compose_secret_env", f, p.line, { service: svc.key.slice(0, 60), name: p.name.slice(0, 80) }, { key: `${svc.key}|${p.name}`, masked: maskValue(p.value), snippet: maskedLine(lineText(f.content, p.line), p.value) }));
      }
    }
  }
  return out;
}
