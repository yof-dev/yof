/**
 * Family 7, Kubernetes manifests (plain YAML, read with ./yaml-lite.ts). Helm templates ({{ ... }}) and files with
 * anchors are not read exactly, so they give no finding at all; rendered manifests are read like any other.
 * Workloads read: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob.
 *
 *   inside.k8s_privileged            a container with securityContext.privileged: true, or capabilities that add
 *                                    ALL or SYS_ADMIN. confirmed (the file says so).
 *   inside.k8s_host_access           hostNetwork / hostPID / hostIPC: true, or a hostPath volume. confirmed.
 *   inside.k8s_secret_env            a container env entry whose name says password / secret / token / key with a
 *                                    literal value (not valueFrom); a Secret or ConfigMap manifest with such values
 *                                    committed. needs_validation.
 *   inside.k8s_run_as_root           runAsUser: 0, or no runAsNonRoot: true at pod or container level. A note.
 *   inside.k8s_privilege_escalation  allowPrivilegeEscalation not set to false. A note.
 *   inside.k8s_no_limits             a container with no resources.limits. A note.
 *   inside.k8s_latest_tag            an image with no tag or :latest (and no digest). A note.
 * One finding per workload and rule, naming the containers.
 * GUARDS: workloads in the kube-system namespace are not judged for host access; SealedSecret and ExternalSecret are
 * other kinds and never match; placeholders and ${VAR} values are not secrets.
 * KNOWN RISKS of a false alarm: a node agent (logging, monitoring, CNI) that needs the host on purpose; a cluster
 * where an admission policy already forces these settings. yof reads the files, never the cluster.
 */
import { isCredName, literalSecret } from "./docker";
import { finding, lineText, maskValue, maskedLine, type R2File, type R2Finding } from "./types";
import { parseYaml, yBool, yGet, yItems, yPath, yStr, type YNode } from "./yaml-lite";

const WORKLOADS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);
export const mayBeK8s = (p: string, content: string): boolean =>
  /\.ya?ml$/i.test(p) && !/^\.github\//.test(p) && !/(?:^|\/)(?:docker-)?compose[\w.-]*\.ya?ml$/i.test(p) && /^apiVersion\s*:/m.test(content) && /^kind\s*:/m.test(content);

function podSpec(doc: YNode, kind: string): YNode | null {
  if (kind === "Pod") return yGet(doc, "spec");
  if (kind === "CronJob") return yPath(doc, "spec", "jobTemplate", "spec", "template", "spec");
  return yPath(doc, "spec", "template", "spec");
}

export function k8sFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  for (const doc of parseYaml(f.content)) {
    if (!doc || doc.t !== "map") continue;
    const kind = yStr(yGet(doc, "kind")) ?? "";
    const name = yStr(yPath(doc, "metadata", "name")) ?? "";
    const ns = yStr(yPath(doc, "metadata", "namespace")) ?? "";
    const id = `${kind}/${name || "(unnamed)"}`;
    const hit = (rule: string, line: number, what: string, extra: Record<string, string> = {}, x: { masked?: string; snippet?: string } = {}) =>
      out.push(finding(rule, f, line, { workload: id.slice(0, 120), what, live: "not_checked", ...extra }, { key: `${id}|${rule}|${extra.name ?? what}`, ...x }));

    if (kind === "Secret" || kind === "ConfigMap") {
      for (const section of kind === "Secret" ? ["stringData", "data"] : ["data"]) {
        const data = yGet(doc, section);
        if (!data || data.t !== "map") continue;
        for (const e of data.entries) {
          const v = yStr(e.value);
          if (v === null) continue;
          const real = section === "data" && kind === "Secret" ? v.length >= 8 && /^[A-Za-z0-9+/=\s]+$/.test(v) : literalSecret(v);
          if (!real || (kind === "ConfigMap" && !isCredName(e.key))) continue;
          hit("inside.k8s_secret_env", e.line, kind === "Secret" ? "a Secret manifest with its value committed" : "a secret value in a ConfigMap", { name: e.key.slice(0, 80) }, { masked: maskValue(v), snippet: maskedLine(lineText(f.content, e.line), v) });
        }
      }
      continue;
    }
    if (!WORKLOADS.has(kind)) continue;
    const spec = podSpec(doc, kind);
    if (!spec || spec.t !== "map") continue;

    if (ns !== "kube-system") {
      for (const k of ["hostNetwork", "hostPID", "hostIPC"]) if (yBool(yGet(spec, k)) === true) hit("inside.k8s_host_access", yGet(spec, k)!.line, `${k}: true`);
      for (const v of yItems(yGet(spec, "volumes"))) {
        const hp = yGet(v, "hostPath");
        if (hp) hit("inside.k8s_host_access", hp.line, "a hostPath volume", { path: (yStr(yGet(hp, "path")) ?? "").slice(0, 120), name: `hostPath ${yStr(yGet(v, "name")) ?? ""}` });
      }
    }

    const podSc = yGet(spec, "securityContext");
    const containers = [...yItems(yGet(spec, "containers")), ...yItems(yGet(spec, "initContainers"))];
    const root: string[] = [], escal: string[] = [], noLimits: string[] = [], latest: string[] = [];
    let firstLine = spec.line;
    for (const c of containers) {
      if (c.t !== "map") continue;
      const cname = yStr(yGet(c, "name")) ?? "(unnamed)";
      const sc = yGet(c, "securityContext");
      if (firstLine === spec.line) firstLine = c.line;

      if (yBool(yGet(sc, "privileged")) === true) hit("inside.k8s_privileged", yGet(sc, "privileged")!.line, "privileged: true", { container: cname, name: `${cname} privileged` });
      for (const cap of yItems(yPath(sc, "capabilities", "add"))) { const v = (yStr(cap) ?? "").toUpperCase(); if (v === "ALL" || v === "SYS_ADMIN") hit("inside.k8s_privileged", cap.line, `capabilities add ${v}`, { container: cname, name: `${cname} ${v}` }); }

      const user = yStr(yGet(sc, "runAsUser")) ?? yStr(yGet(podSc, "runAsUser"));
      const nonRoot = yBool(yGet(sc, "runAsNonRoot")) ?? yBool(yGet(podSc, "runAsNonRoot"));
      if (user === "0" || (nonRoot !== true && (user === null || !/^[1-9]\d*$/.test(user)))) root.push(cname);
      if (yBool(yGet(sc, "allowPrivilegeEscalation")) !== false) escal.push(cname);
      const limits = yPath(c, "resources", "limits");
      if (!limits || limits.t !== "map" || !limits.entries.length) noLimits.push(cname);

      const image = yStr(yGet(c, "image")) ?? "";
      if (image && !image.includes("@sha256:") && !/[${}]/.test(image)) {
        const last = image.slice(image.lastIndexOf("/") + 1);
        if (!last.includes(":") || /:latest$/.test(last)) latest.push(`${cname} (${image.slice(0, 80)})`);
      }

      for (const e of yItems(yGet(c, "env"))) {
        const en = yStr(yGet(e, "name")) ?? "";
        const ev = yGet(e, "value");
        const v = yStr(ev);
        if (!ev || v === null || !isCredName(en) || !literalSecret(v)) continue;
        hit("inside.k8s_secret_env", ev.line, "a secret value written in env", { container: cname, name: en.slice(0, 80) }, { masked: maskValue(v), snippet: maskedLine(lineText(f.content, ev.line), v) });
      }
    }
    const list = (names: string[]) => ({ containers: names.slice(0, 8).join(", "), count: String(names.length) });
    if (root.length) hit("inside.k8s_run_as_root", firstLine, "no runAsNonRoot: true, or runAsUser: 0", list(root));
    if (escal.length) hit("inside.k8s_privilege_escalation", firstLine, "allowPrivilegeEscalation is not false", list(escal));
    if (noLimits.length) hit("inside.k8s_no_limits", firstLine, "no resources.limits", list(noLimits));
    if (latest.length) hit("inside.k8s_latest_tag", firstLine, "an image with no fixed version", list(latest));
  }
  return out;
}
