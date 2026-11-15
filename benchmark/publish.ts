/**
 * Send a scored benchmark run to yof's own API, so yof.io/benchmark shows it (finish list 7.2; owner 13 Nov 2026: "we
 * want yof to be the source of everything"). Used by the last step of .github/workflows/yof-benchmark.yml, and by hand
 * to send a run again after its extra findings were reviewed (docs/YOF_BENCHMARK.md): the API keeps one row per run id,
 * so a second send replaces the first.
 *
 * What is sent is results.json (score.ts) with two additions, both derived from targets.ts, never typed in:
 *   - each found or missed item carries its CHECK FAMILY: the family of the first detector its mapping names (leaked
 *     keys, risky packages, one of yof attack's five groups). An item counts in one family only, so the families add
 *     up to the app's found and missed counts;
 *   - each extra finding carries the family of the yof result that raised it.
 * Items that are not tested or not available are sent as counts only (the page names them in its method section).
 *
 * The key is read from the environment variable YOF_BENCHMARK_INGEST_KEY and sent as a bearer token. It is never
 * printed. With no key, nothing is sent and the command says so (exit 0): a fork or a run without the secret still
 * finishes and uploads its artifact.
 */
import { ATTACK_RULES } from "../src/attack/catalog.ts";
import type { BenchmarkResults, ExtraFinding, ScoredItem, TargetCounts, TargetResult } from "./score.ts";
import { targetById, type Detector } from "./targets.ts";

/** The check families, in the order the page shows them. "code" is the code rules (not scored by the benchmark yet). */
export const FAMILIES = ["keys", "packages", "code", "auth", "tenant", "rbac", "ai", "surface", "other"] as const;
export type Family = (typeof FAMILIES)[number];

const GROUP_OF: Record<string, Family> = Object.fromEntries(ATTACK_RULES.map((r) => [r.id, r.group]));

/** The family of one yof result, from its source and rule id. */
export function familyOfResult(source: "key" | "package" | "attack" | "code", rule: string): Family {
  if (source === "key") return "keys";
  if (source === "package") return "packages";
  if (source === "code") return "code";
  return GROUP_OF[rule] ?? "other";
}

const familyOfDetector = (d: Detector): Family => familyOfResult(d.source, d.source === "attack" ? d.rule : "");

export interface FamilyCounts { family: Family; tested: number; found: number; missed: number; falseAlarms: number; toReview: number }
export type IngestItem = Pick<ScoredItem, "key" | "name" | "category" | "relation" | "note"> & { status: "found" | "missed"; family: Family };
export type IngestExtra = ExtraFinding & { family: Family };
export interface IngestTarget {
  id: string; name: string; repo: string; tag: string | null; commit: string;
  list: { file: string; label: string; items: number };
  ran: boolean; error: string | null;
  counts: TargetCounts | null;
  families: FamilyCounts[];
  items: IngestItem[];
  extra: IngestExtra[];
}
export interface IngestPayload {
  schema: 1;
  run: { id: string; url: string | null; commit: string; yofVersion: string; rulesVersion: string | null; startedAt: string; finishedAt: string | null; runner: string };
  targets: IngestTarget[];
}

function ingestTarget(t: TargetResult): IngestTarget {
  const base = { id: t.id, name: t.name, repo: t.repo, tag: t.tag, commit: t.commit, list: t.list, error: t.error };
  if (!t.ran || !t.counts) return { ...base, ran: false, counts: null, families: [], items: [], extra: [] };
  const target = targetById(t.id);
  if (!target) throw new Error(`Unknown benchmark target: ${t.id}`);
  const mapping = new Map(target.mapping.map((m) => [m.key, m]));
  const items: IngestItem[] = [];
  for (const i of t.items) {
    if (i.status !== "found" && i.status !== "missed") continue;
    const m = mapping.get(i.key);
    if (!m || m.kind !== "tested" || !m.detectors[0]) throw new Error(`${t.id}: ${i.key} is ${i.status} but has no tested mapping.`);
    items.push({ key: i.key, name: i.name, category: i.category, status: i.status, ...(i.relation ? { relation: i.relation } : {}), note: i.note, family: familyOfDetector(m.detectors[0]) });
  }
  const extra = t.extra.map((e) => ({ ...e, family: familyOfResult(e.source, e.rule) }));
  const fam = new Map<Family, FamilyCounts>();
  const at = (f: Family) => { let c = fam.get(f); if (!c) { c = { family: f, tested: 0, found: 0, missed: 0, falseAlarms: 0, toReview: 0 }; fam.set(f, c); } return c; };
  for (const i of items) { const c = at(i.family); c.tested++; if (i.status === "found") c.found++; else c.missed++; }
  for (const e of extra) { if (e.verdict === "false_positive") at(e.family).falseAlarms++; else if (e.verdict === "to_review") at(e.family).toReview++; }
  const families = FAMILIES.filter((f) => fam.has(f)).map((f) => fam.get(f)!);
  return { ...base, ran: true, counts: t.counts, families, items, extra };
}

/** The body sent to the API. Pure: the same results give the same body. */
export function ingestPayload(r: BenchmarkResults, rulesVersion: string | null = null): IngestPayload {
  if (r.status !== "done" || !r.run) throw new Error("Only a finished run can be sent.");
  const run = r.run;
  return {
    schema: 1,
    run: { id: run.id, url: /^https:\/\//.test(run.url) ? run.url : null, commit: run.commit, yofVersion: run.yofVersion, rulesVersion, startedAt: run.startedAt, finishedAt: run.finishedAt ?? null, runner: run.runner },
    targets: r.targets.map(ingestTarget),
  };
}

export const INGEST_PATH = "/api/v1/yof/benchmark/runs";

/** POST the payload. Returns what to print; never prints or returns the key. */
export async function sendRun(payload: IngestPayload, api: string, key: string | undefined, f: typeof fetch = fetch): Promise<{ sent: boolean; message: string }> {
  if (!key) return { sent: false, message: "Not sent: YOF_BENCHMARK_INGEST_KEY is not set for this run." };
  const url = `${api.replace(/\/+$/, "")}${INGEST_PATH}`;
  if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url)) throw new Error("The API address must be https (or localhost).");
  const res = await f(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}`, "User-Agent": "yof-benchmark" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text().catch(() => "");
  if (!res.ok) return { sent: false, message: `Not stored: the API answered HTTP ${res.status} ${text.slice(0, 300)}` };
  return { sent: true, message: `Stored run ${payload.run.id} on yof (HTTP ${res.status}).` };
}
