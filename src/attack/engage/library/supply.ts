/**
 * yof engagement, attack library: SUPPLY CHAIN, as a thin adapter. yof already checks the linked repository's
 * dependencies, lockfiles, licences and build files (packages/api/src/lib/yof/inside: deps, lockfiles, licences,
 * registry, config). This file RUNS NO NEW CHECK. It brings those existing results into the engagement as rows under
 * their own rule ids, so the coverage ledger can record that the supply chain was covered and by which check.
 *
 * Nothing is sent to the app here, and nothing is fetched: the rows come from check results the caller already has
 * (target.checks). A row keeps the outcome its check gave and its own rule id; the engagement never upgrades it.
 */
import { notTestable, result } from "./kit";
import type { CheckRow, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";

/** The rule-id families this adapter brings in (vulnerable, made-up, look-alike or malicious packages, licences, build). */
export const SUPPLY_FAMILIES: readonly string[] = [
  "inside.dep_", "inside.licence_", "inside.docker_", "inside.gha_", "inside.mcp_", "inside.no_update_automation",
];
export const matchesSupply = (ruleId: string): boolean => SUPPLY_FAMILIES.some((f) => ruleId.startsWith(f));

/** The check rows this adapter owns, in input order. Pure. */
export const supplyRows = (checks: readonly CheckRow[]): CheckRow[] => checks.filter((c) => matchesSupply(c.rule_id));

type Head = Omit<Technique, "run" | "chain">;
const HEAD: Head = {
  id: "supply.chain", ruleId: "inside.dep_vulnerable", title: "Dependencies, lockfiles, licences and build files",
  invariants: ["auth_required"], prerequisites: ["check_results"], safetyClass: "read", classes: ["read"], payloads: [],
  oracle: "No oracle: this brings yof's existing dependency, lockfile, licence and build checks into the engagement; each row keeps its own rule id and result.",
  shows: "which of yof's supply-chain checks ran, and what they found", cannotShow: "anything new: it runs no check of its own and fetches nothing",
  best: "needs_validation", impact: { what: "none", position: "anonymous", reach: "one_object", data: "ordinary" }, owasp: "A06 / A08",
};

export const SUPPLY_TECHNIQUES: readonly Technique[] = [
  {
    ...HEAD,
    chain: () => null,
    run: async (_ctx: TechniqueContext, target: TechniqueTarget): Promise<TechniqueResult> => {
      const rows = supplyRows(target.checks ?? []);
      if (!rows.length) return notTestable(HEAD, "yof's dependency, lockfile, licence and build checks have no result to bring in yet");
      const ids = [...new Set(rows.map((r) => r.rule_id))].sort();
      return result(HEAD, "not_tested", {
        reason: `brought in ${rows.length} result(s) from yof's existing dependency, lockfile, licence and build checks; each keeps its own rule id and result`,
        meta: { kind: "adapter", source: "inside", rules: ids.join(", ").slice(0, 300), count: String(rows.length) },
      });
    },
  },
];
