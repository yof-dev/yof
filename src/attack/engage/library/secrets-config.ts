/**
 * yof engagement, attack library: SECRETS AND CONFIGURATION, as a thin adapter. yof already checks for leaked keys,
 * committed secrets, exposed config and loose database grants, from outside the app (packages/api/src/lib/yof/checks)
 * and from inside the linked repository (packages/api/src/lib/yof/inside). This file RUNS NO NEW CHECK. It brings those
 * existing results into the engagement as rows, referencing their own rule ids, so the coverage ledger can say the
 * topic was covered and by which check.
 *
 * Nothing is sent to the app here: the rows come from check results the caller already has (target.checks). A row is
 * carried with the outcome the check gave; the engagement never upgrades it to a demonstration, and the finding keeps
 * its own rule id, never a new one.
 */
import { notTestable, result } from "./kit";
import type { CheckRow, Technique, TechniqueContext, TechniqueResult, TechniqueTarget } from "./types";

/** The rule-id families this adapter brings in (leaked keys, committed secrets, exposed config, loose grants). */
export const SECRETS_FAMILIES: readonly string[] = [
  "secret.", "inside.secret", "inside.env_committed", "inside.firebase_open", "inside.rls_missing", "inside.grant_public",
  "files.env", "files.git", "files.backup", "files.sourcemap", "files.debug",
  "api.key_in_url", "api.live_key_in_url", "api.verbose_errors", "database.",
];
export const matchesSecrets = (ruleId: string): boolean => SECRETS_FAMILIES.some((f) => ruleId.startsWith(f));

/** The check rows this adapter owns, in input order. Pure. */
export const secretsRows = (checks: readonly CheckRow[]): CheckRow[] => checks.filter((c) => matchesSecrets(c.rule_id));

type Head = Omit<Technique, "run" | "chain">;
const HEAD: Head = {
  id: "secrets.config", ruleId: "inside.secret", title: "Leaked keys, secrets and exposed configuration",
  invariants: ["auth_required"], prerequisites: ["check_results"], safetyClass: "read", classes: ["read"], payloads: [],
  oracle: "No oracle: this brings yof's existing key, secret, config and grant checks into the engagement; each row keeps its own rule id and its own result.",
  shows: "which of yof's key, secret, config and grant checks ran, and what they found", cannotShow: "anything new: it runs no check of its own and sends nothing to the app",
  best: "needs_validation", impact: { what: "none", position: "anonymous", reach: "one_object", data: "private" }, owasp: "A05 / A02",
};

export const SECRETS_CONFIG_TECHNIQUES: readonly Technique[] = [
  {
    ...HEAD,
    chain: () => null,
    run: async (_ctx: TechniqueContext, target: TechniqueTarget): Promise<TechniqueResult> => {
      const rows = secretsRows(target.checks ?? []);
      if (!rows.length) return notTestable(HEAD, "yof's key, secret, config and grant checks have no result to bring in yet");
      const ids = [...new Set(rows.map((r) => r.rule_id))].sort();
      return result(HEAD, "not_tested", {
        reason: `brought in ${rows.length} result(s) from yof's existing key, secret, config and grant checks; each keeps its own rule id and result`,
        meta: { kind: "adapter", source: "checks + inside", rules: ids.join(", ").slice(0, 300), count: String(rows.length) },
      });
    },
  },
];
