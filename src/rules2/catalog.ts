/**
 * THE list of the second rule set: every rule's family, urgency, evidence basis, whether it is on by default, whether
 * it needs the TypeScript compiler, and which languages it reads. The hosted check and the CLI both read this list,
 * and tests pin that the shared catalogue (packages/shared/src/yof-rules-inside2.ts) agrees with it rule by rule.
 *
 *   basis "pattern"   the code matches a risky pattern; yof did not run it. The finding is needs_validation.
 *   basis "exact"     the pattern alone is the defect and the file says it in so many words. confirmed.
 *   basis "practice"  good practice that is missing. A hardening note, never a finding.
 * A rule that could not be made precise would be listed with on: false and its reason in `off`; the run skips it
 * unless it is asked for by id. Today every rule is on.
 */
export type R2Family = "injection" | "csrf" | "deserialization" | "crypto" | "passwords" | "uploads" | "containers";
export const R2_FAMILIES: readonly R2Family[] = ["injection", "csrf", "deserialization", "crypto", "passwords", "uploads", "containers"];
export type R2Severity = "fix_now" | "fix_week" | "nice";
export type R2Basis = "pattern" | "exact" | "practice";
/** Which inside check a rule's findings are counted under (the hosted run marks them fixed only when that check ran). */
export type R2Kind = "code" | "secrets" | "config";

export interface R2Rule {
  id: string; family: R2Family; severity: R2Severity; basis: R2Basis; kind: R2Kind;
  on: boolean; off?: string;
  /** Needs the TypeScript compiler for its JavaScript / TypeScript form (the text forms run without it). */
  ast: boolean;
  languages: string;
}
const r = (id: string, family: R2Family, severity: R2Severity, basis: R2Basis, kind: R2Kind, ast: boolean, languages: string): R2Rule => ({ id, family, severity, basis, kind, on: true, ast, languages });
const JS = "JavaScript, TypeScript";

export const R2_RULES: readonly R2Rule[] = [
  r("inside.code_sql_injection", "injection", "fix_now", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_nosql_injection", "injection", "fix_now", "pattern", "code", true, JS),
  r("inside.code_command_injection", "injection", "fix_now", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_template_injection", "injection", "fix_now", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_eval_input", "injection", "fix_now", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_xss_sink", "injection", "fix_week", "pattern", "code", true, JS),
  r("inside.code_open_redirect", "injection", "fix_week", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_ssrf", "injection", "fix_week", "pattern", "code", true, `${JS}, Python`),
  r("inside.code_csrf_missing", "csrf", "fix_week", "pattern", "code", true, `${JS} (Express with express-session or cookie-session)`),
  r("inside.code_cookie_flags", "csrf", "nice", "practice", "code", true, JS),
  r("inside.code_unsafe_deserialize", "deserialization", "fix_now", "pattern", "code", true, `${JS}, Python, PHP, Ruby`),
  r("inside.crypto_weak_hash", "crypto", "fix_week", "pattern", "code", true, `${JS}, Python, PHP`),
  r("inside.crypto_math_random", "crypto", "fix_week", "pattern", "code", true, `${JS}, Python`),
  r("inside.crypto_hardcoded_key", "crypto", "fix_week", "pattern", "code", true, `${JS}, Python`),
  r("inside.crypto_ecb", "crypto", "fix_week", "exact", "code", true, `${JS}, Python, Java, Kotlin, C#, PHP, Ruby, Go`),
  r("inside.tls_verify_off", "crypto", "fix_week", "exact", "config", true, `${JS}, Python, Go, .env files, Dockerfiles, shell scripts, YAML`),
  r("inside.code_jwt_unverified", "crypto", "fix_now", "exact", "code", true, `${JS}, Python`),
  r("inside.cred_password_literal", "passwords", "fix_week", "pattern", "secrets", false, "any code language; YAML, TOML, INI, properties, JSON"),
  r("inside.cred_default_login", "passwords", "fix_week", "pattern", "secrets", false, "any code language; YAML, TOML, INI, properties, JSON"),
  r("inside.cred_url_password", "passwords", "fix_week", "pattern", "secrets", false, "any text file"),
  r("inside.code_upload_unchecked", "uploads", "fix_week", "pattern", "code", true, `${JS}, Python (Flask), PHP`),
  r("inside.code_upload_served", "uploads", "fix_week", "pattern", "code", true, `${JS} (Express)`),
  r("inside.docker_secret_env", "containers", "fix_week", "pattern", "config", false, "Dockerfile"),
  r("inside.docker_remote_script", "containers", "fix_week", "pattern", "config", false, "Dockerfile"),
  r("inside.docker_ssh", "containers", "nice", "practice", "config", false, "Dockerfile"),
  r("inside.docker_no_digest", "containers", "nice", "practice", "config", false, "Dockerfile"),
  r("inside.docker_unpinned_packages", "containers", "nice", "practice", "config", false, "Dockerfile"),
  r("inside.docker_base_eol", "containers", "fix_week", "pattern", "config", false, "Dockerfile (official node, python, alpine, debian, ubuntu, nginx images)"),
  r("inside.compose_privileged", "containers", "fix_week", "exact", "config", false, "docker-compose"),
  r("inside.compose_docker_socket", "containers", "fix_week", "exact", "config", false, "docker-compose"),
  r("inside.compose_secret_env", "containers", "fix_week", "pattern", "config", false, "docker-compose"),
  r("inside.k8s_privileged", "containers", "fix_week", "exact", "config", false, "Kubernetes YAML"),
  r("inside.k8s_host_access", "containers", "fix_week", "exact", "config", false, "Kubernetes YAML"),
  r("inside.k8s_secret_env", "containers", "fix_week", "pattern", "config", false, "Kubernetes YAML"),
  r("inside.k8s_run_as_root", "containers", "nice", "practice", "config", false, "Kubernetes YAML"),
  r("inside.k8s_privilege_escalation", "containers", "nice", "practice", "config", false, "Kubernetes YAML"),
  r("inside.k8s_no_limits", "containers", "nice", "practice", "config", false, "Kubernetes YAML"),
  r("inside.k8s_latest_tag", "containers", "nice", "practice", "config", false, "Kubernetes YAML"),
  r("inside.tf_open_admin_port", "containers", "fix_week", "pattern", "config", false, "Terraform (AWS, Google Cloud, Azure)"),
  r("inside.tf_public_bucket", "containers", "fix_week", "pattern", "config", false, "Terraform (AWS, Google Cloud, Azure)"),
  r("inside.tf_unencrypted", "containers", "nice", "pattern", "config", false, "Terraform (AWS, Azure)"),
  r("inside.tf_public_database", "containers", "fix_week", "pattern", "config", false, "Terraform (AWS, Google Cloud, Azure)"),
  r("inside.tf_hardcoded_credentials", "containers", "fix_now", "pattern", "config", false, "Terraform, tfvars"),
];
export const R2_RULE_BY_ID: Readonly<Record<string, R2Rule>> = Object.fromEntries(R2_RULES.map((x) => [x.id, x]));
export const isRules2Rule = (id: string): boolean => !!R2_RULE_BY_ID[id];

/** What each family reads, and what stays outside it. English: the twelve-language lines live in the shared catalogue. */
export const R2_FAMILY_SCOPE: Readonly<Record<R2Family, { checks: string; not: string }>> = {
  injection: { checks: "Request input that reaches a SQL, NoSQL, shell, template, eval, HTML, redirect or server-fetch call in the same function.", not: "Input that travels through another function or file, or comes back from a database." },
  csrf: { checks: "Cookie sessions with state-changing routes and no CSRF check or SameSite setting in the files read; sign-in cookie flags set in code.", not: "What the live app's headers and cookies say (the engagement tests that)." },
  deserialization: { checks: "Object loaders (node-serialize, unsafe YAML, pickle, marshal, PHP unserialize, Ruby Marshal) fed with request input.", not: "Java and .NET object streams, XML external entities." },
  crypto: { checks: "MD5, SHA-1 and unsalted fast hashes for passwords and tokens, Math.random for secrets, fixed keys and IVs, ECB mode, TLS checks switched off, JWTs accepted without a signature.", not: "Key length, protocol versions and certificates of the live service." },
  passwords: { checks: "Passwords written in code and config, default logins, addresses with a password inside.", not: "Passwords in the git history of deleted files, and whether a password found is still valid." },
  uploads: { checks: "Upload handlers that keep the client's file name or content type, and upload folders served as pages.", not: "What the storage service or the CDN does with the file." },
  containers: { checks: "Dockerfiles, docker-compose files, Kubernetes manifests and Terraform files: secrets, privileges, host access, public or unencrypted cloud resources, end-of-life base images from a dated table.", not: "Built images and their operating-system packages, the running cluster and the cloud account itself." },
};
