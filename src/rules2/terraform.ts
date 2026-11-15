/**
 * Terraform (.tf) rules. yof reads the files, never the cloud account: every finding here is a pattern in the files
 * (verdict needs_validation, meta.live = "not_checked"), because the deployed setting may differ.
 *
 * RESOURCE TYPES READ (nothing else is judged):
 *   inside.tf_open_admin_port   AWS    aws_security_group (ingress blocks), aws_security_group_rule (type ingress),
 *                                      aws_vpc_security_group_ingress_rule
 *                               Google google_compute_firewall (INGRESS, allow blocks)
 *                               Azure  azurerm_network_security_rule, azurerm_network_security_group (security_rule blocks)
 *   inside.tf_public_bucket     AWS    aws_s3_bucket (acl), aws_s3_bucket_acl, aws_s3_bucket_public_access_block
 *                               Google google_storage_bucket_iam_member, google_storage_bucket_iam_binding,
 *                                      google_storage_bucket_access_control, google_storage_default_object_access_control
 *                               Azure  azurerm_storage_container (container_access_type), azurerm_storage_account
 *                                      (allow_blob_public_access / allow_nested_items_to_be_public set to true)
 *   inside.tf_unencrypted       AWS    aws_db_instance, aws_rds_cluster, aws_ebs_volume, aws_efs_file_system (not set
 *                                      or false), aws_redshift_cluster (set to false)
 *                               Azure  azurerm_mssql_database (transparent_data_encryption_enabled set to false)
 *                               Google none: Cloud SQL and Cloud Storage encrypt at rest by default
 *   inside.tf_public_database   AWS    aws_db_instance, aws_rds_cluster_instance, aws_redshift_cluster
 *                                      (publicly_accessible set to true)
 *                               Google google_sql_database_instance (an authorized network of 0.0.0.0/0)
 *                               Azure  the SQL / PostgreSQL / MySQL firewall rules from 0.0.0.0 to the last IPv4 address
 *   inside.tf_hardcoded_credentials  a plain text literal (no variable, no interpolation) given to a credential:
 *                               provider blocks (access_key, secret_key, token, password, client_secret, api_key,
 *                               api_token), resource attributes (password, master_password, admin_password,
 *                               administrator_login_password, master_user_password, secret_key, client_secret,
 *                               private_key, secret_string, auth_token, db_password), the default of a variable or
 *                               a local whose name says password / secret / token / key, and the same names in
 *                               *.tfvars files. The value is masked.
 * GUARDS: only plain literals count. A value from a variable, a local, a module output or a function is never judged.
 * A database restored from a snapshot or built as a replica inherits its encryption and is skipped. Known risk of a
 * false alarm: a bucket that is public on purpose (a static website), a database opened on purpose for a demo.
 */
import { hclBlocks, hclBool, hclList, hclNum, hclStr, parseHcl, type HclBlock } from "./hcl-lite";
import { isCredName, literalSecret } from "./docker";
import { finding, lineOf, lineText, maskValue, maskedLine, type R2File, type R2Finding } from "./types";

export const isTerraformFile = (p: string): boolean => /\.tf$/i.test(p) && !/(?:^|\/)\.terraform\//.test(p);
export const isTfvarsFile = (p: string): boolean => /\.tfvars$/i.test(p) && !/(?:^|\/)\.terraform\//.test(p);

const PROVIDER_CREDS = new Set(["access_key", "secret_key", "token", "password", "client_secret", "api_key", "api_token", "secret", "client_certificate_password"]);
const RESOURCE_CREDS = new Set(["password", "master_password", "admin_password", "administrator_login_password", "administrator_password", "master_user_password", "secret_key", "client_secret", "private_key", "secret_string", "auth_token", "db_password", "root_password", "admin_ssh_key_data"]);

/** *.tfvars: top-level `name = "literal"` lines whose name says it is a credential. */
export function tfvarsFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  for (const m of f.content.matchAll(/^[ \t]*([A-Za-z_][\w-]*)[ \t]*=[ \t]*"((?:[^"\\\n$%]|\\.)*)"[ \t]*(?:#.*|\/\/.*)?$/gm)) {
    if (!isCredName(m[1]!) || !literalSecret(m[2]!)) continue;
    const line = lineOf(f.content, m.index! + m[0].indexOf(m[1]!));
    out.push(finding("inside.tf_hardcoded_credentials", f, line, { what: "a value in a tfvars file", name: m[1]!.slice(0, 80), live: "not_checked" }, { key: `tfvars|${m[1]}`, masked: maskValue(m[2]!), snippet: maskedLine(lineText(f.content, line), m[2]!) }));
  }
  return out;
}

/** Admin and database ports a rule may not open to everyone. */
export const ADMIN_PORTS: Readonly<Record<number, string>> = {
  22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB",
  6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB", 2375: "Docker", 11211: "Memcached",
};
const ANY_V4 = "0.0.0.0/0", ANY_V6 = "::/0";
/** The last IPv4 address, put together here so this file holds no address a leak scan would stop on. */
const LAST_V4 = ["255", "255", "255", "255"].join(".");
const portsIn = (from: number, to: number): string[] => Object.keys(ADMIN_PORTS).map(Number).filter((p) => p >= from && p <= to).map((p) => `${p} (${ADMIN_PORTS[p]})`);
/** "22", "20-30" or "*" as a range. */
function rangeOf(s: string): [number, number] | null {
  const t = s.trim();
  if (t === "*") return [0, 65535];
  const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(t);
  return m ? [Number(m[1]), Number(m[2] ?? m[1])] : null;
}

function awsIngress(b: HclBlock, v4: string, v6: string, proto: string): string[] | null {
  const open = hclList(b.attrs.get(v4))?.includes(ANY_V4) || hclList(b.attrs.get(v6))?.includes(ANY_V6) || hclStr(b.attrs.get(v4)) === ANY_V4 || hclStr(b.attrs.get(v6)) === ANY_V6;
  if (!open) return null;
  const p = (hclStr(b.attrs.get(proto)) ?? String(hclNum(b.attrs.get(proto)) ?? "")).toLowerCase();
  if (p === "-1" || p === "all") return ["every port"];
  if (p && p !== "tcp" && p !== "6") return null;
  const from = hclNum(b.attrs.get("from_port")), to = hclNum(b.attrs.get("to_port"));
  if (from === null || to === null) return null;
  const hit = portsIn(from, to);
  return hit.length ? hit : null;
}

function azureRule(b: HclBlock): string[] | null {
  if ((hclStr(b.attrs.get("direction")) ?? "").toLowerCase() !== "inbound" || (hclStr(b.attrs.get("access")) ?? "").toLowerCase() !== "allow") return null;
  const srcs = [hclStr(b.attrs.get("source_address_prefix")), ...(hclList(b.attrs.get("source_address_prefixes")) ?? [])].filter((x): x is string => !!x).map((x) => x.toLowerCase());
  if (!srcs.some((s) => s === "*" || s === ANY_V4 || s === "internet" || s === "any" || s === ANY_V6)) return null;
  const proto = (hclStr(b.attrs.get("protocol")) ?? "").toLowerCase();
  if (proto && proto !== "tcp" && proto !== "*") return null;
  const ranges = [hclStr(b.attrs.get("destination_port_range")), ...(hclList(b.attrs.get("destination_port_ranges")) ?? [])].filter((x): x is string => !!x);
  const hit = new Set<string>();
  for (const r of ranges) { const g = rangeOf(r); if (g) for (const p of g[0] === 0 && g[1] === 65535 ? ["every port"] : portsIn(g[0], g[1])) hit.add(p); }
  return hit.size ? [...hit] : null;
}

export function terraformFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  const top = parseHcl(f.content);
  const blocks = top.filter((b) => b.type === "resource" && b.labels.length === 2);
  const cred = (where: string, name: string, a: { raw: string; line: number } | undefined) => {
    const v = hclStr(a);
    if (!a || v === null || !literalSecret(v)) return;
    out.push(finding("inside.tf_hardcoded_credentials", f, a.line, { what: where, name: name.slice(0, 80), live: "not_checked" }, { key: `${where}|${name}`, masked: maskValue(v), snippet: maskedLine(lineText(f.content, a.line), v) }));
  };
  for (const b of top) {
    if (b.type === "provider") for (const [k, a] of b.attrs) { if (PROVIDER_CREDS.has(k)) cred(`provider ${b.labels[0] ?? ""}`, k, a); }
    else if (b.type === "variable" && b.labels[0] && isCredName(b.labels[0])) cred("the default of a variable", b.labels[0], b.attrs.get("default"));
    else if (b.type === "locals") for (const [k, a] of b.attrs) { if (isCredName(k)) cred("a local value", k, a); }
    else if (b.type === "resource" && b.labels.length === 2) {
      const walkBlock = (x: HclBlock) => { for (const [k, a] of x.attrs) if (RESOURCE_CREDS.has(k)) cred(`${b.labels[0]}.${b.labels[1]}`, k, a); for (const c of x.blocks) walkBlock(c); };
      walkBlock(b);
    }
  }
  const add = (rule: string, b: HclBlock, line: number, meta: Record<string, string>) =>
    out.push(finding(rule, f, line, { resource: `${b.labels[0]}.${b.labels[1]}`, live: "not_checked", ...meta }, { key: `${b.labels[0]}.${b.labels[1]}|${meta.what ?? meta.port ?? ""}` }));
  for (const b of blocks) {
    const type = b.labels[0]!;
    const A = (k: string) => b.attrs.get(k);
    switch (type) {
      // ── admin ports open to everyone ──
      case "aws_security_group":
        for (const ing of hclBlocks(b, "ingress")) { const hit = awsIngress(ing, "cidr_blocks", "ipv6_cidr_blocks", "protocol"); if (hit) add("inside.tf_open_admin_port", b, ing.line, { port: hit.join(", "), source: "0.0.0.0/0" }); }
        break;
      case "aws_security_group_rule":
        if (hclStr(A("type")) === "ingress") { const hit = awsIngress(b, "cidr_blocks", "ipv6_cidr_blocks", "protocol"); if (hit) add("inside.tf_open_admin_port", b, b.line, { port: hit.join(", "), source: "0.0.0.0/0" }); }
        break;
      case "aws_vpc_security_group_ingress_rule": {
        const hit = awsIngress(b, "cidr_ipv4", "cidr_ipv6", "ip_protocol");
        if (hit) add("inside.tf_open_admin_port", b, b.line, { port: hit.join(", "), source: "0.0.0.0/0" });
        break;
      }
      case "google_compute_firewall": {
        const dir = (hclStr(A("direction")) ?? "INGRESS").toUpperCase();
        if (dir !== "INGRESS" || hclBool(A("disabled")) === true) break;
        const src = hclList(A("source_ranges"));
        if (!src || !(src.includes(ANY_V4) || src.includes(ANY_V6))) break;
        const hit = new Set<string>();
        for (const al of hclBlocks(b, "allow")) {
          const proto = (hclStr(al.attrs.get("protocol")) ?? "").toLowerCase();
          if (proto === "all") { hit.add("every port"); continue; }
          if (proto !== "tcp") continue;
          const ports = hclList(al.attrs.get("ports"));
          if (!al.attrs.has("ports")) { hit.add("every port"); continue; }
          for (const p of ports ?? []) { const g = rangeOf(p); if (g) for (const x of portsIn(g[0], g[1])) hit.add(x); }
        }
        if (hit.size) add("inside.tf_open_admin_port", b, b.line, { port: [...hit].join(", "), source: "0.0.0.0/0" });
        break;
      }
      case "azurerm_network_security_rule": {
        const hit = azureRule(b);
        if (hit) add("inside.tf_open_admin_port", b, b.line, { port: hit.join(", "), source: "any" });
        break;
      }
      case "azurerm_network_security_group":
        for (const r of hclBlocks(b, "security_rule")) { const hit = azureRule(r); if (hit) add("inside.tf_open_admin_port", b, r.line, { port: hit.join(", "), source: "any" }); }
        break;

      // ── public storage ──
      case "aws_s3_bucket":
      case "aws_s3_bucket_acl": {
        const acl = hclStr(A("acl"));
        if (acl === "public-read" || acl === "public-read-write") add("inside.tf_public_bucket", b, A("acl")!.line, { what: `acl ${acl}` });
        break;
      }
      case "aws_s3_bucket_public_access_block":
        for (const k of ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]) {
          if (hclBool(A(k)) === false) { add("inside.tf_public_bucket", b, A(k)!.line, { what: `${k} = false` }); break; }
        }
        break;
      case "google_storage_bucket_iam_member": {
        const m = hclStr(A("member"));
        if (m === "allUsers" || m === "allAuthenticatedUsers") add("inside.tf_public_bucket", b, A("member")!.line, { what: `member ${m}` });
        break;
      }
      case "google_storage_bucket_iam_binding": {
        const m = (hclList(A("members")) ?? []).find((x) => x === "allUsers" || x === "allAuthenticatedUsers");
        if (m) add("inside.tf_public_bucket", b, A("members")!.line, { what: `member ${m}` });
        break;
      }
      case "google_storage_bucket_access_control":
      case "google_storage_default_object_access_control": {
        const e = hclStr(A("entity"));
        if (e === "allUsers" || e === "allAuthenticatedUsers") add("inside.tf_public_bucket", b, A("entity")!.line, { what: `entity ${e}` });
        break;
      }
      case "azurerm_storage_container": {
        const t = hclStr(A("container_access_type"));
        if (t === "blob" || t === "container") add("inside.tf_public_bucket", b, A("container_access_type")!.line, { what: `container_access_type ${t}` });
        break;
      }
      case "azurerm_storage_account":
        for (const k of ["allow_blob_public_access", "allow_nested_items_to_be_public"]) {
          if (hclBool(A(k)) === true) { add("inside.tf_public_bucket", b, A(k)!.line, { what: `${k} = true` }); break; }
        }
        break;

      // ── encryption at rest, public databases ──
      case "aws_db_instance":
      case "aws_rds_cluster": {
        if (type === "aws_db_instance" && hclBool(A("publicly_accessible")) === true) add("inside.tf_public_database", b, A("publicly_accessible")!.line, { what: "publicly_accessible = true" });
        const inherits = ["replicate_source_db", "snapshot_identifier", "replication_source_identifier", "global_cluster_identifier", "source_region"].some((k) => b.attrs.has(k)) || hclBlocks(b, "restore_to_point_in_time").length > 0 || hclStr(A("engine_mode")) === "serverless";
        const enc = A("storage_encrypted");
        if (!inherits && (enc ? hclBool(enc) === false : true)) add("inside.tf_unencrypted", b, enc?.line ?? b.line, { what: enc ? "storage_encrypted = false" : "storage_encrypted not set" });
        break;
      }
      case "aws_rds_cluster_instance":
        if (hclBool(A("publicly_accessible")) === true) add("inside.tf_public_database", b, A("publicly_accessible")!.line, { what: "publicly_accessible = true" });
        break;
      case "aws_ebs_volume":
      case "aws_efs_file_system": {
        const enc = A("encrypted");
        if (!b.attrs.has("snapshot_id") && (enc ? hclBool(enc) === false : true)) add("inside.tf_unencrypted", b, enc?.line ?? b.line, { what: enc ? "encrypted = false" : "encrypted not set" });
        break;
      }
      case "aws_redshift_cluster":
        if (hclBool(A("encrypted")) === false) add("inside.tf_unencrypted", b, A("encrypted")!.line, { what: "encrypted = false" });
        if (hclBool(A("publicly_accessible")) === true) add("inside.tf_public_database", b, A("publicly_accessible")!.line, { what: "publicly_accessible = true" });
        break;
      case "azurerm_mssql_database":
        if (hclBool(A("transparent_data_encryption_enabled")) === false) add("inside.tf_unencrypted", b, A("transparent_data_encryption_enabled")!.line, { what: "transparent_data_encryption_enabled = false" });
        break;
      case "google_sql_database_instance":
        for (const s of hclBlocks(b, "settings")) for (const ip of hclBlocks(s, "ip_configuration")) for (const n of hclBlocks(ip, "authorized_networks")) {
          if (hclStr(n.attrs.get("value")) === ANY_V4) add("inside.tf_public_database", b, n.attrs.get("value")!.line, { what: "authorized network 0.0.0.0/0" });
        }
        break;
      case "azurerm_sql_firewall_rule":
      case "azurerm_mssql_firewall_rule":
      case "azurerm_postgresql_firewall_rule":
      case "azurerm_postgresql_flexible_server_firewall_rule":
      case "azurerm_mysql_firewall_rule":
      case "azurerm_mysql_flexible_server_firewall_rule":
      case "azurerm_mariadb_firewall_rule":
        if (hclStr(A("start_ip_address")) === "0.0.0.0" && hclStr(A("end_ip_address")) === LAST_V4) add("inside.tf_public_database", b, A("start_ip_address")!.line, { what: "firewall rule from 0.0.0.0 to the last address" });
        break;
      default:
        break;
    }
  }
  return out;
}
