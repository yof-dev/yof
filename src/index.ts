/** @yof/cli as a library: the same rules the `yof` command runs. */
export { scanText, maskSecret, maskAll, isPlaceholder, jwtPayload, KEY_RULES, type SecretMatch, type Severity, type ScanOptions } from "./secrets";
export {
  checkPackages, packageFetcher, packageMessage, parsePackageJson, parsePyproject, parseRequirements, parseManifest, isManifest,
  lookalikeOf, editDistance, normalizePypi, pinnedVersion, PACKAGE_HOSTS,
  type Dependency, type Ecosystem, type PackageFinding, type PackageCheckResult, type PackageFetcher, type PackageIssue, type PackageSeverity,
} from "./packages";
export { parseYofYml, matchesIgnore, parseGitignore, matchesGitignore, PROFILES, type Profile, type YofConfig } from "./config";
export { runCheck, visibleIn, failsIn, CheckError, type CheckReport, type CheckOptions, type KeyFinding, type DependencyFinding } from "./check";
export { formatText, formatJson, CLOSING_LINE } from "./format";
export { installHook, uninstallHook, HOOK_SCRIPT, HOOK_MARKER } from "./hook";
export { main, VERSION, HELP } from "./cli";
