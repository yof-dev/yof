# yof

**Catch leaked keys and made-up packages before they ship.**

`yof` (yof by sōtem) is yof on your laptop: a small command-line check for apps built with AI assistants (and apps built any other way). It finds secret keys sitting in your code and dependencies that don't exist or imitate popular ones, before they reach a commit, a pull request or production.

It is rules only: exact patterns, fast, and private. It runs on your machine, needs no account, and never sends your code anywhere.

[![npm](https://img.shields.io/npm/v/@yof/cli)](https://www.npmjs.com/package/@yof/cli) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

## Try it in 30 seconds

```sh
npx @yof/cli check
```

That checks the current folder. Node 20 or newer. Nothing to configure.

```
yof checked 2 files (profile: balanced)

Keys
  src/config.ts:1  Stripe live secret key  sk_live_FwIw••••••••  (fix now)
  A key that was ever committed or shipped counts as leaked: rotate it in the provider's dashboard,
  then keep it on the server only (an environment variable, not the code).

Packages
  package.json  reqeusts-helper (npm)  (fix now)
    This package doesn't exist on npm. AI assistants sometimes invent package names, and attackers register those names with malware. Check the spelling or remove it.
  package.json  expres (npm)  (fix this week)
    This name is one or two letters away from the popular package express. Make sure you meant this one and not express.

Found 3 problems: 2 to fix now, 1 to fix this week.
Want this on every pull request? https://yof.io
```

yof never prints a key in full. You see the prefix and four characters, enough to know which key it is.

Install it if you use it often:

```sh
npm install --save-dev @yof/cli
npx yof check
```

## Check every commit (pre-commit hook)

```sh
npx @yof/cli hook install
```

This adds `.git/hooks/pre-commit`, which runs `yof check --staged` before each commit. In staged mode yof reads exactly what is about to be committed (the staged content, not your working copy), and checks only the dependencies the commit adds. If something must be fixed now, the commit stops and yof says why.

- Remove it with `npx @yof/cli hook uninstall`.
- Skip it once with `git commit --no-verify`.
- If you already have a pre-commit hook, yof leaves it alone and tells you the one line to add to it.

## Check every push (GitHub Action)

```yaml
# .github/workflows/yof.yml
name: yof
on: [push, pull_request]
permissions:
  contents: read
jobs:
  yof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yof-dev/yof@v0.1.0
        with:
          path: .          # optional, default .
          offline: false   # optional, true = keys only, no registry lookups
```

The job fails when yof finds something to fix now, so it shows up as a red check on the commit or pull request.

## Settings: `.yof.yml`

Optional. Put it in the root of your repository. It is the same file yof Guard reads on GitHub, so one file covers both.

```yaml
profile: balanced    # relaxed | balanced | strict

ignore:
  - fixtures/        # a folder
  - docs/examples.md # a file
  - "**/*.snap"      # a glob: * stays inside one folder, ** matches any depth
```

| Profile | Shows | Fails (exit 1) on |
| --- | --- | --- |
| `relaxed` | fix now | fix now |
| `balanced` (default) | fix now, fix this week | fix now |
| `strict` | everything, including public keys that are fine | fix now, fix this week |

`--profile strict` on the command line overrides the file. yof also skips `node_modules`, `.git`, `dist`, `build`, `.next` and similar folders, lock files, binary files, files over 1 MB, and what your root `.gitignore` lists (read simply: plain names, folders and globs; `!` lines are not applied).

## What it checks

**Keys** (exact shapes only, so a random hash never raises an alarm):

| Fix now | Fix this week | Fine, public by design (shown in strict) |
| --- | --- | --- |
| Stripe live secret and restricted keys, Stripe webhook secrets | Stripe test secret keys | Stripe publishable keys |
| OpenAI, Anthropic, Groq, Hugging Face, Replicate | An AWS access key ID on its own | Firebase web keys |
| AWS access key with its secret next to it | Browser-visible settings named like a secret (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_` … `SECRET` / `PASSWORD` / `PRIVATE`) | Supabase anon keys |
| Supabase service-role keys (the JWT is decoded, not guessed) | | |
| GitHub tokens, Slack tokens and webhook URLs | | |
| Resend, SendGrid, Mailgun, Twilio | | |
| Private keys (`BEGIN … PRIVATE KEY`) | | |

Placeholders such as `sk_live_xxxxxxxx` or `sk_live_your_key_here` are skipped, so docs and examples stay quiet.

**Packages** in `package.json`, `requirements*.txt` and `pyproject.toml`:

- **Made up**: the name does not exist on npm or PyPI. AI assistants sometimes invent package names, and attackers register those names with malware. (fix now)
- **Lookalike**: one or two letters away from a popular package (`expres`, `reqeusts`) and not well established itself. (fix this week)
- **Brand new**: first published in the last 14 days. (fix this week)
- **Known advisory**: an exact pinned version with a published advisory in the OSV database. High and critical are fix now, the rest fix this week.

If a registry does not answer, yof says so and claims nothing about that package.

**What it does not do**: it does not read git history, scan your running website, check your database rules, or review code logic. Those live in the yof app and Guard (below).

## Privacy

yof runs on your machine. It reads files, matches patterns and prints the result. Your code, file names and keys never leave your computer.

The only network calls are package-registry lookups: package names (and exact pinned versions) go to `registry.npmjs.org`, `api.npmjs.org`, `pypi.org` and `api.osv.dev`, and to no other host. Skip them with `--offline`, and yof makes no network calls at all. There is no telemetry.

## Options

```
yof check [path]       Check a folder (default: the current one)
yof check --staged     Check only the files staged for the next commit
yof hook install       Run "yof check --staged" before every commit
yof hook uninstall     Remove that hook

--offline              Skip the package-registry lookups (keys only)
--json                 Machine-readable output (masked values only)
--profile <name>       relaxed | balanced | strict
-v, --version          Print the version
-h, --help             Print help
```

Exit codes: `0` nothing to fix, `1` something to fix (per the profile), `2` usage or setup error.

You can also use it as a library: `import { scanText, checkPackages, runCheck } from "@yof/cli"`.

## Want more?

yof is the security watcher for AI-built apps. This CLI is its fast, private, rules-based part. The rest lives at [yof.io](https://yof.io):

- **The yof app** at [yof.io](https://yof.io) watches your live app, explains every finding in plain words, says what the fix is, and keeps track of your app over time.
- **Guard** reviews every pull request on GitHub and leaves one clear comment: [github.com/apps/yof-by-sotem](https://github.com/apps/yof-by-sotem).
- **Patch**, yof's AI agent, writes the fixes for you as a draft pull request.

## Contributing

Issues and pull requests are welcome, especially new key rules with a documented shape. See [CONTRIBUTING.md](./CONTRIBUTING.md). Security problems: [SECURITY.md](./SECURITY.md).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). yof is made by Mondaily.
