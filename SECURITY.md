# Security policy

## Reporting a problem

Please report security problems privately. Do not open a public issue.

- Email **security@yof.io**, or
- use GitHub's private vulnerability reporting on this repository (Security > Report a vulnerability).

Tell us what you found, how to reproduce it, and what an attacker could do with it. We reply within three working days and keep you posted until it is fixed. We credit reporters who want to be credited.

## Scope

This repository is the `yof` command-line tool and its GitHub Action: `yof check` (the key rules, the package check, the code and config patterns), the pre-commit hook, `yof attack`, `yof mcp` and the output of each. Examples of what we want to hear about:

- yof printing a secret in full anywhere (text output, JSON, errors, an MCP answer).
- `yof check` sending anything other than package names and pinned versions to the network, or reaching a host other than registry.npmjs.org, api.npmjs.org, pypi.org and api.osv.dev.
- A file or manifest that makes yof run code, write outside `.git/hooks/pre-commit`, or overwrite a hook that is not its own.

### `yof attack`

`yof attack` sends requests to a running app on purpose, so its limits are part of its security. What it is built to do and not do (the README has the details):

- It tests only a host you proved is yours: `localhost`, a preview that GitHub reports as a successful deployment of this repository, or a live host that yof confirms is one of your proven apps. That check sends only the host name to yof.
- It needs the written consent sentence for that app in `.yof/attack.json`, and it never tests production unless the config turns production on for that app.
- A light run sends only GET and HEAD. A full run also sends POST to the create, sign-in and assistant routes you name, and PATCH, PUT or DELETE only to records it created itself, which it deletes at the end.
- It works within hard budgets (requests, time, pace), stops on Ctrl+C or SIGTERM and deletes its test records, and reads account secrets only from environment variables whose names start with `YOF_ATTACK_`.
- It keeps the shape of an answer as evidence, never its content.

Reports we want: a run reaching a host that is not proven, a request method or route outside the rules above, a test record it created and did not delete, a config or pull request that makes it send a CI secret or another variable, an answer's content kept in a report or a log, or a way to run it against a live host without the proof check.

### `yof mcp`

`yof mcp` is a local MCP server for AI coding tools. Its local tools (`yof_check`, `yof_check_diff`, `yof_explain`, `yof_fix_prompt`, `yof_verify`) read only the project folder the server was started in and never upload code. The account tools (`yof_findings`, `yof_patch_status`, `yof_lessons`) work only with `YOF_API_KEY` and send yof.io the tool name and its arguments (ids and rule ids), never code or file contents. Every answer is marked as untrusted data, and secret values come back as a short prefix plus `REDACTED`.

Reports we want: a path that escapes the project folder, file contents or code sent anywhere, a secret value in an answer, text in a scanned file that a client would read as an instruction despite the marker, or `YOF_API_KEY` sent to a host other than the configured MCP endpoint (`YOF_MCP_URL`, by default `https://mcp.yof.io/mcp`).

### Elsewhere

Problems in the yof app at yof.io, in yof Guard or in the hosted yof MCP endpoint are welcome at the same address. Please test only accounts and apps that are yours.

A key yof misses, or a false alarm, is a normal bug: please open an issue (with a fake value, never a real key).

## Supported versions

Security fixes go into the latest minor release of `@yof/cli`.

## If yof found a real key

Treat it as leaked even if the repository is private: rotate it in the provider's dashboard first, then remove it from the code and keep it on the server only. Removing it from the latest commit does not remove it from git history.
