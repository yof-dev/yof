# Changelog

All notable changes to `@yof/cli`. The format follows Keep a Changelog, and versions follow Semantic Versioning.

## Unreleased

## 0.1.0

First release.

- `yof check [path]`: finds leaked keys (Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, Supabase service-role, Resend, SendGrid, Mailgun, Twilio, Hugging Face, Groq, Replicate, private keys and browser settings named like secrets), masked in every output.
- Package check for package.json, requirements.txt and pyproject.toml: made-up names, lookalikes of popular packages, packages published in the last 14 days, and known advisories for exact pins (OSV).
- `yof check --staged` for the pre-commit hook: reads the staged content and checks only the dependencies the commit adds.
- `yof hook install` / `yof hook uninstall`, which never overwrite a hook that is not yof's.
- `.yof.yml` with `profile` (relaxed, balanced, strict) and `ignore`, the same file yof Guard reads.
- `--offline`, `--json`, `--profile`, and exit codes 0 / 1 / 2.
- GitHub Action (`action.yml`).
