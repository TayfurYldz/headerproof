# Changelog

## 1.2.0

- Opened safe advanced CLI options: `--profile`, `--timeout`, `--origin`, `--header`, `--out-dir`, `--json`, and `--quiet`.
- Added `metadata.json` with tool version, git commit, command line, URL count, and scan config.
- Added Kali-style `install.sh`, `uninstall.sh`, and `Makefile` targets so `headerproof` can run globally without changing into the project directory.
- Tightened CRLF confirmation to require the exact per-request canary in the parsed `X-PA-Injected` response header value.
- Tightened cache poisoning report-ready scoring to require a clean follow-up response plus a shared-cache HIT/Age marker.
- Added package build and installed entrypoint checks to CI.
- Added tests for installer scripts, JSONL input handling, metadata output, timeout behavior, duplicate suppression, CORS `Vary: Origin`, CRLF exact-canary proof, and cache report-ready gating.

## 1.1.0

- Tightened default strict mode to show live cards only for report-ready findings.
- Suppressed lead-only CORS, CSRF cookie, header reflection, cache candidate, and content reflection noise by default.
- Required clean cache follow-up plus cache indicators before cache poisoning is treated as confirmed.
- Added modern evidence-first terminal cards and clearer final run summaries.

## 1.0.0

- Branded the project as HeaderProof.
- Promoted the installable `headerproof` command in Quick Start.
- Added fast active scanner for URL lists.
- Added strict certainty scoring and false-positive filtering.
- Added live detailed alert boxes with evidence, missing proof, and validation steps.
- Added evidence output: JSONL results, JSONL signals, Markdown summary, and verification plan.
- Added tests for core findings, CLI surface, fast defaults, and live alerts.
