# Changelog

## 1.3.1

- Fixed the refactor regression that serialized every baseline and probe exchange as `null`.
- Streamed response bodies while calculating full-response length and SHA-256; added explicit sample length and truncation fields.
- Required every cache confirmation stage to complete without transport errors, with the expected cache-key relationship, isolated client contexts, clean requests, a fresh control, and shared-cache progression.
- Split cache results into cross-request reproduction and shared-cache-confirmed signal types.
- Propagated every failed request into structured probe/error records and marked affected targets `partial_error`; all-failed batches now exit nonzero.
- Removed arbitrary numeric certainty ranks and `CONFIRMED FINDING` wording. Evidence now uses `observed`, `reproduced`, and `cross_request_confirmed`, while impact remains `unverified`.
- Added typed evidence models, JSON Schema v1.2, detector/probe coverage records, incremental JSONL writes, durable checkpoints, SQLite input deduplication, collision-resistant run directories, and run IDs.
- Added independent origin/cache-proxy tests, a 13-case cache proof-gate mutation matrix, schema-contract tests, and full body/exchange/error regressions.
- Raised detector and evidence branch coverage to 99% with a CI floor of 95%.
- Added Ruff and Mypy CI gates, repaired the Makefile, and added an installed-wheel real-scan smoke test.
- Changed package maturity from Beta to developer Alpha until pooled transport and explicit resume support land.
- Changed release automation so one build is tested, attested, uploaded, and published without rebuilding artifacts.

## 1.3.0

- Adopted a real `src/headerproof/` package layout with separate `models`, `transport`, `input`, `engine`, `detectors`, `evidence`, `output`, `metadata`, and `ui` modules.
- Gave every header/cache detector an independent `probe_id`, canary, cache key, and fresh-key control request.
- Reworked cache confirmation into a clean-baseline, poison, clean-victim, fresh-control state machine with shared-cache HIT/Age progression checks.
- Preserved all suppressed and duplicate observations in `observations.jsonl`, and every HTTP exchange in `probes.jsonl`.
- Marked unreachable baselines as `error` instead of `scanned`.
- Added a global request semaphore and bounded URL future submission so `--concurrency N` caps active HTTP requests.
- Removed percentage-style live certainty wording; findings now use evidence state plus `rank/100`.
- Added `headerproof --version`, safer uninstall path validation, and CI build provenance attestation.
- Cleaned HeaderProof-only file safety helpers and refreshed tests for unreachable targets, global concurrency, origin-side cache state, evidence files, and installed entrypoints.

## 1.2.0

- Opened safe advanced CLI options: `--profile`, `--timeout`, `--origin`, `--header`, `--out-dir`, `--json`, and `--quiet`.
- Started the module split by moving the implementation behind a small `header_active_scan.py` compatibility wrapper.
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
