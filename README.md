# HeaderProof

[![HeaderProof CI](https://github.com/TayfurYldz/headerproof/actions/workflows/ci.yml/badge.svg)](https://github.com/TayfurYldz/headerproof/actions/workflows/ci.yml)

Fast, low-noise active scanner for header-driven web security leads.

Current maturity: **developer Alpha**. v1.3.1 prioritizes evidence correctness and conservative proof gates over broad protocol support.

```text
    __  __               __          ____                   __
   / / / /__  ____ _____/ /__  _____/ __ \________  ____  / /
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ /_/ / ___/ _ \/ __ \/ /
 / __  /  __/ /_/ / /_/ /  __/ /  / ____/ /  /  __/ /_/ /_/
/_/ /_/\___/\__,_/\__,_/\___/_/  /_/   /_/   \___/\____(_)
```

It scans a supplied URL list and only live-alerts signals that pass an explicit technical evidence gate for:

- CORS misconfiguration
- CSRF cookie risk signals
- HTTP header injection and response splitting
- Web cache poisoning candidates
- Content spoofing and reflection paths

The scanner is intentionally conservative. Header-only observations are suppressed by default unless the detector can reproduce a defined technical primitive. A live signal is not a bug-bounty submission: impact remains `unverified` until a human proves victim harm.

## Quick Start

Install as a normal Kali-style command. No `cd` into the project directory is required after this:

```bash
curl -fsSL https://raw.githubusercontent.com/TayfurYldz/headerproof/main/install.sh | sh
headerproof -i urls.txt --concurrency 16
```

The installer uses `/opt/headerproof` and `/usr/local/bin/headerproof` when run as root. For a normal user it uses `~/.local/share/headerproof` and `~/.local/bin/headerproof`.

Python package install is also supported:

```bash
pipx install git+https://github.com/TayfurYldz/headerproof.git
headerproof -i urls.txt --concurrency 16
```

Developer run from a clone:

```bash
git clone https://github.com/TayfurYldz/headerproof.git
sh headerproof/install.sh
headerproof -i urls.txt --concurrency 16
```

Input can be a plain text URL list or httpx-style JSONL containing `url` fields.

```text
https://example.com/
https://api.example.com/v1/me
{"url":"https://app.example.com/dashboard"}
```

## CLI

```bash
headerproof -i urls.txt --concurrency 32
headerproof -i urls.txt --profile balanced --timeout 2 --origin https://probe.example --header X-Forwarded-Host
headerproof -i urls.txt --json --out-dir evidence/run-001
```

Supported runtime options stay focused on safe scanner behavior:

- `-i`: URL input file.
- `--concurrency`: concurrent URL workers.
- `--profile`: `fast`, `balanced`, or `thorough`; the per-URL budget still stays capped at 9 seconds.
- `--timeout`: per-request timeout, capped by the URL budget.
- `--origin`: extra Origin value to probe. Repeat for multiple origins.
- `--header`: extra request header name to probe with a generated canary value. Repeat for multiple headers.
- `--out-dir`: evidence output directory.
- `--json`: machine-readable final summary, with live UI suppressed.
- `--quiet`: suppress banner, progress, and live alert cards.

Per-URL time budget is fixed at 9 seconds. The scanner uses strict false-positive filtering and live output only for signals whose detector proof gate passed.

## Architecture

The package uses a `src/` layout and keeps runtime responsibilities separated:

- `src/headerproof/cli.py`: argument parsing and batch orchestration.
- `src/headerproof/engine.py`: per-URL scan flow, bounded task submission, and global HTTP request semaphore.
- `src/headerproof/detectors.py`: CORS, CSRF, CRLF, header reflection, cache, and content spoofing detectors.
- `src/headerproof/evidence.py`: explicit evidence states, technical proof gates, verification plans, and false-positive filters.
- `src/headerproof/transport.py`: HTTP client, timeout budget, and response serialization.
- `src/headerproof/output.py`: incremental JSONL, checkpoint, Markdown summary, and verification-plan writers.
- `src/headerproof/coverage.py`: planned/attempted/completed/skipped/error lifecycle records.
- `schemas/evidence-v1.2.schema.json`: machine-verifiable evidence contract.

## Output

Each run creates an evidence directory under `evidence/headerproof-YYYYmmdd-HHMMSS/`.

- `metadata.json`: tool version, git commit, command line, URL count, and scan config.
- `results.jsonl`: one full scan record per URL.
- `observations.jsonl`: every detector observation, including strict-mode suppressed and duplicate leads.
- `probes.jsonl`: every attempted HTTP exchange with probe role, status, client context, and ID.
- `coverage.jsonl`: detector/probe lifecycle records, including planned, skipped, and failed work.
- `errors.jsonl`: structured request, detector, and URL errors.
- `signals.jsonl`: flattened signals whose technical evidence gate passed.
- `checkpoint.json`: last durably completed URL count and run ID.
- `summary.md`: human-readable run summary.
- `verification-plan.md`: per-class confirmation steps and report gates.

JSONL files are appended per completed URL instead of being built as large in-memory strings. Input is read line by line and deduplicated with SQLite. Live cards include the evidence state, explicit technical gate, unverified impact state, raw evidence, false-positive guardrails, and the next validation step.

Example live card:

```text
╭ VERIFIED TECHNICAL SIGNAL · HIGH · REPRODUCED ──────────────────────────╮
│  Finding           CRLF query probe influenced response headers          │
│  Type              response_splitting_crlf_candidate                     │
│  Evidence state    reproduced                                            │
│  Technical gate    passed                                                │
│  Impact            unverified                                            │
│                                                                          │
│  Why it is shown                                                         │
│    - HTTP 200 response accepted the probe                                │
│    - CRLF probe produced a parsed response header                        │
│                                                                          │
│  Still verify before reporting                                           │
│    - Repeat with a fresh canary and confirm real program impact.         │
╰──────────────────────────────────────────────────────────────────────────╯
```

## Detection Philosophy

The goal is speed with useful signal, not noisy checklist output.

- CORS header looseness is treated as a lead, not a live finding, unless impact is independently proven.
- CSRF cookie attributes are suppressed by default because state change and read-back are required.
- Cache poisoning requires all four clean-before/poison/clean-victim/fresh-control exchanges, distinct cache keys where required, isolated client contexts, clean request headers, and shared-cache progression before its technical gate passes.
- Header injection separates plain reflection from parsed CRLF response splitting, and CRLF confirmation requires the exact canary in the injected header value.
- Content spoofing is suppressed by default unless it gains cache, header, or security impact.

## What Not To Report From HeaderProof Alone

HeaderProof is a proof gate for technical primitives, not a replacement for impact validation. These are intentionally suppressed unless you prove a working chain:

- Missing hardening headers such as CSP, HSTS, X-Frame-Options, or cookie flags alone.
- Wildcard CORS without credentialed sensitive data read.
- CORS origin reflection without authenticated body exfiltration or cache impact.
- CSRF cookie SameSite observations without cross-site state change and independent read-back.
- Body-only content reflection without trusted victim context, cacheability, or script/security impact.
- Cache reflection without a clean follow-up response and shared-cache HIT/Age evidence.

## Roadmap

- Replace the standard-library transport with pooled HTTPX clients, proxy support, granular timeouts, and optional HTTP/2.
- Add explicit resume/recovery commands on top of the durable checkpoint and SQLite state.
- Add per-host rate policies, retry/backoff records, authenticated cookie contexts, and TLS policy controls.
- Add real Varnish/nginx integration fixtures alongside the current independent origin/cache-proxy corpus.
- Publish to PyPI after the evidence schema and transport contract stabilize.

## Requirements

- Python 3.10+
- No third-party runtime dependencies

Quality gates use `pytest`, branch coverage, Ruff, Mypy, JSON Schema contract checks, and a release-wheel real scan.

```bash
make test
```

## Authorized Use

Use only on systems where you have explicit permission to test. Do not use this tool for destructive testing, denial of service, credential theft, or out-of-scope probing.

## License

MIT
