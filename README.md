# HeaderProof

[![HeaderProof CI](https://github.com/TayfurYldz/headerproof/actions/workflows/ci.yml/badge.svg)](https://github.com/TayfurYldz/headerproof/actions/workflows/ci.yml)

Fast, low-noise active scanner for header-driven web security leads.

```text
    __  __               __          ____                   __
   / / / /__  ____ _____/ /__  _____/ __ \________  ____  / /
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ /_/ / ___/ _ \/ __ \/ /
 / __  /  __/ /_/ / /_/ /  __/ /  / ____/ /  /  __/ /_/ /_/
/_/ /_/\___/\__,_/\__,_/\___/_/  /_/   /_/   \___/\____(_)
```

It scans a supplied URL list and only live-alerts findings that pass the report-ready proof gate for:

- CORS misconfiguration
- CSRF cookie risk signals
- HTTP header injection and response splitting
- Web cache poisoning candidates
- Content spoofing and reflection paths

The scanner is intentionally conservative. Header-only observations are suppressed by default unless the automated evidence is strong enough to pass the built-in report gate. It writes raw evidence and a manual verification plan so you can prove impact before reporting.

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
cd headerproof
./headerproof -i urls.txt --concurrency 16
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

Per-URL time budget is fixed at 9 seconds. The scanner uses strict false-positive filtering and live output only for report-ready findings by default.

## Output

Each run creates an evidence directory under `evidence/headerproof-YYYYmmdd-HHMMSS/`.

- `metadata.json`: tool version, git commit, command line, URL count, and scan config.
- `results.jsonl`: one full scan record per URL.
- `signals.jsonl`: flattened report-ready findings only.
- `summary.md`: human-readable run summary.
- `verification-plan.md`: per-class confirmation steps and report gates.

Live cards are printed only after a signal reaches the report-ready gate. Each card includes proof score, why it was shown, evidence, false-positive guardrails, and the next validation step.

Example live card:

```text
╭ CONFIRMED FINDING · HIGH · 98% CONFIRMED ───────────────────────────────╮
│  Finding           CRLF query probe influenced response headers          │
│  Type              response_splitting_crlf_candidate                     │
│  Proof score       98% / confirmed                                       │
│  Gate              report_ready                                          │
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
- Cache poisoning requires a clean follow-up response plus a shared-cache HIT/Age marker before it becomes report-ready.
- Header injection separates plain reflection from parsed CRLF response splitting, and CRLF confirmation requires the exact canary in the injected header value.
- Content spoofing is suppressed by default unless it gains cache, header, or security impact.

## What Not To Report From HeaderProof Alone

HeaderProof is a proof gate for technical primitives, not a replacement for impact validation. These are intentionally suppressed or kept below report-ready unless you prove a working chain:

- Missing hardening headers such as CSP, HSTS, X-Frame-Options, or cookie flags alone.
- Wildcard CORS without credentialed sensitive data read.
- CORS origin reflection without authenticated body exfiltration or cache impact.
- CSRF cookie SameSite observations without cross-site state change and independent read-back.
- Body-only content reflection without trusted victim context, cacheability, or script/security impact.
- Cache reflection without a clean follow-up response and shared-cache HIT/Age evidence.

## Roadmap

- Continue the module split from the compatibility wrapper + `scanner/cli.py` layout into `scanner/http.py`, `scanner/detections.py`, and `scanner/output.py`.
- Add more fixture coverage for CDN-specific cache headers and real-world CORS regex mistakes.
- Publish signed GitHub releases with attached source archives and wheel artifacts.
- Add PyPI publishing after the module split stabilizes.

## Requirements

- Python 3.10+
- No third-party runtime dependencies

Tests use `pytest`.

```bash
python3 -m pytest -q
```

## Authorized Use

Use only on systems where you have explicit permission to test. Do not use this tool for destructive testing, denial of service, credential theft, or out-of-scope probing.

## License

MIT
