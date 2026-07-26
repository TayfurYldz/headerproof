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

```bash
pipx install git+https://github.com/TayfurYldz/headerproof.git
headerproof -i urls.txt --concurrency 16
```

Run from a clone without installing:

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
```

Supported runtime options are deliberately small:

- `-i`: URL input file.
- `--concurrency`: concurrent URL workers.

Per-URL time budget is fixed at 9 seconds. The scanner uses fast internal defaults, strict false-positive filtering, and live output only for report-ready findings without requiring tuning flags.

## Output

Each run creates an evidence directory under `evidence/headerproof-YYYYmmdd-HHMMSS/`.

- `results.jsonl`: one full scan record per URL.
- `signals.jsonl`: flattened report-ready findings only.
- `summary.md`: human-readable run summary.
- `verification-plan.md`: per-class confirmation steps and report gates.

Live cards are printed only after a signal reaches the report-ready gate. Each card includes proof score, why it was shown, evidence, false-positive guardrails, and the next validation step.

## Detection Philosophy

The goal is speed with useful signal, not noisy checklist output.

- CORS header looseness is treated as a lead, not a live finding, unless impact is independently proven.
- CSRF cookie attributes are suppressed by default because state change and read-back are required.
- Cache poisoning requires a clean follow-up response plus cache indicators before it becomes report-ready.
- Header injection separates plain reflection from parsed CRLF response splitting.
- Content spoofing is suppressed by default unless it gains cache, header, or security impact.

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
