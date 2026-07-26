# Changelog

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
