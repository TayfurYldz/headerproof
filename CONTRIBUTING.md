# Contributing

Contributions should preserve the scanner's current operating model:

- keep CLI additions evidence-focused and safe by default
- prefer strict false-positive filtering over noisy output
- add runtime dependencies only when they improve transport, evidence, or correctness enough to justify the cost
- add tests for every new detection or proof-gate branch
- avoid destructive payloads and denial-of-service techniques

Before submitting a change:

```bash
python3 -m compileall -q header_active_scan.py src/headerproof
python3 -m ruff check header_active_scan.py src/headerproof tests
python3 -m mypy
python3 -m pytest -q
python3 -m pytest -q --cov=headerproof.detectors --cov=headerproof.evidence --cov-branch --cov-fail-under=95
./headerproof -h
```
