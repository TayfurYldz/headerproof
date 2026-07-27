## Summary

Describe the change and why it is needed.

## Validation

```bash
python3 -m compileall -q header_active_scan.py src/headerproof
python3 -m ruff check header_active_scan.py src/headerproof tests
python3 -m mypy
python3 -m pytest -q
python3 -m pytest -q --cov=headerproof.detectors --cov=headerproof.evidence --cov-branch --cov-fail-under=95
python -m build
```

## Checklist

- [ ] CLI changes are safe by default and documented.
- [ ] New detection behavior includes tests.
- [ ] False-positive filtering remains conservative by default.
- [ ] Observations/probes are preserved even when findings are filtered.
- [ ] Evidence schema and proof-gate mutation tests pass.
- [ ] No destructive payloads or denial-of-service behavior were added.
