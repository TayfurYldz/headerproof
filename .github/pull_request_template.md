## Summary

Describe the change and why it is needed.

## Validation

```bash
python3 -m compileall -q header_active_scan.py src/headerproof
python3 -m pytest -q
python -m build
```

## Checklist

- [ ] CLI changes are safe by default and documented.
- [ ] New detection behavior includes tests.
- [ ] False-positive filtering remains conservative by default.
- [ ] Observations/probes are preserved even when findings are filtered.
- [ ] No destructive payloads or denial-of-service behavior were added.
