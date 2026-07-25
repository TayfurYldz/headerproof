## Summary

Describe the change and why it is needed.

## Validation

```bash
python3 -m py_compile header_active_scan.py file_safety.py
python3 -m pytest -q
```

## Checklist

- [ ] CLI surface remains limited to `-i` and `--concurrency`.
- [ ] New detection behavior includes tests.
- [ ] False-positive filtering remains conservative by default.
- [ ] No destructive payloads or denial-of-service behavior were added.
