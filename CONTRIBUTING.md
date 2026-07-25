# Contributing

Contributions should preserve the scanner's current operating model:

- keep the CLI minimal: `-i` and `--concurrency`
- prefer strict false-positive filtering over noisy output
- keep runtime dependencies at zero unless there is a strong reason
- add tests for new detection or scoring behavior
- avoid destructive payloads and denial-of-service techniques

Before submitting a change:

```bash
python3 -m py_compile header_active_scan.py file_safety.py
python3 -m pytest -q
./headerproof -h
```
