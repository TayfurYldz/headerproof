#!/usr/bin/env python3
"""Compatibility wrapper for the HeaderProof scanner CLI.

The implementation lives in :mod:`scanner.cli`. This module remains so old
commands, imports, and local scripts that reference ``header_active_scan.py``
continue to work.
"""

from pathlib import Path
import sys

_SRC_DIR = Path(__file__).resolve().parent / "src"
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from headerproof.cli import *  # noqa: F401,F403,E402
from headerproof.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
