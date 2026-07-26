#!/usr/bin/env python3
"""Compatibility wrapper for the HeaderProof scanner CLI.

The implementation lives in :mod:`scanner.cli`. This module remains so old
commands, imports, and local scripts that reference ``header_active_scan.py``
continue to work.
"""

from scanner.cli import *  # noqa: F401,F403
from scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
