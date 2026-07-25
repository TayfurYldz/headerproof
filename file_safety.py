"""Atomic writes + read-modify-write locking + corrupt-JSON quarantine.

The brain capability graph and the intel_engine telemetry both live in small
JSON files that multiple parallel agents (dispatched by /autopilot) mutate
concurrently. Without these primitives, two concurrent record calls lose one
update under last-writer-wins; a crash mid-write leaves a truncated file that
the next load silently treats as empty and overwrites; real evidence
disappears. These helpers prevent all three.

- ``atomic_write_text``: write to ``<path>.tmp`` in the same dir, fsync, rename.
- ``locked_file``: ``fcntl.flock`` on a sidecar ``.lock`` file around a
  read-modify-write so concurrent writers serialise rather than race.
- ``load_json_or_quarantine``: on ``JSONDecodeError``, move the bad file aside
  to ``<path>.corrupt-<timestamp>`` and log loudly — never silently discard.
"""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def atomic_write_text(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically via temp file + rename.

    Crash or SIGKILL mid-write leaves the original file untouched. The rename
    is a single POSIX ``os.replace`` so readers never observe a half-written
    file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            # fsync can fail on some filesystems (e.g. tmpfs on older kernels);
            # the atomicity of the rename is the real guarantee.
            pass
    os.replace(tmp, path)


@contextmanager
def locked_file(path: Path) -> Iterator[None]:
    """Serialise read-modify-write sequences via fcntl.flock on a sidecar lock.

    The lock sits at ``<path>.lock`` so the target file itself is never held
    open across the sequence — callers stay free to rename/replace it
    atomically inside the lock. Works across processes on the same host; does
    NOT work across network filesystems that don't implement flock.

    Silently falls through on platforms without ``fcntl`` (e.g. Windows) —
    concurrency on those platforms is inherently best-effort for this
    workspace.
    """
    try:
        import fcntl  # noqa: WPS433 - optional module
    except ImportError:  # pragma: no cover
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+") as lock_fp:
        try:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)


def load_json_or_quarantine(path: Path, default_factory) -> Any:
    """Load JSON from ``path`` or quarantine a corrupt file and return default.

    Silent corruption recovery is worse than loud failure: the prior
    behaviour (``try: json.loads; except: return default``) let a crashed
    write cascade into a full data wipe on the next save. Now a corrupt file
    is preserved at ``<path>.corrupt-<epoch>`` and a warning is printed to
    stderr so the operator can recover.
    """
    if not path.exists():
        return default_factory()
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        timestamp = int(time.time())
        quarantine = path.with_name(f"{path.name}.corrupt-{timestamp}")
        try:
            path.rename(quarantine)
        except OSError as rename_err:
            # If we can't move it aside we must NOT continue — that would
            # lead to silent overwrite on the next save. Re-raise loudly.
            print(
                f"WARNING: {path} is corrupt ({exc}) and could not be moved aside "
                f"({rename_err}). Refusing to continue to avoid silent data loss.",
                file=sys.stderr,
            )
            raise
        print(
            f"WARNING: {path} was corrupt ({exc}); preserved at {quarantine}. "
            "Starting with a fresh file — investigate before discarding the corrupt copy.",
            file=sys.stderr,
        )
        return default_factory()
