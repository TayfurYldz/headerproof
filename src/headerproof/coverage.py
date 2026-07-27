from __future__ import annotations

import threading

from .models import CoverageRecord, ProbeState


class CoverageTracker:
    """Thread-safe probe and detector lifecycle ledger."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_sequence = 1
        self._records: dict[int, CoverageRecord] = {}

    def plan(self, kind: str, detector: str, probe_id: str, role: str) -> int:
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            self._records[sequence] = {
                "sequence": sequence,
                "kind": kind,  # type: ignore[typeddict-item]
                "detector": detector,
                "probe_id": probe_id,
                "role": role,
                "state": "planned",
            }
            return sequence

    def transition(
        self,
        sequence: int,
        state: ProbeState,
        *,
        reason: str = "",
        error: str = "",
    ) -> None:
        with self._lock:
            record = self._records[sequence]
            record["state"] = state
            if reason:
                record["reason"] = reason
            if error:
                record["error"] = error

    def records(self) -> list[CoverageRecord]:
        with self._lock:
            return [dict(self._records[key]) for key in sorted(self._records)]  # type: ignore[misc]
