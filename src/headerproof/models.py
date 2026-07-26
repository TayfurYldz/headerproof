from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HttpSnapshot:
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    status: int | None = None
    reason: str = ""
    headers: dict[str, list[str]] = field(default_factory=dict)
    body_sample: str = ""
    body_len: int = 0
    body_sha256: str = ""
    elapsed_ms: int = 0
    error: str = ""

    def values(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])

    def first(self, name: str, default: str = "") -> str:
        values = self.values(name)
        return values[0] if values else default
