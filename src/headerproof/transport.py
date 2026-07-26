from __future__ import annotations

import hashlib
import re
import socket
import ssl
import time
from typing import Any
from urllib import error, request

from .constants import VERSION
from .models import HttpSnapshot

class NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrlBudget:
    def __init__(self, seconds: float) -> None:
        self.seconds = max(0.1, seconds)
        self.started = time.monotonic()

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining(self) -> float:
        return max(0.0, self.seconds - self.elapsed())

    def expired(self) -> bool:
        return self.remaining() <= 0

    def request_timeout(self, preferred: float) -> float:
        remaining = self.remaining()
        if remaining <= 0:
            return 0.0
        return max(0.05, min(preferred, remaining))


def headers_from_message(message: Any) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for key, value in message.items():
        headers.setdefault(key.lower(), []).append(value)
    return headers


def serialise_headers(headers: dict[str, list[str]]) -> dict[str, str | list[str]]:
    out: dict[str, str | list[str]] = {}
    for key, values in sorted(headers.items()):
        out[key] = values[0] if len(values) == 1 else values
    return out


def decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


class HttpClient:
    def __init__(self, timeout: float, max_body: int, follow_redirects: bool, delay: float) -> None:
        self.timeout = timeout
        self.max_body = max_body
        self.delay = delay
        handlers: list[Any] = []
        if not follow_redirects:
            handlers.append(NoRedirectHandler())
        self.opener = request.build_opener(*handlers)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpSnapshot:
        request_headers = {
            "User-Agent": f"headerproof/{VERSION}",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        request_headers.update(headers or {})
        snap = HttpSnapshot(method, url, request_headers)
        req = request.Request(url, headers=request_headers, method=method)
        start = time.monotonic()
        effective_timeout = self.timeout if timeout is None else max(0.05, timeout)
        if self.delay > 0:
            time.sleep(min(self.delay, effective_timeout))
        try:
            with self.opener.open(req, timeout=effective_timeout) as resp:
                raw = resp.read(self.max_body + 1)
                snap.status = resp.status
                snap.reason = resp.reason
                snap.headers = headers_from_message(resp.headers)
        except error.HTTPError as exc:
            raw = exc.read(self.max_body + 1)
            snap.status = exc.code
            snap.reason = exc.reason
            snap.headers = headers_from_message(exc.headers)
        except (error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
            snap.error = f"{type(exc).__name__}: {exc}"
            raw = b""
        snap.elapsed_ms = int((time.monotonic() - start) * 1000)
        snap.body_len = len(raw)
        snap.body_sha256 = hashlib.sha256(raw).hexdigest() if raw else ""
        snap.body_sample = decode_body(raw[: self.max_body], snap.first("content-type")) if raw else ""
        return snap


def snapshot_summary(snap: HttpSnapshot, save_body: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "request": {
            "method": snap.request_method,
            "url": snap.request_url,
            "headers": snap.request_headers,
        },
        "response": {
            "status": snap.status,
            "reason": snap.reason,
            "error": snap.error,
            "elapsed_ms": snap.elapsed_ms,
            "headers": serialise_headers(snap.headers),
            "body_len": snap.body_len,
            "body_sha256": snap.body_sha256,
        },
    }
    if save_body:
        data["response"]["body_sample"] = snap.body_sample
