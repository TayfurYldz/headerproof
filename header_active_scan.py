#!/usr/bin/env python3
"""HeaderProof: active header-focused scanner for authorized bug bounty workspaces.

The scanner intentionally stays on low-impact request methods by default:
GET, HEAD-equivalent metadata from GET responses, and OPTIONS preflight. It
looks for CORS, CSRF risk signals, request-header reflection, cache poisoning
candidates, response splitting via CRLF query probes, and content spoofing
reflection. Treat results as leads unless a cache poisoning confirmation or
credentialed CORS/data-exfil proof is later validated manually.

Usage:
    python3 header_active_scan.py -i urls.txt
    python3 header_active_scan.py -i urls.txt --concurrency 16
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Any
from urllib import error, parse, request

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from file_safety import atomic_write_text  # noqa: E402


DEFAULT_CHECKS = {
    "cors",
    "csrf",
    "header-injection",
    "cache-poisoning",
    "content-spoofing",
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LIKELY_AUTH_COOKIE = re.compile(r"(session|sess|sid|auth|token|jwt|sso|remember|login)", re.I)
TEXTUAL_CONTENT = re.compile(r"(text/|json|xml|javascript|html|form-urlencoded)", re.I)
CACHEABLE_STATUSES = {200, 203, 204, 206, 300, 301, 302, 404, 410}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}
ALERT_LOCK = threading.Lock()
PRODUCT_NAME = "HeaderProof"
VERSION = "1.0.0"
BANNER = r"""
    __  __               __          ____                   __
   / / / /__  ____ _____/ /__  _____/ __ \________  ____  / /
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ /_/ / ___/ _ \/ __ \/ /
 / __  /  __/ /_/ / /_/ /  __/ /  / ____/ /  /  __/ /_/ /_/
/_/ /_/\___/\__,_/\__,_/\___/_/  /_/   /_/   \___/\____(_)
"""
FP_CERTAINTY_DEFAULTS = {"strict": 70, "balanced": 55, "all": 0}
PROFILE_DEFAULTS = {
    "fast": {
        "timeout": 2.0,
        "max_body": 8192,
        "concurrency": 16,
        "per_url_concurrency": 6,
        "origin_mode": "single",
        "header_probe_limit": 3,
        "no_preflight": True,
        "no_cache_confirm": True,
    },
    "balanced": {
        "timeout": 2.5,
        "max_body": 16384,
        "concurrency": 12,
        "per_url_concurrency": 4,
        "origin_mode": "standard",
        "header_probe_limit": 5,
        "no_preflight": False,
        "no_cache_confirm": False,
    },
    "thorough": {
        "timeout": 3.0,
        "max_body": 32768,
        "concurrency": 8,
        "per_url_concurrency": 4,
        "origin_mode": "standard",
        "header_probe_limit": 0,
        "no_preflight": False,
        "no_cache_confirm": False,
    },
}
SUPPRESSED_BY_STRICT = {
    "cors_wildcard_origin",
    "csrf_cookie_samesite_missing",
    "csrf_cookie_cross_site_auth",
    "csrf_cookie_auth_unsafe_methods_exposed",
    "header_reflection_candidate",
    "header_based_content_spoofing",
    "cookie_samesite_none_without_secure",
    "query_parameter_content_reflection",
}


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


def normalise_url(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("{"):
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            return None
        for key in ("url", "final_url", "input", "target"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                raw = value.strip()
                break
    else:
        raw = raw.split()[0]

    if raw.startswith("//"):
        raw = "https:" + raw
    if "://" not in raw:
        raw = "https://" + raw

    parsed = parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def load_urls(path: Path, max_urls: int | None = None) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        url = normalise_url(line)
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if max_urls and len(urls) >= max_urls:
            break
    return urls


def add_query(url: str, params: dict[str, str]) -> str:
    parts = parse.urlsplit(url)
    query = parse.parse_qsl(parts.query, keep_blank_values=True)
    query.extend(params.items())
    return parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", parse.urlencode(query), parts.fragment)
    )


def add_raw_query(url: str, key: str, raw_value: str) -> str:
    parts = parse.urlsplit(url)
    sep = "&" if parts.query else ""
    query = f"{parts.query}{sep}{parse.quote(key)}={raw_value}"
    return parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment))


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
    return data


def header_join(snap: HttpSnapshot, name: str) -> str:
    return ", ".join(snap.values(name))


def vary_has(snap: HttpSnapshot, token: str) -> bool:
    vary = header_join(snap, "vary").lower()
    return token.lower() in {part.strip() for part in vary.split(",")}


def cache_indicators(snap: HttpSnapshot) -> list[str]:
    indicators: list[str] = []
    cc = header_join(snap, "cache-control").lower()
    if cc:
        indicators.append(f"cache-control={cc}")
    if "no-store" in cc:
        indicators.append("no-store")
    if "private" in cc:
        indicators.append("private")
    for name in (
        "age",
        "expires",
        "etag",
        "x-cache",
        "x-cache-hits",
        "cf-cache-status",
        "cdn-cache-control",
        "surrogate-control",
        "akamai-cache-status",
        "server-timing",
    ):
        value = header_join(snap, name)
        if value:
            indicators.append(f"{name}={value}")
    return indicators


def looks_cacheable(snap: HttpSnapshot) -> tuple[bool, list[str]]:
    indicators = cache_indicators(snap)
    cc = header_join(snap, "cache-control").lower()
    if snap.status not in CACHEABLE_STATUSES:
        return False, indicators
    if "no-store" in cc or "private" in cc:
        return False, indicators
    active = any(
        marker in " ".join(indicators).lower()
        for marker in ("max-age", "s-maxage", "public", "age=", "x-cache", "cf-cache-status", "etag")
    )
    return active, indicators


def is_textual_response(snap: HttpSnapshot) -> bool:
    return bool(TEXTUAL_CONTENT.search(snap.first("content-type")))


def snippet_around(text: str, needle: str, radius: int = 90) -> str:
    lower = text.lower()
    index = lower.find(needle.lower())
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return text[start:end].replace("\r", "\\r").replace("\n", "\\n")


def canary_locations(snap: HttpSnapshot, canary: str) -> list[dict[str, str]]:
    locations: list[dict[str, str]] = []
    needle = canary.lower()
    for name, values in snap.headers.items():
        for value in values:
            if needle in value.lower():
                locations.append(
                    {
                        "where": "response_header",
                        "name": name,
                        "snippet": snippet_around(value, canary),
                    }
                )
    if needle in snap.body_sample.lower():
        locations.append(
            {
                "where": "response_body",
                "name": "body",
                "snippet": snippet_around(snap.body_sample, canary),
            }
        )
    return locations


def make_signal(
    check: str,
    signal_type: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: dict[str, Any],
    snap: HttpSnapshot | None = None,
    next_step: str = "",
    save_body: bool = False,
) -> dict[str, Any]:
    signal: dict[str, Any] = {
        "check": check,
        "type": signal_type,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "evidence": evidence,
        "submission_status": "lead_only",
        "next_step": next_step,
    }
    if snap:
        signal["exchange"] = snapshot_summary(snap, save_body=save_body)
    apply_detection_assessment(signal)
    return signal


def certainty_level(score: int) -> str:
    if score >= 95:
        return "confirmed"
    if score >= 85:
        return "very_high"
    if score >= 70:
        return "high"
    if score >= 55:
        return "medium"
    if score >= 35:
        return "low"
    return "noise"


def response_status_from_signal(signal: dict[str, Any]) -> int | None:
    exchange = signal.get("exchange", {})
    if not isinstance(exchange, dict):
        return None
    response = exchange.get("response", {})
    if not isinstance(response, dict):
        return None
    status = response.get("status")
    return status if isinstance(status, int) else None


def evidence_locations(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for key in ("locations", "poison_locations", "victim_locations"):
        value = evidence.get(key)
        if isinstance(value, list):
            locations.extend(item for item in value if isinstance(item, dict))
    return locations


def verification_template(signal_type: str) -> dict[str, list[str] | str]:
    if signal_type.startswith("cors_"):
        return {
            "objective": "Prove a browser can read sensitive cross-origin data, not merely that CORS headers are loose.",
            "automated_checks": [
                "Compare ACAO against the exact injected Origin.",
                "Record ACAC, allowed methods, Vary: Origin, status code, and cache headers.",
                "Differentiate arbitrary-origin reflection from wildcard CORS and null-origin quirks.",
            ],
            "manual_confirmation": [
                "Replay from an authenticated browser session against /me, billing, export, token, or private API endpoints.",
                "Confirm JavaScript fetch can read the body, not only send the request.",
                "Capture the sensitive field returned to the attacker origin.",
                "If cacheable and Vary: Origin is missing, repeat from a second client to test CORS cache poisoning.",
            ],
            "report_gate": "Report only with credentialed sensitive data read or a confirmed CORS cache poisoning chain.",
        }
    if signal_type.startswith("csrf_") or signal_type.startswith("cookie_"):
        return {
            "objective": "Prove a cross-site browser request causes a real state change under victim credentials.",
            "automated_checks": [
                "Identify likely auth cookies and SameSite/Secure attributes.",
                "Inspect advertised unsafe methods from Allow/ACAM headers when available.",
                "Avoid treating cookie attributes alone as a vulnerability.",
            ],
            "manual_confirmation": [
                "Pick a state-changing endpoint with account/security/billing/team impact.",
                "Send a cross-site form/fetch/navigation PoC from attacker origin.",
                "Remove, reuse, and swap CSRF token values across sessions.",
                "Forge missing/null/cross-site Origin and Referer variants.",
                "Read back the changed state from a separate session.",
            ],
            "report_gate": "Report only after exploit request plus independent read-back proves the state change.",
        }
    if "cache" in signal_type:
        return {
            "objective": "Prove shared cache key confusion, not browser-cache or one-off origin reflection.",
            "automated_checks": [
                "Require cache indicators such as Cache-Control, Age, ETag, X-Cache, CF-Cache-Status, or CDN timing.",
                "Use a cache-buster URL for the poison attempt.",
                "When enabled, send a clean follow-up request without the poisoning header.",
            ],
            "manual_confirmation": [
                "Repeat with two independent clients/sessions and a fresh cache key.",
                "Verify the victim response contains the attacker canary without attacker-controlled headers.",
                "Check TTL/Age changes across repeated clean requests.",
                "Test whether the poisoned value controls Location, ACAO, Link, HTML, or script-relevant content.",
            ],
            "report_gate": "Report only when a clean second client receives attacker-controlled cached content.",
        }
    if "crlf" in signal_type or "header" in signal_type:
        return {
            "objective": "Separate harmless reflection from response-header control or response splitting.",
            "automated_checks": [
                "Use a unique canary and record exact header/body location.",
                "Promote only parsed response headers such as X-PA-Injected, Location, Link, or ACAO.",
                "Keep body-only reflection below report threshold unless it gains cache/security impact.",
            ],
            "manual_confirmation": [
                "Repeat with a new canary and cache-buster.",
                "Try the same vector across sibling paths and redirects.",
                "Check if the value can set arbitrary headers, change redirects, poison CORS, or alter cacheable HTML.",
                "Confirm with a clean victim request if any cache indicator is present.",
            ],
            "report_gate": "Report only with parsed header injection, redirect/header control, or confirmed shared-cache impact.",
        }
    if "content" in signal_type:
        return {
            "objective": "Prove user-visible spoofing impact, not plain reflection on an untrusted page.",
            "automated_checks": [
                "Require textual response and exact canary reflection.",
                "Suppress plain body reflection in strict mode unless it appears in headers or cacheable responses.",
            ],
            "manual_confirmation": [
                "Verify the reflected content is visible in a victim-reachable browser page.",
                "Check if the response is cacheable, indexed, used in OAuth/login, or embedded in trusted UI.",
                "Attempt context escalation only with harmless markers and no user impact.",
            ],
            "report_gate": "Report only with victim-visible trusted-context spoofing, cacheability, or script/security impact.",
        }
    return {
        "objective": "Convert the lead into independent impact proof.",
        "automated_checks": ["Record exact request, response headers, status, and canary location."],
        "manual_confirmation": ["Repeat with a fresh canary and prove attacker-observable impact."],
        "report_gate": "Report only after independent reproduction and impact validation.",
    }


def assess_signal(signal: dict[str, Any]) -> dict[str, Any]:
    signal_type = signal.get("type", "")
    evidence = signal.get("evidence", {})
    locations = evidence_locations(evidence)
    status = response_status_from_signal(signal)
    confidence_score = CONFIDENCE_ORDER.get(signal.get("confidence", "low"), 1)
    score = 20 + (confidence_score * 8)
    reasons: list[str] = []
    missing: list[str] = []

    if status and 200 <= status < 400:
        score += 5
        reasons.append(f"HTTP {status} response accepted the probe")
    elif status:
        missing.append(f"probe returned HTTP {status}, reducing confidence")

    if signal_type == "cors_arbitrary_origin_with_credentials":
        score = 82
        reasons.extend(["exact Origin reflected", "Access-Control-Allow-Credentials is true"])
        if evidence.get("unsafe_methods"):
            score += 3
            reasons.append("unsafe CORS methods are advertised")
        missing.append("authenticated sensitive body read is not proven by header scan")
    elif signal_type == "cors_arbitrary_origin_reflection":
        score = 62
        reasons.append("exact Origin reflected in ACAO")
        missing.append("credentials or sensitive readable data not proven")
    elif signal_type == "cors_wildcard_origin":
        score = 28
        reasons.append("wildcard ACAO observed")
        missing.append("wildcard CORS alone is normally not reportable")
    elif signal_type == "cors_cache_poisoning_candidate":
        score = 70
        reasons.extend(["reflected Origin on cacheable response", "Vary: Origin missing"])
        missing.append("second-client poisoned response not proven")
    elif signal_type == "csrf_cookie_samesite_missing":
        score = 42 if evidence.get("likely_auth_cookie") else 20
        reasons.append("SameSite missing on Set-Cookie")
        missing.append("no cross-site state-changing request or read-back proof")
    elif signal_type == "csrf_cookie_cross_site_auth":
        score = 48
        reasons.append("likely auth cookie permits cross-site delivery")
        missing.append("CSRF token/origin enforcement and state change not tested")
    elif signal_type == "csrf_cookie_auth_unsafe_methods_exposed":
        score = 55
        reasons.extend(["likely auth cookie present", "unsafe methods advertised"])
        missing.append("browser-delivered exploit and separate read-back not proven")
    elif signal_type == "cookie_samesite_none_without_secure":
        score = 25
        reasons.append("cookie attribute hardening issue")
        missing.append("no exploitable session or CSRF impact proven")
    elif signal_type == "header_poisoning_candidate":
        score = 76
        reasons.append("canary reached security-relevant response header")
        missing.append("victim-observable impact not independently proven")
    elif signal_type == "header_reflection_candidate":
        score = 58
        reasons.append("canary reached response header")
        missing.append("plain reflection does not prove header control or splitting")
    elif signal_type == "header_based_content_spoofing":
        score = 52
        reasons.append("header canary reached textual response body")
        missing.append("trusted victim-visible spoofing or cache impact not proven")
    elif signal_type == "unkeyed_header_cache_poisoning_candidate":
        score = 72
        reasons.extend(["header canary reflected", "response has cache indicators"])
        missing.append("clean second-client cached response not proven")
    elif signal_type == "cache_poisoning_confirmed_on_cache_buster_url":
        score = 96
        reasons.extend(["poison request contained canary", "clean follow-up response contained canary"])
        missing.append("repeat on production-relevant low-traffic path and second client before report")
    elif signal_type == "query_parameter_content_reflection":
        score = 32
        reasons.append("query canary reflected in textual body")
        missing.append("plain reflection lacks trusted-context, cache, or script impact")
    elif signal_type == "query_parameter_header_reflection":
        score = 68
        reasons.append("query canary reached response header")
        missing.append("arbitrary header setting or response splitting not proven")
    elif signal_type == "response_splitting_crlf_candidate":
        if evidence.get("injected_header_seen"):
            score = 98
            reasons.append("CRLF probe produced a parsed response header")
        else:
            score = 60
            reasons.append("CRLF canary reflected but parsed injected header not observed")
            missing.append("parsed arbitrary header not proven")

    score = max(0, min(100, score))
    reportability = "report_ready" if score >= 95 else "strong_lead" if score >= 70 else "manual_review" if score >= 55 else "suppress_by_default"
    return {
        "score": score,
        "level": certainty_level(score),
        "reportability": reportability,
        "reasons": reasons,
        "missing_proof": missing,
    }


def apply_detection_assessment(signal: dict[str, Any]) -> None:
    signal["certainty"] = assess_signal(signal)
    signal["verification_plan"] = verification_template(signal.get("type", ""))


def signal_passes_fp_filter(signal: dict[str, Any], fp_mode: str, min_certainty: int) -> bool:
    if fp_mode == "all":
        return True

    signal_type = signal.get("type", "")
    evidence = signal.get("evidence", {})
    severity_score = SEVERITY_ORDER.get(signal.get("severity", "info"), 0)
    confidence_score = CONFIDENCE_ORDER.get(signal.get("confidence", "low"), 0)
    certainty_score = signal.get("certainty", {}).get("score", 0)

    if certainty_score < min_certainty:
        return False

    if signal_type == "csrf_cookie_samesite_missing" and not evidence.get("likely_auth_cookie"):
        return False
    if signal_type == "cookie_samesite_none_without_secure":
        return fp_mode != "strict"
    if signal_type == "cors_wildcard_origin":
        return fp_mode != "strict"

    if fp_mode == "strict":
        if signal_type in SUPPRESSED_BY_STRICT:
            return False
        if severity_score <= SEVERITY_ORDER["low"]:
            return False
        if confidence_score < CONFIDENCE_ORDER["medium"]:
            return False

    return True


def alert_allowed(signal: dict[str, Any], min_confidence: str) -> bool:
    return CONFIDENCE_ORDER.get(signal.get("confidence", "low"), 0) >= CONFIDENCE_ORDER[min_confidence]


def terminal_color(enabled: bool, severity: str) -> str:
    if not enabled:
        return ""
    return {
        "critical": "\033[95m",
        "high": "\033[91m",
        "medium": "\033[93m",
        "low": "\033[96m",
        "info": "\033[90m",
    }.get(severity, "")


def reset_color(enabled: bool) -> str:
    return "\033[0m" if enabled else ""


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def shorten(value: Any, limit: int = 180) -> str:
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def ui_box(title: str, lines: list[str], color: str = "", stream: Any | None = None) -> None:
    stream = sys.stderr if stream is None else stream
    width = 96
    reset = reset_color(bool(color))
    top = "+" + "-" * (width - 2) + "+"
    title_text = f" {title} "
    header = "|" + title_text[: width - 2].center(width - 2) + "|"
    rendered = [top, header, top]
    for line in lines:
        wrapped = wrap(str(line), width=width - 6, replace_whitespace=False) or [""]
        for part in wrapped:
            rendered.append("|  " + part.ljust(width - 6) + "  |")
    rendered.append(top)
    with ALERT_LOCK:
        print(color + "\n".join(rendered) + reset, file=stream, flush=True)


def ui_kv(label: str, value: Any) -> str:
    return f"{label:<18} {value}"


def emit_banner(args: argparse.Namespace) -> None:
    color = terminal_color(sys.stderr.isatty() and not args.no_color, "info")
    with ALERT_LOCK:
        print(color + BANNER.rstrip() + reset_color(bool(color)), file=sys.stderr, flush=True)


def emit_scan_start(input_path: Path, url_count: int, args: argparse.Namespace, out_dir: Path) -> None:
    color = terminal_color(sys.stderr.isatty() and not args.no_color, "info")
    lines = [
        ui_kv("Tool", f"{PRODUCT_NAME} v{VERSION}"),
        ui_kv("Focus", "CORS, CSRF, header injection, cache poisoning, content spoofing"),
        ui_kv("Input", input_path),
        ui_kv("URLs", url_count),
        ui_kv("Concurrency", args.concurrency),
        ui_kv("Mode", "fast + strict false-positive filter"),
        ui_kv("URL budget", f"{args.url_timeout:.1f}s max per URL"),
        ui_kv("Request timeout", f"{args.timeout:.1f}s"),
        ui_kv("Live alerts", "enabled; only high-certainty leads are printed"),
        ui_kv("Evidence", out_dir),
    ]
    emit_banner(args)
    ui_box("HEADERPROOF ACTIVE SCAN", lines, color=color)


def emit_progress(
    completed: int,
    total: int,
    started_at: float,
    results: list[dict[str, Any]],
    total_signals: int,
) -> None:
    elapsed = time.monotonic() - started_at
    rate = completed / elapsed if elapsed > 0 else 0
    remaining = (total - completed) / rate if rate > 0 else 0
    timed_out = sum(1 for result in results if result["status"] == "partial_timeout")
    filtered = sum(result.get("filtered_signals", 0) for result in results)
    percent = (completed / total) * 100 if total else 100
    line = (
        f"[headerproof] {completed}/{total} ({percent:5.1f}%) "
        f"rate={rate:.1f}/s eta={format_duration(remaining)} "
        f"timeouts={timed_out} alerts={total_signals} filtered={filtered}"
    )
    with ALERT_LOCK:
        print(line, file=sys.stderr, flush=True)


def format_evidence_lines(evidence: dict[str, Any], limit: int = 8) -> list[str]:
    lines: list[str] = []
    for key, value in evidence.items():
        if key in {"locations", "poison_locations", "victim_locations"} and isinstance(value, list):
            lines.append(f"{key}: {len(value)} hit(s)")
            for item in value[:3]:
                if isinstance(item, dict):
                    where = item.get("where", "?")
                    name = item.get("name", "?")
                    snippet = item.get("snippet", "")
                    lines.append(f"  - {where}.{name}: {shorten(snippet, 140)}")
                else:
                    lines.append(f"  - {shorten(item, 140)}")
        elif key == "cache_indicators" and isinstance(value, list):
            lines.append(f"{key}: {', '.join(shorten(item, 80) for item in value[:4])}")
        else:
            lines.append(f"{key}: {shorten(value)}")
        if len(lines) >= limit:
            lines.append("...")
            break
    return lines


def fp_guard_line(signal: dict[str, Any]) -> str:
    signal_type = signal.get("type", "")
    if signal_type.startswith("cors_"):
        return "FP guard: requires ACAO/ACAC header evidence from this exact probe; wildcard-only noise is filtered in strict mode."
    if signal_type.startswith("csrf_"):
        return "FP guard: cookie-only CSRF signals are kept only when the cookie name looks auth/session related."
    if "cache" in signal_type:
        return "FP guard: cache candidates require cache indicators or clean follow-up evidence; report only after cross-client confirmation."
    if "header" in signal_type or "crlf" in signal_type:
        return "FP guard: canary must appear in response header/body from this request; CRLF is separated from plain reflection."
    if "content" in signal_type:
        return "FP guard: plain body reflection is suppressed in strict mode unless it gains cache/header/security impact."
    return "FP guard: lead is still not report-ready until independent impact validation is done."


def emit_live_alert(url: str, signal: dict[str, Any], args: argparse.Namespace) -> None:
    if args.no_live_alerts or not alert_allowed(signal, args.min_alert_confidence):
        return

    color_enabled = sys.stderr.isatty() and not args.no_color
    severity = signal.get("severity", "info")
    color = terminal_color(color_enabled, severity)
    exchange = signal.get("exchange", {})
    response = exchange.get("response", {}) if isinstance(exchange, dict) else {}
    request_data = exchange.get("request", {}) if isinstance(exchange, dict) else {}
    certainty = signal.get("certainty", {})
    plan = signal.get("verification_plan", {})
    status = response.get("status", "?")
    elapsed = response.get("elapsed_ms", "?")
    method = request_data.get("method", "?")
    request_url = request_data.get("url", url)
    missing = certainty.get("missing_proof", [])
    confirmation = plan.get("manual_confirmation", []) if isinstance(plan, dict) else []

    lines = [
        ui_kv("Type", signal.get("type", "")),
        ui_kv("URL", shorten(url, 220)),
        ui_kv("Title", signal.get("title", "")),
        ui_kv("Check", signal.get("check", "")),
        ui_kv("HTTP", f"{method} {status} in {elapsed}ms"),
        ui_kv("Certainty", f"{certainty.get('score', 0)}% / {certainty.get('level', 'unknown')}"),
        ui_kv("Report gate", certainty.get("reportability", "unknown")),
        ui_kv("Request", shorten(request_url, 220)),
        "",
        "Evidence",
    ]
    lines.extend(f"  {line}" for line in format_evidence_lines(signal.get("evidence", {})))
    if missing:
        lines.extend(["", "Missing Proof"])
        lines.extend(f"  - {shorten(item, 160)}" for item in missing[:4])
    if confirmation:
        lines.extend(["", "Validation Plan"])
        lines.extend(f"  {index}. {shorten(item, 170)}" for index, item in enumerate(confirmation[:4], 1))
    lines.extend(["", fp_guard_line(signal), f"Next: {signal.get('next_step', '')}"])
    title = (
        f"ALERT {severity.upper()} / {signal.get('confidence', 'low').upper()} / "
        f"{certainty.get('score', 0)}% {certainty.get('level', 'unknown').upper()}"
    )
    ui_box(title, lines, color=color)


def parse_methods(*values: str) -> set[str]:
    methods: set[str] = set()
    for value in values:
        for part in re.split(r"[, ]+", value.upper()):
            part = part.strip()
            if part:
                methods.add(part)
    return methods


def parse_cookie(cookie: str) -> dict[str, Any]:
    parts = [part.strip() for part in cookie.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs: dict[str, Any] = {"name": name, "secure": False, "samesite": ""}
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key_l = key.strip().lower()
        if key_l == "secure":
            attrs["secure"] = True
        elif key_l == "samesite":
            attrs["samesite"] = value.strip().lower()
    attrs["likely_auth"] = bool(LIKELY_AUTH_COOKIE.search(name))
    return attrs


def analyze_csrf(baseline: HttpSnapshot, options: HttpSnapshot | None, save_body: bool) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    cookies = baseline.values("set-cookie")
    parsed_cookies = [parse_cookie(cookie) for cookie in cookies]
    for cookie in parsed_cookies:
        if not cookie["samesite"]:
            severity = "medium" if cookie["likely_auth"] else "low"
            signals.append(
                make_signal(
                    "csrf",
                    "csrf_cookie_samesite_missing",
                    severity,
                    "medium",
                    "Set-Cookie lacks SameSite; CSRF risk if this cookie authenticates state-changing requests",
                    {"cookie_name": cookie["name"], "likely_auth_cookie": cookie["likely_auth"]},
                    baseline,
                    "Confirm with a real state-changing action and a cross-site PoC before reporting.",
                    save_body,
                )
            )
        elif cookie["samesite"] == "none" and cookie["likely_auth"]:
            signals.append(
                make_signal(
                    "csrf",
                    "csrf_cookie_cross_site_auth",
                    "medium",
                    "medium",
                    "Likely auth cookie uses SameSite=None; CSRF depends on token/origin enforcement",
                    {
                        "cookie_name": cookie["name"],
                        "secure": cookie["secure"],
                        "samesite": cookie["samesite"],
                    },
                    baseline,
                    "Test token removal/reuse and forged Origin/Referer on an authorized state-changing workflow.",
                    save_body,
                )
            )
        if cookie["samesite"] == "none" and not cookie["secure"]:
            signals.append(
                make_signal(
                    "csrf",
                    "cookie_samesite_none_without_secure",
                    "low",
                    "high",
                    "Cookie sets SameSite=None without Secure",
                    {"cookie_name": cookie["name"]},
                    baseline,
                    "Treat as hardening signal unless chained to a working CSRF or session exposure path.",
                    save_body,
                )
            )

    method_headers = [header_join(baseline, "allow"), header_join(baseline, "access-control-allow-methods")]
    if options:
        method_headers.extend([header_join(options, "allow"), header_join(options, "access-control-allow-methods")])
    unsafe = sorted(parse_methods(*method_headers) & UNSAFE_METHODS)
    if unsafe and any(cookie["likely_auth"] for cookie in parsed_cookies):
        signals.append(
            make_signal(
                "csrf",
                "csrf_cookie_auth_unsafe_methods_exposed",
                "medium",
                "low",
                "Likely cookie-auth surface advertises unsafe methods",
                {"unsafe_methods": unsafe, "cookie_names": [c["name"] for c in parsed_cookies if c["likely_auth"]]},
                options or baseline,
                "Use browser/API parity testing and a separate read-back to prove a cross-site side effect.",
                save_body,
            )
        )
    return signals


def analyze_cors_probe(origin: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    acao_values = [value.strip() for value in snap.values("access-control-allow-origin")]
    if not acao_values:
        return signals
    acac = header_join(snap, "access-control-allow-credentials").lower().strip() == "true"
    cacheable, indicators = looks_cacheable(snap)
    methods = sorted(parse_methods(header_join(snap, "access-control-allow-methods")) & UNSAFE_METHODS)
    for acao in acao_values:
        acao_l = acao.lower()
        reflected = acao == origin or (origin == "null" and acao_l == "null")
        wildcard = acao == "*"
        if reflected and acac:
            signals.append(
                make_signal(
                    "cors",
                    "cors_arbitrary_origin_with_credentials",
                    "high",
                    "high",
                    "Arbitrary Origin is reflected with Access-Control-Allow-Credentials: true",
                    {
                        "origin": origin,
                        "access_control_allow_origin": acao,
                        "unsafe_methods": methods,
                    },
                    snap,
                    "Confirm against an authenticated sensitive endpoint and capture credentialed data exfiltration.",
                    save_body,
                )
            )
        elif reflected:
            signals.append(
                make_signal(
                    "cors",
                    "cors_arbitrary_origin_reflection",
                    "medium",
                    "high",
                    "Arbitrary Origin is reflected in Access-Control-Allow-Origin",
                    {"origin": origin, "access_control_allow_origin": acao, "unsafe_methods": methods},
                    snap,
                    "Check whether credentials, tokens, or sensitive unauthenticated data are reachable.",
                    save_body,
                )
            )
        elif wildcard:
            severity = "low"
            title = "Wildcard CORS is enabled"
            if acac:
                title = "Wildcard CORS appears with credentials header; browsers block credentialed wildcard reads"
            signals.append(
                make_signal(
                    "cors",
                    "cors_wildcard_origin",
                    severity,
                    "medium",
                    title,
                    {"origin": origin, "access_control_allow_origin": acao, "credentials": acac},
                    snap,
                    "Do not report wildcard CORS alone; chain to credentialed data exfiltration if possible.",
                    save_body,
                )
            )

        if reflected and not vary_has(snap, "origin") and cacheable:
            signals.append(
                make_signal(
                    "cache-poisoning",
                    "cors_cache_poisoning_candidate",
                    "medium",
                    "medium",
                    "Reflected CORS origin on a cacheable response lacks Vary: Origin",
                    {
                        "origin": origin,
                        "access_control_allow_origin": acao,
                        "cache_indicators": indicators,
                    },
                    snap,
                    "Confirm whether a second client receives the poisoned ACAO value from shared cache.",
                    save_body,
                )
            )
    return signals


def default_origin_variants(hostname: str, canary: str, user_origins: list[str], mode: str) -> list[str]:
    origins = [f"https://{canary}.invalid"]
    if mode == "standard":
        origins.append("null")
        if hostname:
            origins.append(f"https://{hostname}.attacker.invalid")
    origins.extend(user_origins)
    deduped: list[str] = []
    for origin in origins:
        if origin not in deduped:
            deduped.append(origin)
    return deduped


def default_header_probes(canary: str, custom_headers: list[str], limit: int) -> list[tuple[str, str]]:
    probes = [
        ("X-Forwarded-Host", f"{canary}.invalid"),
        ("Forwarded", f"for=192.0.2.1;host={canary}.invalid;proto=https"),
        ("X-Original-URL", f"/{canary}"),
        ("X-Host", f"{canary}.invalid"),
        ("X-Forwarded-Server", f"{canary}.invalid"),
        ("X-Rewrite-URL", f"/{canary}"),
        ("X-Forwarded-Prefix", f"/{canary}"),
    ]
    if limit > 0:
        probes = probes[:limit]
    for header in custom_headers:
        probes.append((header, f"{canary}.invalid"))
    return probes


def analyze_header_probe(
    header_name: str,
    canary: str,
    probe: HttpSnapshot,
    victim: HttpSnapshot | None,
    save_body: bool,
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    locations = canary_locations(probe, canary)
    if not locations:
        return signals

    cacheable, indicators = looks_cacheable(probe)
    reflected_headers = [loc for loc in locations if loc["where"] == "response_header"]
    reflected_body = [loc for loc in locations if loc["where"] == "response_body"]

    if reflected_headers:
        header_names = sorted({loc["name"] for loc in reflected_headers})
        signal_type = "header_reflection_candidate"
        severity = "medium"
        title = "Request header value is reflected into response headers"
        if any(name in {"location", "link", "access-control-allow-origin"} for name in header_names):
            signal_type = "header_poisoning_candidate"
            severity = "high"
            title = "Request header value controls a security-relevant response header"
        signals.append(
            make_signal(
                "header-injection",
                signal_type,
                severity,
                "high",
                title,
                {"probe_header": header_name, "locations": reflected_headers},
                probe,
                "Validate exploitability with a victim-context request pair; CRLF is not proven by reflection alone.",
                save_body,
            )
        )

    if reflected_body and is_textual_response(probe):
        signals.append(
            make_signal(
                "content-spoofing",
                "header_based_content_spoofing",
                "medium",
                "high",
                "Request header value is reflected in textual response body",
                {"probe_header": header_name, "locations": reflected_body},
                probe,
                "Check whether the reflected content is reachable by victims and whether it can be cached.",
                save_body,
            )
        )

    if cacheable:
        signals.append(
            make_signal(
                "cache-poisoning",
                "unkeyed_header_cache_poisoning_candidate",
                "medium",
                "medium",
                "Header reflection appears on a cacheable response",
                {
                    "probe_header": header_name,
                    "locations": locations,
                    "cache_indicators": indicators,
                },
                probe,
                "A report needs a clean victim request receiving the poisoned response from shared cache.",
                save_body,
            )
        )

    if victim and canary_locations(victim, canary):
        signals.append(
            make_signal(
                "cache-poisoning",
                "cache_poisoning_confirmed_on_cache_buster_url",
                "high",
                "high",
                "Clean follow-up request received the poisoned canary",
                {
                    "probe_header": header_name,
                    "poison_locations": locations,
                    "victim_locations": canary_locations(victim, canary),
                    "cache_indicators": indicators + cache_indicators(victim),
                },
                victim,
                "Repeat on an authorized low-traffic path and prove cross-client reachability before reporting.",
                save_body,
            )
        )

    return signals


def analyze_content_param(canary: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    locations = canary_locations(snap, canary)
    if not locations:
        return []
    signals: list[dict[str, Any]] = []
    body_hits = [loc for loc in locations if loc["where"] == "response_body"]
    header_hits = [loc for loc in locations if loc["where"] == "response_header"]
    if body_hits and is_textual_response(snap):
        signals.append(
            make_signal(
                "content-spoofing",
                "query_parameter_content_reflection",
                "low",
                "high",
                "Query parameter value is reflected in textual response body",
                {"locations": body_hits},
                snap,
                "Content spoofing becomes reportable only with victim impact, caching, or script execution.",
                save_body,
            )
        )
    if header_hits:
        signals.append(
            make_signal(
                "header-injection",
                "query_parameter_header_reflection",
                "medium",
                "medium",
                "Query parameter value is reflected into response headers",
                {"locations": header_hits},
                snap,
                "Try controlled response-splitting validation only on authorized targets and without user impact.",
                save_body,
            )
        )
    return signals


def analyze_crlf_probe(canary: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    injected_header_seen = "x-pa-injected" in snap.headers
    locations = canary_locations(snap, canary)
    if not injected_header_seen and not locations:
        return []
    severity = "high" if injected_header_seen else "medium"
    confidence = "high" if injected_header_seen else "medium"
    return [
        make_signal(
            "header-injection",
            "response_splitting_crlf_candidate",
            severity,
            confidence,
            "CRLF query probe influenced response headers",
            {
                "injected_header_seen": injected_header_seen,
                "locations": locations,
                "probe": "%0d%0aX-PA-Injected:<canary>",
            },
            snap,
            "Re-test manually with a harmless cache-buster and prove a victim-observable header/body change.",
            save_body,
        )
    ]


def scan_url(url: str, args: argparse.Namespace) -> dict[str, Any]:
    checks = args.enabled_checks
    result: dict[str, Any] = {
        "url": url,
        "status": "pending",
        "time_budget": {"seconds": args.url_timeout, "elapsed_ms": 0},
        "baseline": None,
        "signals": [],
        "filtered_signals": 0,
        "errors": [],
    }

    client = HttpClient(args.timeout, args.max_body, args.follow_redirects, args.delay)
    budget = UrlBudget(args.url_timeout)
    parsed = parse.urlsplit(url)
    hostname = parsed.hostname or ""
    canary = f"pa-scan-{secrets.token_hex(6)}"
    cache_url = add_query(url, {"pa_cb": canary})
    save_body = args.save_body_samples
    timeout_recorded = False
    result_lock = threading.Lock()

    def mark_timeout() -> None:
        nonlocal timeout_recorded
        with result_lock:
            if not timeout_recorded:
                result["errors"].append(f"url-timeout reached after {args.url_timeout:.2f}s")
                timeout_recorded = True
            result["status"] = "partial_timeout"

    def fetch_budgeted(
        request_url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpSnapshot | None:
        if budget.expired():
            mark_timeout()
            return None
        snap = client.fetch(request_url, method, headers, timeout=budget.request_timeout(args.timeout))
        if budget.expired():
            mark_timeout()
        return snap

    baseline = fetch_budgeted(url)
    if baseline is None:
        result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
        return result
    result["baseline"] = snapshot_summary(baseline, save_body=save_body)
    if baseline.error:
        result["errors"].append(baseline.error)

    options: HttpSnapshot | None = None
    if not args.no_preflight and ({"cors", "csrf"} & checks):
        options = fetch_budgeted(url, "OPTIONS")

    signals: list[dict[str, Any]] = []

    def add_signals(new_signals: list[dict[str, Any]]) -> None:
        for signal in new_signals:
            if not signal_passes_fp_filter(signal, args.fp_mode, args.min_certainty):
                result["filtered_signals"] += 1
                continue
            signals.append(signal)
            emit_live_alert(url, signal, args)

    if "csrf" in checks:
        add_signals(analyze_csrf(baseline, options, save_body))

    def run_probe_tasks(tasks: list[tuple[str, Any]]) -> None:
        if not tasks:
            return
        if budget.expired():
            mark_timeout()
            return

        max_workers = max(1, min(args.per_url_concurrency, len(tasks)))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        futures: dict[concurrent.futures.Future, str] = {}
        try:
            for name, task in tasks:
                if budget.expired():
                    mark_timeout()
                    break
                futures[executor.submit(task)] = name

            while futures:
                remaining = budget.remaining()
                if remaining <= 0:
                    mark_timeout()
                    break
                done, _ = concurrent.futures.wait(
                    futures,
                    timeout=remaining,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    mark_timeout()
                    break
                for future in done:
                    name = futures.pop(future)
                    try:
                        add_signals(future.result())
                    except Exception as exc:  # noqa: BLE001 - keep the URL scan moving.
                        with result_lock:
                            result["errors"].append(f"{name}: {type(exc).__name__}: {exc}")
        finally:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    probe_tasks: list[tuple[str, Any]] = []

    if "cors" in checks:
        for origin in default_origin_variants(hostname, canary, args.origin, args.origin_mode):
            def cors_task(origin: str = origin) -> list[dict[str, Any]]:
                cors_resp = fetch_budgeted(url, headers={"Origin": origin})
                if cors_resp is None:
                    return []
                return analyze_cors_probe(origin, cors_resp, save_body)

            probe_tasks.append((f"cors:{origin}", cors_task))
            if not args.no_preflight:
                def preflight_task(origin: str = origin) -> list[dict[str, Any]]:
                    preflight = fetch_budgeted(
                        url,
                        "OPTIONS",
                        {
                            "Origin": origin,
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "content-type,x-requested-with",
                        },
                    )
                    if preflight is None:
                        return []
                    return analyze_cors_probe(origin, preflight, save_body)

                probe_tasks.append((f"cors-preflight:{origin}", preflight_task))

    if {"header-injection", "cache-poisoning", "content-spoofing"} & checks:
        for header_name, header_value in default_header_probes(canary, args.header, args.header_probe_limit):
            def header_task(
                header_name: str = header_name,
                header_value: str = header_value,
            ) -> list[dict[str, Any]]:
                probe = fetch_budgeted(cache_url, headers={header_name: header_value})
                if probe is None:
                    return []
                victim: HttpSnapshot | None = None
                if "cache-poisoning" in checks and not args.no_cache_confirm and canary_locations(probe, canary):
                    victim = fetch_budgeted(cache_url)
                return analyze_header_probe(header_name, canary, probe, victim, save_body)

            probe_tasks.append((f"header:{header_name}", header_task))

    if "content-spoofing" in checks:
        content_url = add_query(url, {args.content_param: canary})
        def content_task() -> list[dict[str, Any]]:
            content_probe = fetch_budgeted(content_url)
            if content_probe is None:
                return []
            return analyze_content_param(canary, content_probe, save_body)

        probe_tasks.append(("content-param", content_task))

    if "header-injection" in checks and not args.no_crlf:
        crlf_url = add_raw_query(url, "pa_crlf", f"%0d%0aX-PA-Injected%3A%20{canary}")
        def crlf_task() -> list[dict[str, Any]]:
            crlf_probe = fetch_budgeted(crlf_url)
            if crlf_probe is None:
                return []
            return analyze_crlf_probe(canary, crlf_probe, save_body)

        probe_tasks.append(("crlf", crlf_task))

    run_probe_tasks(probe_tasks)

    signals.sort(key=lambda item: SEVERITY_ORDER.get(item["severity"], 0), reverse=True)
    result["signals"] = signals
    result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
    if result["status"] != "partial_timeout":
        result["status"] = "scanned"
    return result


def parse_checks(raw: str) -> set[str]:
    checks = {item.strip().lower() for item in raw.split(",") if item.strip()}
    unknown = checks - DEFAULT_CHECKS
    if unknown:
        raise SystemExit(f"ERROR: Unknown checks: {', '.join(sorted(unknown))}")
    return checks or set(DEFAULT_CHECKS)


def apply_profile_defaults(args: argparse.Namespace) -> argparse.Namespace:
    defaults = PROFILE_DEFAULTS[args.profile]
    for key, value in defaults.items():
        if getattr(args, key) is None:
            setattr(args, key, value)
    return args


def parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    profile_defaults = PROFILE_DEFAULTS["fast"]
    args.profile = "fast"
    args.enabled_checks = set(DEFAULT_CHECKS)
    args.fp_mode = "strict"
    args.min_alert_confidence = "medium"
    args.min_certainty = FP_CERTAINTY_DEFAULTS[args.fp_mode]
    args.timeout = profile_defaults["timeout"]
    args.url_timeout = 9.0
    args.max_body = profile_defaults["max_body"]
    args.per_url_concurrency = profile_defaults["per_url_concurrency"]
    args.origin_mode = profile_defaults["origin_mode"]
    args.header_probe_limit = profile_defaults["header_probe_limit"]
    args.no_preflight = profile_defaults["no_preflight"]
    args.no_cache_confirm = profile_defaults["no_cache_confirm"]
    args.delay = 0.0
    args.max_urls = 0
    args.follow_redirects = False
    args.save_body_samples = False
    args.no_crlf = False
    args.origin = []
    args.header = []
    args.content_param = "pa_reflect"
    args.progress_every = 50
    args.quiet = False
    args.no_live_alerts = False
    args.no_color = False
    args.json = False
    args.out_dir = ""

    args.concurrency = max(1, args.concurrency)
    args.per_url_concurrency = max(1, args.per_url_concurrency)
    args.url_timeout = max(0.1, args.url_timeout)
    args.timeout = max(0.05, min(args.timeout, args.url_timeout))
    args.delay = max(0.0, args.delay)
    args.max_body = max(0, args.max_body)
    args.header_probe_limit = max(0, args.header_probe_limit)
    args.progress_every = max(0, args.progress_every)
    args.min_certainty = max(0, min(100, args.min_certainty))
    return args


def write_outputs(results: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in results) + "\n"
    atomic_write_text(out_dir / "results.jsonl", results_jsonl)

    flat_signals: list[dict[str, Any]] = []
    for item in results:
        for signal in item["signals"]:
            flat = {"url": item["url"], **signal}
            flat_signals.append(flat)
    signals_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in flat_signals)
    atomic_write_text(out_dir / "signals.jsonl", signals_jsonl + ("\n" if signals_jsonl else ""))

    lines = [
        "# HeaderProof Scan Summary",
        "",
        f"- generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- urls: {len(results)}",
        f"- scanned: {sum(1 for item in results if item['status'] == 'scanned')}",
        f"- partial_timeout: {sum(1 for item in results if item['status'] == 'partial_timeout')}",
        f"- signals: {len(flat_signals)}",
        f"- filtered_signals: {sum(item.get('filtered_signals', 0) for item in results)}",
        "",
        "| URL | Status | Signals | Top Types |",
        "| --- | --- | ---: | --- |",
    ]
    for item in results:
        types = Counter(signal["type"] for signal in item["signals"])
        top_types = ", ".join(f"{name}({count})" for name, count in types.most_common(4))
        lines.append(f"| {item['url']} | {item['status']} | {len(item['signals'])} | {top_types} |")

    if flat_signals:
        lines.extend(["", "## Signals", ""])
        for signal in sorted(flat_signals, key=lambda item: SEVERITY_ORDER.get(item["severity"], 0), reverse=True):
            certainty = signal.get("certainty", {})
            lines.append(
                (
                    f"- **{signal['severity'].upper()}** `{signal['type']}` "
                    f"certainty={certainty.get('score', 0)}%/{certainty.get('level', 'unknown')} "
                    f"{signal['url']} - {signal['title']}"
                )
            )
            missing = certainty.get("missing_proof", [])
            if missing:
                lines.append(f"  Missing proof: {shorten('; '.join(missing), 260)}")
    atomic_write_text(out_dir / "summary.md", "\n".join(lines) + "\n")
    write_verification_plan(out_dir)


def write_verification_plan(out_dir: Path) -> None:
    plans = {
        "CORS": verification_template("cors_arbitrary_origin_with_credentials"),
        "CSRF": verification_template("csrf_cookie_samesite_missing"),
        "Header Injection / Response Splitting": verification_template("response_splitting_crlf_candidate"),
        "Cache Poisoning": verification_template("cache_poisoning_confirmed_on_cache_buster_url"),
        "Content Spoofing": verification_template("query_parameter_content_reflection"),
    }
    lines = [
        "# Verification Plan",
        "",
        "This scanner intentionally treats most header-only observations as leads. A finding is report-ready only after the report gate for its class is satisfied.",
        "",
        "## Certainty Levels",
        "",
        "- 95-100: confirmed technical primitive, still validate program impact before reporting.",
        "- 85-94: very high confidence lead.",
        "- 70-84: high confidence lead kept by strict mode.",
        "- 55-69: manual-review lead kept by balanced mode.",
        "- <55: suppressed by the scanner's default false-positive filter.",
        "",
    ]
    for name, plan in plans.items():
        lines.extend([f"## {name}", "", f"Objective: {plan['objective']}", "", "Automated Checks:"])
        lines.extend(f"- {item}" for item in plan["automated_checks"])
        lines.extend(["", "Manual Confirmation:"])
        lines.extend(f"- {item}" for item in plan["manual_confirmation"])
        lines.extend(["", f"Report Gate: {plan['report_gate']}", ""])
    atomic_write_text(out_dir / "verification-plan.md", "\n".join(lines))


def print_console_summary(results: list[dict[str, Any]], out_dir: Path, as_json: bool) -> None:
    flat = [signal for item in results for signal in item["signals"]]
    payload = {
        "urls": len(results),
        "scanned": sum(1 for item in results if item["status"] == "scanned"),
        "partial_timeout": sum(1 for item in results if item["status"] == "partial_timeout"),
        "signals": len(flat),
        "filtered_signals": sum(item.get("filtered_signals", 0) for item in results),
        "by_severity": dict(Counter(signal["severity"] for signal in flat)),
        "by_certainty": dict(Counter(signal.get("certainty", {}).get("level", "unknown") for signal in flat)),
        "by_type": dict(Counter(signal["type"] for signal in flat).most_common()),
        "out_dir": str(out_dir),
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    lines = [
        ui_kv("URLs", payload["urls"]),
        ui_kv("Scanned", payload["scanned"]),
        ui_kv("Partial timeout", payload["partial_timeout"]),
        ui_kv("Alerts", payload["signals"]),
        ui_kv("Filtered", payload["filtered_signals"]),
        ui_kv("Severity", payload["by_severity"] or "none"),
    ]
    if payload["by_certainty"]:
        lines.append(ui_kv("Certainty", ", ".join(f"{name}={count}" for name, count in payload["by_certainty"].items())))
    if payload["by_type"]:
        lines.append(ui_kv("Types", ", ".join(f"{name}={count}" for name, count in payload["by_type"].items())))
    lines.extend(
        [
            ui_kv("Evidence", out_dir),
            ui_kv("Files", "results.jsonl, signals.jsonl, summary.md, verification-plan.md"),
        ]
    )
    ui_box("SCAN COMPLETE", lines, stream=sys.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Active header/CORS/CSRF/cache/content-spoofing scanner")
    parser.add_argument("-i", dest="input", required=True, help="File containing one URL per line or httpx-style JSONL")
    parser.add_argument("--concurrency", type=int, default=16, help="Concurrent URL workers")
    return parser


def main_from_args(argv: list[str] | None = None) -> int:
    args = parse_cli_args(argv)
    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        print(f"ERROR: input URL file not found: {input_path}", file=sys.stderr)
        print("Pass a real URL list path, for example: -i /home/tayfur/urls.txt", file=sys.stderr)
        return 2
    if not input_path.is_file():
        print(f"ERROR: input path is not a file: {input_path}", file=sys.stderr)
        return 2

    urls = load_urls(input_path, max_urls=args.max_urls or None)
    if not urls:
        print("ERROR: No usable URLs found in input file.", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir) if args.out_dir else Path("evidence") / f"headerproof-{datetime.now():%Y%m%d-%H%M%S}"
    emit_scan_start(input_path, len(urls), args, out_dir)

    results: list[dict[str, Any]] = []
    completed = 0
    total_signals = 0
    started_at = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(scan_url, url, args): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                item = future.result()
            except Exception as exc:  # noqa: BLE001 - scanner should keep batch evidence moving.
                item = {
                    "url": url,
                    "status": "error",
                    "baseline": None,
                    "signals": [],
                    "filtered_signals": 0,
                    "errors": [repr(exc)],
                }
            results.append(item)
            completed += 1
            total_signals += len(item["signals"])
            if not args.quiet and args.progress_every and completed % args.progress_every == 0:
                emit_progress(completed, len(urls), started_at, results, total_signals)

    results.sort(key=lambda item: item["url"])
    write_outputs(results, out_dir)
    print_console_summary(results, out_dir, args.json)
    return 0


def main() -> int:
    return main_from_args()


if __name__ == "__main__":
    raise SystemExit(main())
