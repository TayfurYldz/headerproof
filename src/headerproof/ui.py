from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections import Counter
from textwrap import wrap
from typing import Any

from .constants import BANNER, CONFIDENCE_ORDER, PRODUCT_NAME, VERSION

ALERT_LOCK = threading.Lock()


def alert_allowed(signal: dict[str, Any], min_confidence: str) -> bool:
    assessment = signal.get("assessment", {})
    if assessment.get("technical_gate") != "passed":
        return False
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


def progress_bar(percent: float, width: int = 18) -> str:
    filled = max(0, min(width, int(round((percent / 100) * width))))
    return "█" * filled + "░" * (width - filled)


def ui_box(title: str, lines: list[str], color: str = "", stream: Any | None = None) -> None:
    stream = sys.stderr if stream is None else stream
    width = 100
    reset = reset_color(bool(color))
    title_text = f" {shorten(title, width - 6)} "
    top = "╭" + title_text + "─" * max(0, width - len(title_text) - 2) + "╮"
    rendered = [top]
    for line in lines:
        wrapped = wrap(str(line), width=width - 6, replace_whitespace=False) or [""]
        for part in wrapped:
            rendered.append("│  " + part.ljust(width - 6) + "  │")
    rendered.append("╰" + "─" * (width - 2) + "╯")
    with ALERT_LOCK:
        print(color + "\n".join(rendered) + reset, file=stream, flush=True)


def ui_kv(label: str, value: Any) -> str:
    return f"{label:<18} {value}"


def emit_banner(args: argparse.Namespace) -> None:
    color = terminal_color(sys.stderr.isatty() and not args.no_color, "info")
    with ALERT_LOCK:
        print(color + BANNER.rstrip() + reset_color(bool(color)), file=sys.stderr, flush=True)


def emit_scan_start(input_path: Any, url_count: int | str, args: argparse.Namespace, out_dir: Any) -> None:
    color = terminal_color(sys.stderr.isatty() and not args.no_color, "info")
    lines = [
        ui_kv("Tool", f"{PRODUCT_NAME} v{VERSION}"),
        ui_kv("Focus", "CORS, CSRF, header injection, cache poisoning, content spoofing"),
        ui_kv("Input", input_path),
        ui_kv("URLs", url_count),
        ui_kv("Concurrency", args.concurrency),
        ui_kv("Mode", "evidence-first; live cards only for verified technical signals"),
        ui_kv("URL budget", f"{args.url_timeout:.1f}s max per URL"),
        ui_kv("Request timeout", f"{args.timeout:.1f}s"),
        ui_kv("Live signals", "enabled; requires an explicit detector proof gate"),
        ui_kv("Evidence", out_dir),
    ]
    emit_banner(args)
    ui_box("HEADERPROOF ACTIVE SCAN", lines, color=color)


def emit_progress(
    completed: int,
    total: int,
    started_at: float,
    statuses: Counter[str],
    total_signals: int,
    filtered: int,
) -> None:
    elapsed = time.monotonic() - started_at
    rate = completed / elapsed if elapsed > 0 else 0
    remaining = (total - completed) / rate if rate > 0 else 0
    timed_out = statuses["partial_timeout"]
    errors = statuses["error"] + statuses["partial_error"]
    percent = (completed / total) * 100 if total else 100
    bar = progress_bar(percent)
    line = (
        f"HeaderProof  {bar}  {completed}/{total} {percent:5.1f}%  "
        f"{rate:.1f}/s  eta {format_duration(remaining)}  "
        f"verified {total_signals}  suppressed {filtered}  errors {errors}  timeouts {timed_out}"
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
    return "FP guard: technical evidence still requires independent impact validation before submission."


def emit_live_alert(url: str, signal: dict[str, Any], args: argparse.Namespace) -> None:
    if args.no_live_alerts or not alert_allowed(signal, args.min_alert_confidence):
        return

    color_enabled = sys.stderr.isatty() and not args.no_color
    severity = signal.get("severity", "info")
    color = terminal_color(color_enabled, severity)
    exchange = signal.get("exchange", {})
    response = exchange.get("response", {}) if isinstance(exchange, dict) else {}
    request_data = exchange.get("request", {}) if isinstance(exchange, dict) else {}
    assessment = signal.get("assessment", {})
    plan = signal.get("verification_plan", {})
    status = response.get("status", "?")
    elapsed = response.get("elapsed_ms", "?")
    method = request_data.get("method", "?")
    request_url = request_data.get("url", url)
    missing = assessment.get("missing_proof", [])
    reasons = assessment.get("reasons", [])
    confirmation = plan.get("manual_confirmation", []) if isinstance(plan, dict) else []

    lines = [
        ui_kv("Finding", signal.get("title", "")),
        ui_kv("Class", signal.get("check", "")),
        ui_kv("Type", signal.get("type", "")),
        ui_kv("Target", shorten(url, 220)),
        ui_kv("HTTP", f"{method} {status} in {elapsed}ms"),
        ui_kv("Evidence state", assessment.get("state", "unknown")),
        ui_kv("Technical gate", assessment.get("technical_gate", "unknown")),
        ui_kv("Impact", assessment.get("impact", "unknown")),
        ui_kv("Replay", shorten(request_url, 220)),
        "",
        "Why it is shown",
    ]
    lines.extend(f"  - {shorten(item, 170)}" for item in reasons[:4])
    lines.extend(["", "Evidence"])
    lines.extend(f"  {line}" for line in format_evidence_lines(signal.get("evidence", {})))
    lines.extend(["", "Still verify before reporting"])
    if missing:
        lines.extend(f"  - {shorten(item, 160)}" for item in missing[:4])
    else:
        lines.append("  - Repeat with a fresh canary and confirm real program impact before submission.")
    if confirmation:
        lines.extend(["", "Next validation"])
        lines.extend(f"  {index}. {shorten(item, 170)}" for index, item in enumerate(confirmation[:4], 1))
    lines.extend(["", fp_guard_line(signal), f"Next: {signal.get('next_step', '')}"])
    title = f"VERIFIED TECHNICAL SIGNAL · {severity.upper()} · {assessment.get('state', 'unknown').upper()}"
    ui_box(title, lines, color=color)
