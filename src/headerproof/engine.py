from __future__ import annotations

import argparse
import concurrent.futures
import secrets
import threading
import time
from typing import Any
from urllib import parse

from .constants import SCHEMA_VERSION, SEVERITY_ORDER
from .detectors import (
    analyze_content_param,
    analyze_cors_probe,
    analyze_crlf_probe,
    analyze_csrf,
    analyze_header_probe,
    canary_locations,
    default_header_probe_names,
    default_origin_variants,
    header_probe_value,
)
from .evidence import signal_passes_fp_filter
from .input import add_query, add_raw_query
from .models import HttpSnapshot
from .transport import HttpClient, UrlBudget, snapshot_summary
from .ui import emit_live_alert

def scan_url(url: str, args: argparse.Namespace) -> dict[str, Any]:
    checks = args.enabled_checks
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "url": url,
        "status": "pending",
        "time_budget": {"seconds": args.url_timeout, "elapsed_ms": 0},
        "baseline": None,
        "probes": [],
        "observations": [],
        "signals": [],
        "filtered_signals": 0,
        "duplicate_signals": 0,
        "errors": [],
    }

    client = HttpClient(args.timeout, args.max_body, args.follow_redirects, args.delay)
    budget = UrlBudget(args.url_timeout)
    parsed = parse.urlsplit(url)
    hostname = parsed.hostname or ""
    save_body = args.save_body_samples
    timeout_recorded = False
    result_lock = threading.Lock()

    def new_canary() -> str:
        return f"pa-scan-{secrets.token_hex(6)}"

    def new_probe_id(prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(5)}"

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
        probe_id: str = "",
        role: str = "",
    ) -> HttpSnapshot | None:
        if budget.expired():
            mark_timeout()
            return None
        semaphore = getattr(args, "request_semaphore", None)
        if semaphore is None:
            snap = client.fetch(request_url, method, headers, timeout=budget.request_timeout(args.timeout))
        else:
            with semaphore:
                snap = client.fetch(request_url, method, headers, timeout=budget.request_timeout(args.timeout))
        with result_lock:
            result["probes"].append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "probe_id": probe_id or new_probe_id("probe"),
                    "role": role or "probe",
                    "exchange": snapshot_summary(snap, save_body=save_body),
                }
            )
        if budget.expired():
            mark_timeout()
        return snap

    baseline = fetch_budgeted(url, probe_id="baseline", role="baseline")
    if baseline is None:
        result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
        return result
    result["baseline"] = snapshot_summary(baseline, save_body=save_body)
    if baseline.error:
        result["errors"].append(baseline.error)
        result["status"] = "error"
        result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
        return result

    options: HttpSnapshot | None = None
    if not args.no_preflight and ({"cors", "csrf"} & checks):
        options = fetch_budgeted(url, "OPTIONS", probe_id="preflight", role="preflight")

    signals: list[dict[str, Any]] = []
    seen_signal_keys: set[tuple[str, str]] = set()

    def add_signals(new_signals: list[dict[str, Any]]) -> None:
        for signal in new_signals:
            observation = {**signal, "url": url, "kept": False, "filter_mode": args.fp_mode, "filter_reason": ""}
            if not signal_passes_fp_filter(signal, args.fp_mode, args.min_certainty):
                observation["filter_reason"] = "below_strict_report_ready_gate"
                result["observations"].append(observation)
                result["filtered_signals"] += 1
                continue
            signal_key = (signal.get("check", ""), signal.get("type", ""))
            if args.fp_mode == "strict" and signal_key in seen_signal_keys:
                observation["filter_reason"] = "duplicate_type_in_strict_mode"
                result["observations"].append(observation)
                result["duplicate_signals"] += 1
                continue
            seen_signal_keys.add(signal_key)
            observation["kept"] = True
            observation["filter_reason"] = "kept_as_finding"
            result["observations"].append(observation)
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
        cors_canary = new_canary()
        for origin in default_origin_variants(hostname, cors_canary, args.origin, args.origin_mode):
            def cors_task(origin: str = origin) -> list[dict[str, Any]]:
                cors_resp = fetch_budgeted(url, headers={"Origin": origin}, probe_id=new_probe_id("cors"), role="cors")
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
                        probe_id=new_probe_id("cors-preflight"),
                        role="cors-preflight",
                    )
                    if preflight is None:
                        return []
                    return analyze_cors_probe(origin, preflight, save_body)

                probe_tasks.append((f"cors-preflight:{origin}", preflight_task))

    if "content-spoofing" in checks:
        canary = new_canary()
        content_url = add_query(url, {args.content_param: canary})
        def content_task(canary: str = canary, content_url: str = content_url) -> list[dict[str, Any]]:
            content_probe = fetch_budgeted(content_url, probe_id=new_probe_id("content"), role="content-param")
            if content_probe is None:
                return []
            return analyze_content_param(canary, content_probe, save_body)

        probe_tasks.append(("content-param", content_task))

    if "header-injection" in checks and not args.no_crlf:
        canary = new_canary()
        crlf_url = add_raw_query(url, "pa_crlf", f"%0d%0aX-PA-Injected%3A%20{canary}")
        def crlf_task(canary: str = canary, crlf_url: str = crlf_url) -> list[dict[str, Any]]:
            crlf_probe = fetch_budgeted(crlf_url, probe_id=new_probe_id("crlf"), role="crlf")
            if crlf_probe is None:
                return []
            return analyze_crlf_probe(canary, crlf_probe, save_body)

        probe_tasks.append(("crlf", crlf_task))

    if {"header-injection", "cache-poisoning", "content-spoofing"} & checks:
        for header_name in default_header_probe_names(args.header, args.header_probe_limit):
            def header_task(
                header_name: str = header_name,
            ) -> list[dict[str, Any]]:
                probe_id = new_probe_id("header")
                canary = new_canary()
                header_value = header_probe_value(header_name, canary)
                cache_url = add_query(url, {"pa_cb": probe_id})
                control_url = add_query(url, {"pa_cb": f"{probe_id}-control"})
                clean_before = None
                if "cache-poisoning" in checks and not args.no_cache_confirm:
                    clean_before = fetch_budgeted(cache_url, probe_id=f"{probe_id}-clean-before", role="cache-clean-before")
                probe = fetch_budgeted(
                    cache_url,
                    headers={header_name: header_value},
                    probe_id=f"{probe_id}-poison",
                    role="cache-poison",
                )
                if probe is None:
                    return []
                victim: HttpSnapshot | None = None
                control: HttpSnapshot | None = None
                if "cache-poisoning" in checks and not args.no_cache_confirm and canary_locations(probe, canary):
                    victim = fetch_budgeted(cache_url, probe_id=f"{probe_id}-victim", role="cache-victim")
                    control = fetch_budgeted(control_url, probe_id=f"{probe_id}-fresh-control", role="cache-fresh-control")
                return analyze_header_probe(header_name, canary, probe_id, clean_before, probe, victim, control, save_body)

            probe_tasks.append((f"header:{header_name}", header_task))

    run_probe_tasks(probe_tasks)

    signals.sort(
        key=lambda item: (
            item.get("certainty", {}).get("score", 0),
            SEVERITY_ORDER.get(item["severity"], 0),
        ),
        reverse=True,
    )
    result["signals"] = signals
    result["time_budget"]["elapsed_ms"] = int(budget.elapsed() * 1000)
    if result["status"] != "partial_timeout":
        result["status"] = "scanned"
    return result
