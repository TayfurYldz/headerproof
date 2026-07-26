#!/usr/bin/env python3
"""HeaderProof command-line entrypoint."""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import DEFAULT_CHECKS, FP_CERTAINTY_DEFAULTS, PRODUCT_NAME, PROFILE_DEFAULTS, SCHEMA_VERSION, VERSION
from .detectors import (
    analyze_content_param,
    analyze_cors_probe,
    analyze_crlf_probe,
    analyze_csrf,
    analyze_header_probe,
    cache_hit_progressed,
    cache_indicators,
    canary_locations,
    default_header_probe_names,
    default_origin_variants,
    header_join,
    header_probe_value,
    looks_cacheable,
    parse_cookie,
    parse_methods,
    shared_cache_hit_markers,
)
from .engine import scan_url
from .evidence import assess_signal, make_signal, signal_passes_fp_filter, verification_template
from .input import add_query, add_raw_query, iter_urls, load_urls, normalise_url
from .metadata import build_metadata, current_git_commit, safe_cli_args, scan_config
from .models import HttpSnapshot
from .output import print_console_summary, write_outputs
from .transport import HttpClient, UrlBudget, snapshot_summary
from .ui import emit_progress, emit_scan_start


def parse_checks(raw: str) -> set[str]:
    checks = {item.strip().lower() for item in raw.split(",") if item.strip()}
    unknown = checks - DEFAULT_CHECKS
    if unknown:
        raise SystemExit(f"ERROR: Unknown checks: {', '.join(sorted(unknown))}")
    return checks or set(DEFAULT_CHECKS)


def parse_header_name(raw: str) -> str:
    name = raw.strip()
    if not name:
        raise argparse.ArgumentTypeError("header name cannot be empty")
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
        raise argparse.ArgumentTypeError("invalid HTTP header name")
    return name


def parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_argv)

    profile_defaults = PROFILE_DEFAULTS[args.profile]
    args.argv = raw_argv
    args.enabled_checks = set(DEFAULT_CHECKS)
    args.fp_mode = "strict"
    args.min_alert_confidence = "medium"
    args.min_certainty = FP_CERTAINTY_DEFAULTS[args.fp_mode]
    args.timeout = profile_defaults["timeout"] if args.timeout is None else args.timeout
    args.url_timeout = 9.0
    args.max_body = profile_defaults["max_body"]
    args.concurrency = profile_defaults["concurrency"] if args.concurrency is None else args.concurrency
    args.per_url_concurrency = min(profile_defaults["per_url_concurrency"], args.concurrency)
    args.origin_mode = profile_defaults["origin_mode"]
    args.header_probe_limit = profile_defaults["header_probe_limit"]
    args.no_preflight = profile_defaults["no_preflight"]
    args.no_cache_confirm = profile_defaults["no_cache_confirm"]
    args.delay = 0.0
    args.max_urls = 0
    args.follow_redirects = False
    args.save_body_samples = False
    args.no_crlf = False
    args.header = args.header or []
    args.content_param = "pa_reflect"
    args.progress_every = 50
    args.quiet = bool(args.quiet or args.json)
    args.no_live_alerts = bool(args.quiet)
    args.no_color = False

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

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRODUCT_NAME.lower(),
        description="Fast, low-noise active scanner for CORS, CSRF, header injection, cache poisoning, and content spoofing leads.",
    )
    parser.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {VERSION}")
    parser.add_argument("-i", dest="input", required=True, help="File containing one URL per line or httpx-style JSONL")
    parser.add_argument("--concurrency", type=int, default=None, help="Concurrent URL workers")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_DEFAULTS),
        default="fast",
        help="Scan profile: fast keeps the 9s URL budget tight; balanced/thorough add more probes inside the same budget",
    )
    parser.add_argument("--timeout", type=float, default=None, help="Per-request timeout in seconds, capped by the 9s URL budget")
    parser.add_argument("--origin", action="append", default=[], help="Additional Origin value to probe; repeatable")
    parser.add_argument(
        "--header",
        action="append",
        type=parse_header_name,
        default=[],
        metavar="NAME",
        help="Additional request header name to probe with a generated canary value; repeatable",
    )
    parser.add_argument("--out-dir", default="", help="Evidence output directory")
    parser.add_argument("--json", action="store_true", help="Print final summary as JSON and suppress live terminal UI")
    parser.add_argument("--quiet", action="store_true", help="Suppress banner, progress, and live alert cards")
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

    url_iter = iter(iter_urls(input_path, max_urls=args.max_urls or None))
    first_url = next(url_iter, None)
    if not first_url:
        print("ERROR: No usable URLs found in input file.", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir) if args.out_dir else Path("evidence") / f"headerproof-{datetime.now():%Y%m%d-%H%M%S}"
    metadata = build_metadata(args, input_path, 0)
    args.request_semaphore = threading.BoundedSemaphore(args.concurrency)
    if not args.quiet:
        emit_scan_start(input_path, "streaming", args, out_dir)

    results: list[dict[str, Any]] = []
    completed = 0
    submitted = 0
    total_signals = 0
    started_at = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures: dict[concurrent.futures.Future, str] = {}
        exhausted = False

        def submit_url(item_url: str) -> None:
            nonlocal submitted
            futures[executor.submit(scan_url, item_url, args)] = item_url
            submitted += 1

        submit_url(first_url)
        while futures:
            while not exhausted and len(futures) < args.concurrency:
                next_url = next(url_iter, None)
                if next_url is None:
                    exhausted = True
                    break
                submit_url(next_url)
            done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                url = futures.pop(future)
                try:
                    item = future.result()
                except Exception as exc:  # noqa: BLE001 - scanner should keep batch evidence moving.
                    item = {
                        "schema_version": SCHEMA_VERSION,
                        "url": url,
                        "status": "error",
                        "baseline": None,
                        "probes": [],
                        "observations": [],
                        "signals": [],
                        "filtered_signals": 0,
                        "duplicate_signals": 0,
                        "errors": [repr(exc)],
                    }
                results.append(item)
                completed += 1
                total_signals += len(item["signals"])
                if not args.quiet and args.progress_every and completed % args.progress_every == 0:
                    emit_progress(completed, submitted, started_at, results, total_signals)

    results.sort(key=lambda item: item["url"])
    metadata["url_count"] = submitted
    write_outputs(results, out_dir, metadata)
    print_console_summary(results, out_dir, args.json)
    return 0


def main() -> int:
    return main_from_args()
