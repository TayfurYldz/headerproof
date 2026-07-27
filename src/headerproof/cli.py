#!/usr/bin/env python3
"""HeaderProof command-line entrypoint."""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from .constants import DEFAULT_CHECKS, PRODUCT_NAME, PROFILE_DEFAULTS, SCHEMA_VERSION, VERSION
from .engine import scan_url
from .input import iter_urls
from .metadata import build_metadata
from .output import EvidenceWriter, print_console_summary, reserve_output_dir
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

    try:
        out_dir = reserve_output_dir(Path(args.out_dir) if args.out_dir else None)
    except (FileExistsError, OSError) as exc:
        print(f"ERROR: cannot prepare evidence directory: {exc}", file=sys.stderr)
        return 2

    url_iter = iter(
        iter_urls(
            input_path,
            max_urls=args.max_urls or None,
            dedup_db=out_dir / "input-dedup.sqlite3",
        )
    )
    first_url = next(url_iter, None)
    if not first_url:
        print("ERROR: No usable URLs found in input file.", file=sys.stderr)
        return 2

    metadata = build_metadata(args, input_path, 0)
    writer = EvidenceWriter(out_dir, metadata)
    args.request_semaphore = threading.BoundedSemaphore(args.concurrency)
    if not args.quiet:
        emit_scan_start(input_path, "streaming", args, out_dir)

    completed = 0
    submitted = 0
    total_signals = 0
    filtered_signals = 0
    statuses: Counter[str] = Counter()
    started_at = time.monotonic()
    interrupted = False
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency)
    futures: dict[concurrent.futures.Future, str] = {}
    exhausted = False

    def submit_url(item_url: str) -> None:
        nonlocal submitted
        futures[executor.submit(scan_url, item_url, args)] = item_url
        submitted += 1

    try:
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
                        "record_type": "result",
                        "url": url,
                        "status": "error",
                        "baseline": None,
                        "probes": [],
                        "observations": [],
                        "signals": [],
                        "filtered_signals": 0,
                        "duplicate_signals": 0,
                        "errors": [
                            {
                                "error_type": "scan_worker_error",
                                "message": f"{type(exc).__name__}: {exc}",
                            }
                        ],
                        "coverage": [],
                    }
                writer.append_result(item)
                completed += 1
                statuses[item["status"]] += 1
                total_signals += len(item["signals"])
                filtered_signals += int(item.get("filtered_signals", 0))
                if not args.quiet and args.progress_every and completed % args.progress_every == 0:
                    emit_progress(
                        completed,
                        submitted,
                        started_at,
                        statuses,
                        total_signals,
                        filtered_signals,
                    )
    except KeyboardInterrupt:
        interrupted = True
        for future in futures:
            future.cancel()
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    metadata["url_count"] = submitted
    payload = writer.finalize()
    print_console_summary(payload, out_dir, args.json)
    if interrupted:
        return 130
    return 0 if payload["scanned"] else 1


def main() -> int:
    return main_from_args()
