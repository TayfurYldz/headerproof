from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402


def make_snapshot(
    headers: dict[str, str],
    body: str = "",
    status: int = 200,
    request_headers: dict[str, str] | None = None,
    request_url: str = "http://example.test/demo",
    client_context: str = "test-client",
    error: str = "",
) -> header_active_scan.HttpSnapshot:
    return header_active_scan.HttpSnapshot(
        "GET",
        request_url,
        request_headers or {},
        status=status,
        headers={name.lower(): [value] for name, value in headers.items()},
        body_sample=body,
        body_len=len(body),
        body_sample_len=len(body),
        body_sha256=hashlib.sha256(body.encode()).hexdigest(),
        client_context=client_context,
        error=error,
    )


class ScannerFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send_common_headers(self, cache_status: str = "MISS", age: str = "0") -> None:
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"scanner-test"')
        self.send_header("X-Cache", cache_status)
        self.send_header("Age", age)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_common_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/slow":
            time.sleep(0.2)
        query = parse_qs(parsed.query)
        canary = self._canary_from_headers()
        reflected = []
        if canary:
            reflected.append(f"header-reflect={canary}")

        if "pa_reflect" in query:
            reflected.append(f"param-reflect={query['pa_reflect'][0]}")

        crlf_value = query.get("pa_crlf", [""])[0]
        crlf_match = re.search(r"X-PA-Injected:\s*(pa-scan-[a-f0-9]+)", crlf_value)

        self.send_response(200)
        self._send_common_headers(cache_status="MISS", age="0")
        if canary:
            self.send_header("X-Reflected-Header", canary)
        if crlf_match:
            self.send_header("X-PA-Injected", crlf_match.group(1))
        self.end_headers()
        body = "<html><body>" + " ".join(reflected) + "</body></html>"
        self.wfile.write(body.encode())

    def _canary_from_headers(self) -> str:
        for value in self.headers.values():
            match = re.search(r"(pa-scan-[a-f0-9]+)", value)
            if match:
                return match.group(1)
        return ""


class CacheOriginHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        canary = ""
        for value in self.headers.values():
            match = re.search(r"(pa-scan-[a-f0-9]+)", value)
            if match:
                canary = match.group(1)
                break
        body = f"origin-response {canary}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"proxy-fixture"')
        if canary:
            self.send_header("X-Origin-Reflection", canary)
        self.end_headers()
        self.wfile.write(body)


class SharedCacheProxyHandler(BaseHTTPRequestHandler):
    origin_port = 0
    cache: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}
    lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        bypass = "no-cache" in self.headers.get("Cache-Control", "").lower()
        with self.lock:
            cached = self.cache.get(self.path) if not bypass else None
        if cached is not None:
            status, headers, body = cached
            self._send_cached(status, headers, body, "HIT", "7")
            return

        upstream_headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in {"host", "connection", "cache-control", "pragma"}
        }
        upstream = request.Request(
            f"http://127.0.0.1:{self.origin_port}{self.path}",
            headers=upstream_headers,
        )
        with request.urlopen(upstream, timeout=1.0) as response:
            status = response.status
            headers = [
                (name, value)
                for name, value in response.headers.items()
                if name.lower() not in {"server", "date", "content-length", "x-cache", "age"}
            ]
            body = response.read()
        if not bypass:
            with self.lock:
                self.cache[self.path] = (status, headers, body)
        self._send_cached(status, headers, body, "BYPASS" if bypass else "MISS", "0")

    def _send_cached(
        self,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
        cache_status: str,
        age: str,
    ) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("X-Cache", cache_status)
        self.send_header("Age", age)
        self.end_headers()
        self.wfile.write(body)


class ConcurrencyFixtureHandler(BaseHTTPRequestHandler):
    active = 0
    max_active = 0
    lock = threading.Lock()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_OPTIONS(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        with ConcurrencyFixtureHandler.lock:
            ConcurrencyFixtureHandler.active += 1
            ConcurrencyFixtureHandler.max_active = max(
                ConcurrencyFixtureHandler.max_active,
                ConcurrencyFixtureHandler.active,
            )
        try:
            time.sleep(0.03)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"ok")
        finally:
            with ConcurrencyFixtureHandler.lock:
                ConcurrencyFixtureHandler.active -= 1


class FixedBodyHandler(BaseHTTPRequestHandler):
    body = b"0123456789" * 10

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)


def test_header_active_scan_detects_core_signals(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "1"])
        args.fp_mode = "all"
        args.no_live_alerts = True
        args.no_preflight = False
        args.no_cache_confirm = False
        args.origin_mode = "standard"
        args.header_probe_limit = 0

        result = header_active_scan.scan_url(url, args)
        signal_types = {signal["type"] for signal in result["signals"]}

        assert result["status"] == "scanned"
        assert "cors_arbitrary_origin_with_credentials" in signal_types
        assert "header_reflection_candidate" in signal_types
        assert "header_based_content_spoofing" in signal_types
        assert "cache_poisoning_shared_cache_confirmed" not in signal_types
        assert "query_parameter_content_reflection" in signal_types
        assert "response_splitting_crlf_candidate" in signal_types
    finally:
        server.shutdown()
        server.server_close()


def test_header_active_scan_fast_defaults(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")
    args = header_active_scan.parse_cli_args(["-i", str(input_file)])

    assert args.url_timeout == 9.0
    assert args.timeout == 2.0
    assert args.delay == 0.0
    assert args.concurrency == 16
    assert args.per_url_concurrency == 6
    assert args.max_body == 8192
    assert args.origin_mode == "single"
    assert args.header_probe_limit == 3
    assert args.no_preflight is True
    assert args.no_cache_confirm is False
    assert args.fp_mode == "strict"
    assert args.min_alert_confidence == "medium"
    assert args.no_live_alerts is False


def test_header_active_scan_version(capsys) -> None:
    try:
        header_active_scan.parse_cli_args(["--version"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 0
        assert "HeaderProof" in captured.out
    else:
        raise AssertionError("--version must exit cleanly")


def test_header_active_scan_missing_input_is_clean_error(capsys) -> None:
    rc = header_active_scan.main_from_args(["-i", "/path/to/urls.txt"])

    captured = capsys.readouterr()
    assert rc == 2
    assert "input URL file not found" in captured.err
    assert "Traceback" not in captured.err


def test_header_active_scan_cli_accepts_safe_advanced_options(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")

    ok = header_active_scan.parse_cli_args(
        [
            "-i",
            str(input_file),
            "--concurrency",
            "2",
            "--profile",
            "balanced",
            "--timeout",
            "1.5",
            "--origin",
            "https://attacker.example",
            "--header",
            "X-Test-Probe",
            "--out-dir",
            str(tmp_path / "out"),
            "--json",
        ]
    )
    assert ok.input == str(input_file)
    assert ok.concurrency == 2
    assert ok.profile == "balanced"
    assert ok.timeout == 1.5
    assert ok.origin == ["https://attacker.example"]
    assert ok.header == ["X-Test-Probe"]
    assert ok.out_dir == str(tmp_path / "out")
    assert ok.json is True
    assert ok.quiet is True
    assert ok.no_live_alerts is True


def test_header_active_scan_rejects_invalid_custom_header(tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")

    try:
        header_active_scan.parse_cli_args(["-i", str(input_file), "--header", "Bad Header"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 2
        assert "invalid HTTP header name" in captured.err
    else:
        raise AssertionError("invalid header names must be rejected")


def test_load_urls_handles_jsonl_invalid_urls_duplicates_and_limits(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text(
        "\n".join(
            [
                "# comment",
                "example.com",
                '{"url":"https://api.example.com/v1/me"}',
                '{"final_url":"http://example.net/path?q=1#frag"}',
                '{"url":""}',
                '{"not_json"',
                "ftp://example.org/file",
                "example.com",
            ]
        )
        + "\n"
    )

    assert header_active_scan.load_urls(input_file) == [
        "https://example.com/",
        "https://api.example.com/v1/me",
        "http://example.net/path?q=1",
    ]
    assert header_active_scan.load_urls(input_file, max_urls=2) == [
        "https://example.com/",
        "https://api.example.com/v1/me",
    ]


def test_header_active_scan_writes_verification_plan(tmp_path: Path) -> None:
    metadata = {
        "tool": "HeaderProof",
        "version": "test",
        "git_commit": "abc123",
        "command": ["headerproof", "-i", "urls.txt"],
        "config": {"profile": "fast"},
    }
    header_active_scan.write_outputs(
        [
            {
                "url": "https://example.com/",
                "status": "scanned",
                "signals": [],
                "filtered_signals": 0,
            }
        ],
        tmp_path,
        metadata,
    )

    saved_metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert saved_metadata["tool"] == "HeaderProof"
    assert saved_metadata["version"] == "test"
    assert saved_metadata["git_commit"] == "abc123"
    assert saved_metadata["config"]["profile"] == "fast"
    plan = (tmp_path / "verification-plan.md").read_text()
    assert "## CORS" in plan
    assert "## CSRF" in plan
    assert "## Cache Poisoning" in plan
    assert "Report Gate:" in plan
    summary = (tmp_path / "summary.md").read_text()
    assert "## Run Metadata" in summary
    assert "- git_commit: abc123" in summary
    assert (tmp_path / "observations.jsonl").exists()
    assert (tmp_path / "probes.jsonl").exists()


def test_header_active_scan_live_alerts_and_strict_filtering(tmp_path: Path, capsys) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "1"])
        args.no_color = True

        result = header_active_scan.scan_url(url, args)
        captured = capsys.readouterr()
        signal_types = {signal["type"] for signal in result["signals"]}

        assert "VERIFIED TECHNICAL SIGNAL" in captured.err
        assert "response_splitting_crlf_candidate" in captured.err
        assert "Evidence" in captured.err
        assert "FP guard:" in captured.err
        assert "Still verify before reporting" in captured.err
        assert "Next validation" in captured.err
        assert "response_splitting_crlf_candidate" in signal_types
        assert "cors_arbitrary_origin_with_credentials" not in signal_types
        assert "query_parameter_content_reflection" not in signal_types
        assert result["filtered_signals"] >= 1
        confirmed_signal = next(signal for signal in result["signals"] if signal["type"] == "response_splitting_crlf_candidate")
        assert confirmed_signal["assessment"]["state"] == "reproduced"
        assert confirmed_signal["assessment"]["technical_gate"] == "passed"
        assert confirmed_signal["assessment"]["impact"] == "unverified"
        assert "verification_plan" in confirmed_signal
    finally:
        server.shutdown()
        server.server_close()


def test_main_json_out_dir_writes_metadata_and_machine_summary(tmp_path: Path, capsys) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        out_dir = tmp_path / "evidence-out"
        input_file.write_text(url + "\n")

        rc = header_active_scan.main_from_args(
            ["-i", str(input_file), "--concurrency", "1", "--json", "--out-dir", str(out_dir)]
        )
        captured = capsys.readouterr()
        summary = json.loads(captured.out)
        metadata = json.loads((out_dir / "metadata.json").read_text())

        assert rc == 0
        assert captured.err == ""
        assert summary["urls"] == 1
        assert summary["out_dir"] == str(out_dir)
        assert metadata["tool"] == "HeaderProof"
        assert metadata["config"]["profile"] == "fast"
        assert metadata["config"]["concurrency"] == 1
        assert metadata["command"][0] == "headerproof"
        observations = (out_dir / "observations.jsonl").read_text().splitlines()
        probes = [json.loads(line) for line in (out_dir / "probes.jsonl").read_text().splitlines()]
        assert observations
        assert probes
        assert all(probe["exchange"] is not None for probe in probes if probe["status"] == "completed")
        assert all(probe["exchange"]["response"]["status"] == 200 for probe in probes if probe["role"] != "preflight")
        assert summary["error"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_scan_timeout_keeps_batch_moving(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/slow"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "1", "--timeout", "0.05"])
        args.no_live_alerts = True
        args.url_timeout = 0.12

        result = header_active_scan.scan_url(url, args)

        assert result["status"] in {"error", "partial_timeout"}
        assert result["time_budget"]["elapsed_ms"] < 900
        assert isinstance(result["errors"], list)
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_baseline_is_error_not_scanned(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://127.0.0.1:1/\n")
    args = header_active_scan.parse_cli_args(["-i", str(input_file), "--timeout", "0.05"])
    args.no_live_alerts = True

    result = header_active_scan.scan_url("http://127.0.0.1:1/", args)

    assert result["status"] == "error"
    assert result["errors"]
    assert result["probes"]
    assert result["signals"] == []


def test_transport_records_full_body_hash_and_explicit_truncation() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixedBodyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/body"
        client = header_active_scan.HttpClient(1.0, 10, False, 0.0)
        snapshot = client.fetch(url, client_context="body-test")
        exchange = header_active_scan.snapshot_summary(snapshot, save_body=True)
        response = exchange["response"]

        assert response["body_len"] == 100
        assert response["body_sample_len"] == 10
        assert response["body_truncated"] is True
        assert response["body_sha256"] == hashlib.sha256(FixedBodyHandler.body).hexdigest()
        assert response["body_sha256_scope"] == "full_response"
        assert response["body_sample"] == "0123456789"
    finally:
        server.shutdown()
        server.server_close()


def test_probe_errors_make_scan_partial_and_are_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    call_lock = threading.Lock()

    def fake_fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        client_context: str = "default",
    ) -> header_active_scan.HttpSnapshot:
        nonlocal calls
        with call_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            return make_snapshot(
                {"Content-Type": "text/plain", "Cache-Control": "no-store"},
                body="baseline",
                request_url=url,
                request_headers=headers,
                client_context=client_context,
            )
        return make_snapshot(
            {},
            status=0,
            request_url=url,
            request_headers=headers,
            client_context=client_context,
            error="ConnectionError: fixture failure",
        )

    monkeypatch.setattr(header_active_scan.HttpClient, "fetch", fake_fetch)
    input_file = tmp_path / "urls.txt"
    input_file.write_text("http://fixture.invalid/\n")
    args = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "2"])
    args.no_live_alerts = True

    result = header_active_scan.scan_url("http://fixture.invalid/", args)

    assert result["status"] == "partial_error"
    assert result["errors"]
    failed_probes = [probe for probe in result["probes"] if probe["status"] == "error"]
    assert failed_probes
    assert all(probe["exchange"]["response"]["error"] for probe in failed_probes)
    assert any(item["state"] == "error" for item in result["coverage"] if item["kind"] == "probe")


def test_all_failed_batch_returns_nonzero_and_reports_error_count(tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "urls.txt"
    out_dir = tmp_path / "failed-run"
    input_file.write_text("http://127.0.0.1:1/\n")

    rc = header_active_scan.main_from_args(
        [
            "-i",
            str(input_file),
            "--concurrency",
            "1",
            "--timeout",
            "0.05",
            "--json",
            "--out-dir",
            str(out_dir),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["scanned"] == 0
    assert payload["error"] == 1
    assert payload["error_events"] >= 1
    assert (out_dir / "errors.jsonl").read_text().splitlines()


def test_output_records_match_published_json_schema(tmp_path: Path, capsys) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        input_file = tmp_path / "urls.txt"
        out_dir = tmp_path / "schema-run"
        input_file.write_text(f"http://127.0.0.1:{server.server_port}/demo\n")
        rc = header_active_scan.main_from_args(
            ["-i", str(input_file), "--concurrency", "1", "--quiet", "--out-dir", str(out_dir)]
        )
        capsys.readouterr()
        schema = json.loads((ROOT / "schemas" / "evidence-v1.2.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        jsonschema.Draft202012Validator.check_schema(schema)

        assert rc == 0
        for filename in (
            "results.jsonl",
            "signals.jsonl",
            "observations.jsonl",
            "probes.jsonl",
            "coverage.jsonl",
            "errors.jsonl",
        ):
            for line in (out_dir / filename).read_text().splitlines():
                validator.validate(json.loads(line))
    finally:
        server.shutdown()
        server.server_close()


def test_cors_vary_origin_suppresses_cache_poisoning_candidate() -> None:
    origin = "https://pa-scan-vary.invalid"
    snap = make_snapshot(
        {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Cache-Control": "public, max-age=120",
            "Vary": "Accept-Encoding, Origin",
        }
    )

    signal_types = {signal["type"] for signal in header_active_scan.analyze_cors_probe(origin, snap, save_body=False)}

    assert "cors_arbitrary_origin_with_credentials" in signal_types
    assert "cors_cache_poisoning_candidate" not in signal_types


def test_large_input_list_deduplicates_without_expanding_scope(tmp_path: Path) -> None:
    input_file = tmp_path / "urls.txt"
    lines = [f"https://example.com/path-{index % 25}" for index in range(1000)]
    input_file.write_text("\n".join(lines) + "\n")

    urls = header_active_scan.load_urls(input_file)

    assert len(urls) == 25
    assert urls[0] == "https://example.com/path-0"


def test_main_respects_global_http_concurrency(tmp_path: Path, capsys) -> None:
    ConcurrencyFixtureHandler.active = 0
    ConcurrencyFixtureHandler.max_active = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), ConcurrencyFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        input_file = tmp_path / "urls.txt"
        out_dir = tmp_path / "out"
        urls = [f"http://127.0.0.1:{server.server_port}/demo?u={index}" for index in range(6)]
        input_file.write_text("\n".join(urls) + "\n")

        rc = header_active_scan.main_from_args(
            ["-i", str(input_file), "--concurrency", "2", "--quiet", "--out-dir", str(out_dir)]
        )
        capsys.readouterr()

        assert rc == 0
        assert ConcurrencyFixtureHandler.max_active <= 2
        assert (out_dir / "probes.jsonl").exists()
    finally:
        server.shutdown()
        server.server_close()


def test_independent_header_findings_are_not_hidden_as_duplicates(tmp_path: Path) -> None:
    SharedCacheProxyHandler.cache = {}
    origin = ThreadingHTTPServer(("127.0.0.1", 0), CacheOriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    SharedCacheProxyHandler.origin_port = origin.server_port
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), SharedCacheProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        url = f"http://127.0.0.1:{proxy.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(
            ["-i", str(input_file), "--concurrency", "1", "--profile", "thorough"]
        )
        args.no_live_alerts = True
        args.header_probe_limit = 2

        result = header_active_scan.scan_url(url, args)
        cache_confirmed = [
            signal for signal in result["signals"] if signal["type"] == "cache_poisoning_shared_cache_confirmed"
        ]

        probe_headers = {signal["evidence"]["probe_header"] for signal in cache_confirmed}
        assert len(probe_headers) == len(cache_confirmed)
        assert len(cache_confirmed) >= 2
        assert result["duplicate_signals"] == 0
    finally:
        proxy.shutdown()
        proxy.server_close()
        origin.shutdown()
        origin.server_close()


def test_crlf_confirmation_requires_exact_canary_header_value() -> None:
    canary = "pa-scan-deadbeef"
    ambient_header = make_snapshot({"X-PA-Injected": "static-debug-value"})

    assert header_active_scan.analyze_crlf_probe(canary, ambient_header, save_body=False) == []

    reflected_but_not_exact = make_snapshot({"X-PA-Injected": f"prefix-{canary}"})
    weak_signal = header_active_scan.analyze_crlf_probe(canary, reflected_but_not_exact, save_body=False)[0]
    assert weak_signal["evidence"]["injected_header_seen"] is False
    assert weak_signal["assessment"]["technical_gate"] == "failed"

    exact_header = make_snapshot({"X-PA-Injected": canary})
    confirmed_signal = header_active_scan.analyze_crlf_probe(canary, exact_header, save_body=False)[0]
    assert confirmed_signal["evidence"]["injected_header_seen"] is True
    assert confirmed_signal["assessment"]["state"] == "reproduced"
    assert confirmed_signal["assessment"]["technical_gate"] == "passed"
    assert confirmed_signal["submission_status"] == "manual_validation_required"


def test_cache_confirmation_requires_complete_state_machine() -> None:
    canary = "pa-scan-cafebabe"
    cache_url = "http://example.test/demo?pa_cb=probe"
    control_url = "http://example.test/demo?pa_cb=probe-control"
    poison = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
        request_url=cache_url,
        client_context="poison",
    )
    clean_before = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"', "Age": "0"},
        body="clean",
        request_url=cache_url,
        client_context="clean-before",
    )
    clean_without_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    fresh_control = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"', "Age": "0"},
        body="clean-control",
        request_url=control_url,
        client_context="fresh-control",
    )

    weak_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-weak",
        clean_before,
        poison,
        clean_without_hit,
        fresh_control,
        save_body=False,
    )
    weak_reproduction = next(
        signal for signal in weak_signals if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )
    assert weak_reproduction["evidence"]["shared_cache_confirmed"] is False
    assert weak_reproduction["assessment"]["technical_gate"] == "failed"

    clean_with_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "7", "X-Cache": "HIT"},
        body=f"cached={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    strong_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-strong",
        clean_before,
        poison,
        clean_with_hit,
        fresh_control,
        save_body=False,
    )
    strong_confirmed = next(
        signal for signal in strong_signals if signal["type"] == "cache_poisoning_shared_cache_confirmed"
    )
    assert strong_confirmed["evidence"]["shared_cache_confirmed"] is True
    assert all(strong_confirmed["evidence"]["state_machine_checks"].values())
    assert strong_confirmed["assessment"]["state"] == "cross_request_confirmed"
    assert strong_confirmed["assessment"]["technical_gate"] == "passed"

    missing_control = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-missing-control",
        clean_before,
        poison,
        clean_with_hit,
        None,
        save_body=False,
    )
    missing_control_signal = next(
        signal for signal in missing_control if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )
    assert missing_control_signal["evidence"]["shared_cache_confirmed"] is False
    assert missing_control_signal["evidence"]["state_machine_checks"]["fresh_control_completed"] is False
    assert missing_control_signal["assessment"]["technical_gate"] == "failed"


def test_cache_confirmation_rejects_origin_side_state_with_static_age() -> None:
    canary = "pa-scan-originstate"
    cache_url = "http://example.test/demo?pa_cb=origin-state"
    control_url = "http://example.test/demo?pa_cb=origin-state-control"
    clean_before = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body="clean",
        request_url=cache_url,
        client_context="clean-before",
    )
    poison = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
        request_url=cache_url,
        client_context="poison",
    )
    victim = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body=f"origin-memory={canary}",
        request_url=cache_url,
        client_context="victim",
    )
    fresh_control = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "5"},
        body="fresh-clean",
        request_url=control_url,
        client_context="fresh-control",
    )

    signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        "probe-origin-state",
        clean_before,
        poison,
        victim,
        fresh_control,
        save_body=False,
    )
    reproduced = next(
        signal for signal in signals if signal["type"] == "cache_poisoning_cross_request_reproduction"
    )

    assert reproduced["evidence"]["shared_cache_confirmed"] is False
    assert reproduced["assessment"]["technical_gate"] == "failed"


def test_install_scripts_are_executable_and_valid_shell() -> None:
    for script in ("install.sh", "uninstall.sh"):
        path = ROOT / script
        assert path.exists()
        assert path.stat().st_mode & 0o111
        subprocess.run(["sh", "-n", str(path)], check=True)
