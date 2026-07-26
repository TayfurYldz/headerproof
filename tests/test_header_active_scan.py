from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402


def make_snapshot(
    headers: dict[str, str],
    body: str = "",
    status: int = 200,
    request_headers: dict[str, str] | None = None,
) -> header_active_scan.HttpSnapshot:
    return header_active_scan.HttpSnapshot(
        "GET",
        "http://example.test/demo",
        request_headers or {},
        status=status,
        headers={name.lower(): [value] for name, value in headers.items()},
        body_sample=body,
        body_len=len(body),
    )


class ScannerFixtureHandler(BaseHTTPRequestHandler):
    poisoned: dict[str, str] = {}

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send_common_headers(self) -> None:
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"scanner-test"')
        self.send_header("Age", "5")
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
            ScannerFixtureHandler.poisoned[self.path] = canary
            reflected.append(f"header-reflect={canary}")
        elif self.path in ScannerFixtureHandler.poisoned:
            reflected.append(f"cached-reflect={ScannerFixtureHandler.poisoned[self.path]}")

        if "pa_reflect" in query:
            reflected.append(f"param-reflect={query['pa_reflect'][0]}")

        crlf_value = query.get("pa_crlf", [""])[0]
        crlf_match = re.search(r"X-PA-Injected:\s*(pa-scan-[a-f0-9]+)", crlf_value)

        self.send_response(200)
        self._send_common_headers()
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
        args.min_certainty = 0
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
        assert "cache_poisoning_confirmed_on_cache_buster_url" in signal_types
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
    assert args.min_certainty == 95
    assert args.min_alert_confidence == "medium"
    assert args.no_live_alerts is False


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

        assert "CONFIRMED FINDING" in captured.err
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
        assert confirmed_signal["certainty"]["score"] >= 95
        assert confirmed_signal["certainty"]["reportability"] == "report_ready"
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

        assert result["status"] in {"scanned", "partial_timeout"}
        assert result["time_budget"]["elapsed_ms"] < 900
        assert isinstance(result["errors"], list)
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


def test_duplicate_report_ready_signal_types_are_suppressed(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/demo"
        input_file = tmp_path / "urls.txt"
        input_file.write_text(url + "\n")
        args = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "1", "--profile", "thorough"])
        args.no_live_alerts = True

        result = header_active_scan.scan_url(url, args)
        cache_confirmed = [
            signal for signal in result["signals"] if signal["type"] == "cache_poisoning_confirmed_on_cache_buster_url"
        ]

        assert len(cache_confirmed) == 1
        assert result["duplicate_signals"] >= 1
    finally:
        server.shutdown()
        server.server_close()


def test_crlf_confirmation_requires_exact_canary_header_value() -> None:
    canary = "pa-scan-deadbeef"
    ambient_header = make_snapshot({"X-PA-Injected": "static-debug-value"})

    assert header_active_scan.analyze_crlf_probe(canary, ambient_header, save_body=False) == []

    reflected_but_not_exact = make_snapshot({"X-PA-Injected": f"prefix-{canary}"})
    weak_signal = header_active_scan.analyze_crlf_probe(canary, reflected_but_not_exact, save_body=False)[0]
    assert weak_signal["evidence"]["injected_header_seen"] is False
    assert weak_signal["certainty"]["reportability"] != "report_ready"

    exact_header = make_snapshot({"X-PA-Injected": canary})
    confirmed_signal = header_active_scan.analyze_crlf_probe(canary, exact_header, save_body=False)[0]
    assert confirmed_signal["evidence"]["injected_header_seen"] is True
    assert confirmed_signal["certainty"]["score"] >= 95
    assert confirmed_signal["certainty"]["reportability"] == "report_ready"


def test_cache_confirmation_requires_shared_cache_marker_for_report_ready() -> None:
    canary = "pa-scan-cafebabe"
    poison = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"poison={canary}",
        request_headers={"X-Forwarded-Host": canary},
    )
    clean_without_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "ETag": '"weak-proof"'},
        body=f"cached={canary}",
    )

    weak_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        poison,
        clean_without_hit,
        save_body=False,
    )
    weak_confirmed = next(
        signal for signal in weak_signals if signal["type"] == "cache_poisoning_confirmed_on_cache_buster_url"
    )
    assert weak_confirmed["evidence"]["shared_cache_confirmed"] is False
    assert weak_confirmed["certainty"]["score"] < 95
    assert weak_confirmed["certainty"]["reportability"] != "report_ready"

    clean_with_hit = make_snapshot(
        {"Cache-Control": "public, max-age=120", "Age": "7", "X-Cache": "HIT"},
        body=f"cached={canary}",
    )
    strong_signals = header_active_scan.analyze_header_probe(
        "X-Forwarded-Host",
        canary,
        poison,
        clean_with_hit,
        save_body=False,
    )
    strong_confirmed = next(
        signal for signal in strong_signals if signal["type"] == "cache_poisoning_confirmed_on_cache_buster_url"
    )
    assert strong_confirmed["evidence"]["shared_cache_confirmed"] is True
    assert strong_confirmed["certainty"]["score"] >= 95
    assert strong_confirmed["certainty"]["reportability"] == "report_ready"


def test_install_scripts_are_executable_and_valid_shell() -> None:
    for script in ("install.sh", "uninstall.sh"):
        path = ROOT / script
        assert path.exists()
        assert path.stat().st_mode & 0o111
        subprocess.run(["sh", "-n", str(path)], check=True)
