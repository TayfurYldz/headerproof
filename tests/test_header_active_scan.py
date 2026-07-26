from __future__ import annotations

import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import header_active_scan  # noqa: E402


class ScannerFixtureHandler(BaseHTTPRequestHandler):
    poisoned: dict[str, str] = {}

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send_common_headers(self) -> None:
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("ETag", '"scanner-test"')
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


def test_header_active_scan_cli_only_accepts_input_and_concurrency(tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "urls.txt"
    input_file.write_text("https://example.com/\n")

    ok = header_active_scan.parse_cli_args(["-i", str(input_file), "--concurrency", "2"])
    assert ok.input == str(input_file)
    assert ok.concurrency == 2

    try:
        header_active_scan.parse_cli_args(["-i", str(input_file), "--profile", "balanced"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 2
        assert "unrecognized arguments" in captured.err
    else:
        raise AssertionError("extra CLI options must be rejected")


def test_header_active_scan_writes_verification_plan(tmp_path: Path) -> None:
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
    )

    plan = (tmp_path / "verification-plan.md").read_text()
    assert "## CORS" in plan
    assert "## CSRF" in plan
    assert "## Cache Poisoning" in plan
    assert "Report Gate:" in plan


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
