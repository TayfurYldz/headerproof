from __future__ import annotations

import json
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class SmokeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_OPTIONS(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"headerproof-release-smoke")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="headerproof-release-smoke-") as raw_tmp:
            tmp = Path(raw_tmp)
            input_file = tmp / "urls.txt"
            out_dir = tmp / "evidence"
            input_file.write_text(f"http://127.0.0.1:{server.server_port}/smoke\n")
            completed = subprocess.run(
                [
                    "headerproof",
                    "-i",
                    str(input_file),
                    "--concurrency",
                    "1",
                    "--quiet",
                    "--out-dir",
                    str(out_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"installed scan failed: {completed.stderr or completed.stdout}")
            result = json.loads((out_dir / "results.jsonl").read_text().splitlines()[0])
            if result["status"] != "scanned" or not result["probes"]:
                raise RuntimeError("installed scan did not produce a completed result with probes")
            for probe in result["probes"]:
                if probe["status"] == "completed" and not isinstance(probe["exchange"], dict):
                    raise RuntimeError("installed scan wrote a null completed exchange")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
