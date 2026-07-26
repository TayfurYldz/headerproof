from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import PRODUCT_NAME, SEVERITY_ORDER, VERSION
from .evidence import verification_template
from .file_safety import atomic_write_text
from .metadata import current_git_commit
from .ui import shorten, ui_box, ui_kv

def write_outputs(results: list[dict[str, Any]], out_dir: Path, metadata: dict[str, Any] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata = metadata or {
        "tool": PRODUCT_NAME,
        "version": VERSION,
        "git_commit": current_git_commit(),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "config": {},
    }
    atomic_write_text(out_dir / "metadata.json", json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    results_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in results) + "\n"
    atomic_write_text(out_dir / "results.jsonl", results_jsonl)

    flat_signals: list[dict[str, Any]] = []
    for item in results:
        for signal in item["signals"]:
            flat = {"url": item["url"], **signal}
            flat_signals.append(flat)
    signals_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in flat_signals)
    atomic_write_text(out_dir / "signals.jsonl", signals_jsonl + ("\n" if signals_jsonl else ""))

    flat_observations: list[dict[str, Any]] = []
    flat_probes: list[dict[str, Any]] = []
    for item in results:
        for observation in item.get("observations", []):
            flat_observations.append(observation)
        for probe in item.get("probes", []):
            flat_probes.append({"url": item["url"], **probe})
    observations_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in flat_observations)
    probes_jsonl = "\n".join(json.dumps(item, sort_keys=True) for item in flat_probes)
    atomic_write_text(out_dir / "observations.jsonl", observations_jsonl + ("\n" if observations_jsonl else ""))
    atomic_write_text(out_dir / "probes.jsonl", probes_jsonl + ("\n" if probes_jsonl else ""))

    lines = [
        "# HeaderProof Scan Summary",
        "",
        "## Run Metadata",
        "",
        f"- generated: {datetime.now().isoformat(timespec='seconds')}",
        f"- tool: {metadata.get('tool', PRODUCT_NAME)} {metadata.get('version', VERSION)}",
        f"- git_commit: {metadata.get('git_commit') or 'unknown'}",
        f"- command: {' '.join(str(item) for item in metadata.get('command', [])) or 'unknown'}",
        f"- profile: {metadata.get('config', {}).get('profile', 'unknown')}",
        f"- urls: {len(results)}",
        f"- scanned: {sum(1 for item in results if item['status'] == 'scanned')}",
        f"- partial_timeout: {sum(1 for item in results if item['status'] == 'partial_timeout')}",
        f"- confirmed_findings: {len(flat_signals)}",
        f"- observations: {len(flat_observations)}",
        f"- probes: {len(flat_probes)}",
        f"- filtered_signals: {sum(item.get('filtered_signals', 0) for item in results)}",
        f"- duplicate_signals: {sum(item.get('duplicate_signals', 0) for item in results)}",
        "",
        "## Results",
        "",
        "| URL | Status | Confirmed | Top Types |",
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
                    f"evidence_state={certainty.get('level', 'unknown')} rank={certainty.get('score', 0)}/100 "
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
    sorted_flat = sorted(
        flat,
        key=lambda signal: (
            signal.get("certainty", {}).get("score", 0),
            SEVERITY_ORDER.get(signal.get("severity", "info"), 0),
        ),
        reverse=True,
    )
    payload = {
        "urls": len(results),
        "scanned": sum(1 for item in results if item["status"] == "scanned"),
        "partial_timeout": sum(1 for item in results if item["status"] == "partial_timeout"),
        "confirmed_findings": len(flat),
        "filtered_signals": sum(item.get("filtered_signals", 0) for item in results),
        "duplicate_signals": sum(item.get("duplicate_signals", 0) for item in results),
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
        ui_kv("Confirmed", payload["confirmed_findings"]),
        ui_kv("Suppressed", payload["filtered_signals"]),
        ui_kv("Duplicates", payload["duplicate_signals"]),
        ui_kv("Severity", payload["by_severity"] or "none"),
    ]
    if payload["by_certainty"]:
        lines.append(ui_kv("Certainty", ", ".join(f"{name}={count}" for name, count in payload["by_certainty"].items())))
    if payload["by_type"]:
        lines.append(ui_kv("Types", ", ".join(f"{name}={count}" for name, count in payload["by_type"].items())))
    lines.extend(
        [
            ui_kv("Evidence", out_dir),
            ui_kv(
                "Files",
                "metadata.json, results.jsonl, observations.jsonl, probes.jsonl, signals.jsonl, summary.md, verification-plan.md",
            ),
        ]
    )
    if sorted_flat:
        lines.extend(["", "Confirmed findings"])
        for signal in sorted_flat[:5]:
            certainty = signal.get("certainty", {})
            lines.append(
                (
                    f"  {certainty.get('level', 'unknown').upper():<10} rank {certainty.get('score', 0):>3}/100  "
                    f"{signal.get('severity', '').upper():<7} "
                    f"{signal.get('type', '')}  {shorten(signal.get('title', ''), 80)}"
                )
            )
    else:
        lines.extend(["", "No confirmed findings met the report-ready gate."])
    ui_box("SCAN COMPLETE · EVIDENCE-FIRST RESULTS", lines, stream=sys.stdout)
