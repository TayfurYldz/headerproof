from __future__ import annotations

from typing import Any

from .constants import (
    CONFIDENCE_ORDER,
    REPORT_READY_THRESHOLD,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    SUPPRESSED_BY_STRICT,
)
from .models import HttpSnapshot
from .transport import snapshot_summary

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
        "schema_version": SCHEMA_VERSION,
        "check": check,
        "type": signal_type,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "evidence": evidence,
        "next_step": next_step,
    }
    if snap:
        signal["exchange"] = snapshot_summary(snap, save_body=save_body)
    apply_detection_assessment(signal)
    reportability = signal.get("certainty", {}).get("reportability")
    signal["submission_status"] = "report_ready" if reportability == "report_ready" else "lead_only"
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
        score = 78
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
        score = 64
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
        score = 82
        reasons.append("canary reached security-relevant response header")
        missing.append("victim-observable impact not independently proven")
    elif signal_type == "header_reflection_candidate":
        score = 48
        reasons.append("canary reached response header")
        missing.append("plain reflection does not prove header control or splitting")
    elif signal_type == "header_based_content_spoofing":
        score = 42
        reasons.append("header canary reached textual response body")
        missing.append("trusted victim-visible spoofing or cache impact not proven")
    elif signal_type == "unkeyed_header_cache_poisoning_candidate":
        score = 66
        reasons.extend(["header canary reflected", "response has cache indicators"])
        missing.append("clean second-client cached response not proven")
    elif signal_type == "cache_poisoning_confirmed_on_cache_buster_url":
        if evidence.get("shared_cache_confirmed"):
            score = 97
            reasons.extend(
                [
                    "poison request contained canary",
                    "clean follow-up response contained canary",
                    "clean follow-up response included a shared-cache hit marker",
                ]
            )
            missing.append("repeat from an independent network/client before final report submission")
        else:
            score = 88
            reasons.extend(["poison request contained canary", "clean follow-up response contained canary"])
            missing.append("shared-cache HIT/Age proof was absent; rule out origin-side state before reporting")
    elif signal_type == "query_parameter_content_reflection":
        score = 32
        reasons.append("query canary reflected in textual body")
        missing.append("plain reflection lacks trusted-context, cache, or script impact")
    elif signal_type == "query_parameter_header_reflection":
        score = 58
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
    reportability = (
        "report_ready"
        if score >= REPORT_READY_THRESHOLD
        else "probable_lead"
        if score >= 85
        else "needs_manual_proof"
        if score >= 70
        else "manual_review"
        if score >= 55
        else "suppress_by_default"
    )
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

    if fp_mode == "strict" and signal.get("certainty", {}).get("reportability") != "report_ready":
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
