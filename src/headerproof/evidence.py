from __future__ import annotations

from typing import Any

from .constants import CONFIDENCE_ORDER, SCHEMA_VERSION, SEVERITY_ORDER, SUPPRESSED_BY_STRICT
from .models import EvidenceAssessment, EvidenceState, HttpSnapshot, TechnicalGate
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
        "record_type": "finding",
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
    signal["submission_status"] = "manual_validation_required"
    return signal


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


def assess_signal(signal: dict[str, Any]) -> EvidenceAssessment:
    signal_type = signal.get("type", "")
    evidence = signal.get("evidence", {})
    status = response_status_from_signal(signal)
    state: EvidenceState = "observed"
    technical_gate: TechnicalGate = "failed"
    reasons: list[str] = []
    missing: list[str] = []
    gate_checks: dict[str, bool] = {
        "response_recorded": status is not None,
        "transport_succeeded": status is not None,
    }

    if status is not None:
        reasons.append(f"HTTP {status} response was recorded")
    else:
        missing.append("probe response was not recorded")

    if signal_type == "cors_arbitrary_origin_with_credentials":
        reasons.extend(["exact Origin reflected", "Access-Control-Allow-Credentials is true"])
        gate_checks["exact_origin_reflected"] = True
        gate_checks["credentials_enabled"] = True
        missing.append("authenticated sensitive body read is not proven by header scan")
    elif signal_type == "cors_arbitrary_origin_reflection":
        reasons.append("exact Origin reflected in ACAO")
        gate_checks["exact_origin_reflected"] = True
        missing.append("credentials or sensitive readable data not proven")
    elif signal_type == "cors_wildcard_origin":
        reasons.append("wildcard ACAO observed")
        gate_checks["wildcard_origin_observed"] = True
        missing.append("wildcard CORS alone is normally not reportable")
    elif signal_type == "cors_cache_poisoning_candidate":
        reasons.extend(["reflected Origin on cacheable response", "Vary: Origin missing"])
        gate_checks["cache_candidate"] = True
        missing.append("second-client poisoned response not proven")
    elif signal_type == "csrf_cookie_samesite_missing":
        reasons.append("SameSite missing on Set-Cookie")
        gate_checks["likely_auth_cookie"] = bool(evidence.get("likely_auth_cookie"))
        missing.append("no cross-site state-changing request or read-back proof")
    elif signal_type == "csrf_cookie_cross_site_auth":
        reasons.append("likely auth cookie permits cross-site delivery")
        gate_checks["likely_auth_cookie"] = True
        missing.append("CSRF token/origin enforcement and state change not tested")
    elif signal_type == "csrf_cookie_auth_unsafe_methods_exposed":
        reasons.extend(["likely auth cookie present", "unsafe methods advertised"])
        gate_checks["unsafe_methods_advertised"] = True
        missing.append("browser-delivered exploit and separate read-back not proven")
    elif signal_type == "cookie_samesite_none_without_secure":
        reasons.append("cookie attribute hardening issue")
        gate_checks["cookie_attribute_observed"] = True
        missing.append("no exploitable session or CSRF impact proven")
    elif signal_type == "header_poisoning_candidate":
        reasons.append("canary reached security-relevant response header")
        gate_checks["security_header_reflection"] = True
        missing.append("victim-observable impact not independently proven")
    elif signal_type == "header_reflection_candidate":
        reasons.append("canary reached response header")
        gate_checks["header_reflection"] = True
        missing.append("plain reflection does not prove header control or splitting")
    elif signal_type == "header_based_content_spoofing":
        reasons.append("header canary reached textual response body")
        gate_checks["body_reflection"] = True
        missing.append("trusted victim-visible spoofing or cache impact not proven")
    elif signal_type == "unkeyed_header_cache_poisoning_candidate":
        reasons.extend(["header canary reflected", "response has cache indicators"])
        gate_checks["cache_candidate"] = True
        missing.append("clean second-client cached response not proven")
    elif signal_type in {
        "cache_poisoning_cross_request_reproduction",
        "cache_poisoning_shared_cache_confirmed",
    }:
        state = "reproduced"
        required_checks = evidence.get("state_machine_checks", {})
        if isinstance(required_checks, dict):
            gate_checks.update({str(key): bool(value) for key, value in required_checks.items()})
        if evidence.get("shared_cache_confirmed"):
            state = "cross_request_confirmed"
            technical_gate = "passed"
            reasons.extend(
                [
                    "poison request contained canary",
                    "clean follow-up response contained canary",
                    "all four cache-state requests completed in isolated client contexts",
                    "clean victim response included shared-cache progression evidence",
                ]
            )
            missing.append("real victim impact remains unverified; validate on an authorized low-traffic path")
        else:
            reasons.extend(["poison request contained canary", "clean follow-up response contained canary"])
            missing.append("the complete shared-cache state-machine gate did not pass")
    elif signal_type == "query_parameter_content_reflection":
        reasons.append("query canary reflected in textual body")
        gate_checks["body_reflection"] = True
        missing.append("plain reflection lacks trusted-context, cache, or script impact")
    elif signal_type == "query_parameter_header_reflection":
        reasons.append("query canary reached response header")
        gate_checks["header_reflection"] = True
        missing.append("arbitrary header setting or response splitting not proven")
    elif signal_type == "response_splitting_crlf_candidate":
        exact_header = bool(evidence.get("injected_header_seen"))
        gate_checks["exact_canary_parsed_as_header"] = exact_header
        if exact_header and status is not None:
            state = "reproduced"
            technical_gate = "passed"
            reasons.append("CRLF probe produced a parsed response header")
            missing.append("real victim impact remains unverified")
        else:
            reasons.append("CRLF canary reflected but parsed injected header not observed")
            missing.append("parsed arbitrary header not proven")

    return {
        "state": state,
        "technical_gate": technical_gate,
        "impact": "unverified",
        "reasons": reasons,
        "missing_proof": missing,
        "gate_checks": gate_checks,
    }


def apply_detection_assessment(signal: dict[str, Any]) -> None:
    signal["assessment"] = assess_signal(signal)
    signal["verification_plan"] = verification_template(signal.get("type", ""))


def signal_passes_fp_filter(signal: dict[str, Any], fp_mode: str) -> bool:
    if fp_mode == "all":
        return True

    signal_type = signal.get("type", "")
    evidence = signal.get("evidence", {})
    severity_level = SEVERITY_ORDER.get(signal.get("severity", "info"), 0)
    confidence_level = CONFIDENCE_ORDER.get(signal.get("confidence", "low"), 0)
    assessment = signal.get("assessment", {})

    if fp_mode == "strict" and assessment.get("technical_gate") != "passed":
        return False
    if fp_mode == "balanced" and assessment.get("state") == "observed":
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
        if severity_level <= SEVERITY_ORDER["low"]:
            return False
        if confidence_level < CONFIDENCE_ORDER["medium"]:
            return False

    return True
