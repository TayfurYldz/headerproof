from __future__ import annotations

import re
from typing import Any

from .constants import CACHEABLE_STATUSES, LIKELY_AUTH_COOKIE, TEXTUAL_CONTENT, UNSAFE_METHODS
from .evidence import make_signal
from .models import HttpSnapshot


def header_join(snap: HttpSnapshot, name: str) -> str:
    return ", ".join(snap.values(name))


def vary_has(snap: HttpSnapshot, token: str) -> bool:
    vary = header_join(snap, "vary").lower()
    return token.lower() in {part.strip() for part in vary.split(",")}


def cache_indicators(snap: HttpSnapshot) -> list[str]:
    indicators: list[str] = []
    cc = header_join(snap, "cache-control").lower()
    if cc:
        indicators.append(f"cache-control={cc}")
    if "no-store" in cc:
        indicators.append("no-store")
    if "private" in cc:
        indicators.append("private")
    for name in (
        "age",
        "expires",
        "etag",
        "x-cache",
        "x-cache-hits",
        "cache-status",
        "cf-cache-status",
        "cdn-cache-control",
        "surrogate-control",
        "akamai-cache-status",
        "server-timing",
    ):
        value = header_join(snap, name)
        if value:
            indicators.append(f"{name}={value}")
    return indicators


def looks_cacheable(snap: HttpSnapshot) -> tuple[bool, list[str]]:
    indicators = cache_indicators(snap)
    cc = header_join(snap, "cache-control").lower()
    if snap.status not in CACHEABLE_STATUSES:
        return False, indicators
    if "no-store" in cc or "private" in cc:
        return False, indicators
    active = any(
        marker in " ".join(indicators).lower()
        for marker in ("max-age", "s-maxage", "public", "age=", "x-cache", "cf-cache-status", "etag")
    )
    return active, indicators


def shared_cache_hit_markers(indicators: list[str]) -> list[str]:
    markers: list[str] = []
    for indicator in indicators:
        name, _, value = indicator.partition("=")
        name_l = name.lower()
        value_l = value.lower()
        if name_l == "age":
            match = re.search(r"\d+", value_l)
            if match and int(match.group(0)) > 0:
                markers.append(indicator)
        elif name_l == "x-cache-hits":
            match = re.search(r"\d+", value_l)
            if match and int(match.group(0)) > 0:
                markers.append(indicator)
        elif name_l in {"x-cache", "cf-cache-status", "cache-status", "akamai-cache-status", "server-timing"}:
            has_hit = re.search(r"\b(hit|cached|revalidated)\b", value_l)
            has_miss = re.search(r"\b(miss|bypass|dynamic|uncacheable|expired)\b", value_l)
            if has_hit and not has_miss:
                markers.append(indicator)
    return markers


def header_int(snap: HttpSnapshot | None, name: str) -> int:
    if snap is None:
        return 0
    match = re.search(r"\d+", header_join(snap, name))
    return int(match.group(0)) if match else 0


def has_cache_hit_header(snap: HttpSnapshot | None) -> bool:
    if snap is None:
        return False
    indicators = " ".join(shared_cache_hit_markers(cache_indicators(snap))).lower()
    return bool(re.search(r"\b(hit|cached|revalidated)\b", indicators))


def cache_hit_progressed(
    clean_before: HttpSnapshot | None,
    poison: HttpSnapshot | None,
    victim: HttpSnapshot | None,
) -> bool:
    if victim is None:
        return False
    if has_cache_hit_header(victim) and not has_cache_hit_header(clean_before):
        return True
    victim_age = header_int(victim, "age")
    previous_age = max(header_int(clean_before, "age"), header_int(poison, "age"))
    return victim_age > 0 and victim_age > previous_age


def snapshot_completed(snap: HttpSnapshot | None) -> bool:
    return snap is not None and not snap.error and snap.status is not None


def request_contains_canary(snap: HttpSnapshot | None, canary: str) -> bool:
    if snap is None:
        return False
    needle = canary.lower()
    return any(needle in value.lower() for value in snap.request_headers.values())


def is_textual_response(snap: HttpSnapshot) -> bool:
    return bool(TEXTUAL_CONTENT.search(snap.first("content-type")))


def snippet_around(text: str, needle: str, radius: int = 90) -> str:
    lower = text.lower()
    index = lower.find(needle.lower())
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return text[start:end].replace("\r", "\\r").replace("\n", "\\n")


def canary_locations(snap: HttpSnapshot, canary: str) -> list[dict[str, str]]:
    locations: list[dict[str, str]] = []
    needle = canary.lower()
    for name, values in snap.headers.items():
        for value in values:
            if needle in value.lower():
                locations.append(
                    {
                        "where": "response_header",
                        "name": name,
                        "snippet": snippet_around(value, canary),
                    }
                )
    if needle in snap.body_sample.lower():
        locations.append(
            {
                "where": "response_body",
                "name": "body",
                "snippet": snippet_around(snap.body_sample, canary),
            }
        )
    return locations

def parse_methods(*values: str) -> set[str]:
    methods: set[str] = set()
    for value in values:
        for part in re.split(r"[, ]+", value.upper()):
            part = part.strip()
            if part:
                methods.add(part)
    return methods


def parse_cookie(cookie: str) -> dict[str, Any]:
    parts = [part.strip() for part in cookie.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs: dict[str, Any] = {"name": name, "secure": False, "samesite": ""}
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key_l = key.strip().lower()
        if key_l == "secure":
            attrs["secure"] = True
        elif key_l == "samesite":
            attrs["samesite"] = value.strip().lower()
    attrs["likely_auth"] = bool(LIKELY_AUTH_COOKIE.search(name))
    return attrs


def analyze_csrf(baseline: HttpSnapshot, options: HttpSnapshot | None, save_body: bool) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    cookies = baseline.values("set-cookie")
    parsed_cookies = [parse_cookie(cookie) for cookie in cookies]
    for cookie in parsed_cookies:
        if not cookie["samesite"]:
            severity = "medium" if cookie["likely_auth"] else "low"
            signals.append(
                make_signal(
                    "csrf",
                    "csrf_cookie_samesite_missing",
                    severity,
                    "medium",
                    "Set-Cookie lacks SameSite; CSRF risk if this cookie authenticates state-changing requests",
                    {"cookie_name": cookie["name"], "likely_auth_cookie": cookie["likely_auth"]},
                    baseline,
                    "Confirm with a real state-changing action and a cross-site PoC before reporting.",
                    save_body,
                )
            )
        elif cookie["samesite"] == "none" and cookie["likely_auth"]:
            signals.append(
                make_signal(
                    "csrf",
                    "csrf_cookie_cross_site_auth",
                    "medium",
                    "medium",
                    "Likely auth cookie uses SameSite=None; CSRF depends on token/origin enforcement",
                    {
                        "cookie_name": cookie["name"],
                        "secure": cookie["secure"],
                        "samesite": cookie["samesite"],
                    },
                    baseline,
                    "Test token removal/reuse and forged Origin/Referer on an authorized state-changing workflow.",
                    save_body,
                )
            )
        if cookie["samesite"] == "none" and not cookie["secure"]:
            signals.append(
                make_signal(
                    "csrf",
                    "cookie_samesite_none_without_secure",
                    "low",
                    "high",
                    "Cookie sets SameSite=None without Secure",
                    {"cookie_name": cookie["name"]},
                    baseline,
                    "Treat as hardening signal unless chained to a working CSRF or session exposure path.",
                    save_body,
                )
            )

    method_headers = [header_join(baseline, "allow"), header_join(baseline, "access-control-allow-methods")]
    if options:
        method_headers.extend([header_join(options, "allow"), header_join(options, "access-control-allow-methods")])
    unsafe = sorted(parse_methods(*method_headers) & UNSAFE_METHODS)
    if unsafe and any(cookie["likely_auth"] for cookie in parsed_cookies):
        signals.append(
            make_signal(
                "csrf",
                "csrf_cookie_auth_unsafe_methods_exposed",
                "medium",
                "low",
                "Likely cookie-auth surface advertises unsafe methods",
                {"unsafe_methods": unsafe, "cookie_names": [c["name"] for c in parsed_cookies if c["likely_auth"]]},
                options or baseline,
                "Use browser/API parity testing and a separate read-back to prove a cross-site side effect.",
                save_body,
            )
        )
    return signals


def analyze_cors_probe(origin: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    acao_values = [value.strip() for value in snap.values("access-control-allow-origin")]
    if not acao_values:
        return signals
    acac = header_join(snap, "access-control-allow-credentials").lower().strip() == "true"
    cacheable, indicators = looks_cacheable(snap)
    methods = sorted(parse_methods(header_join(snap, "access-control-allow-methods")) & UNSAFE_METHODS)
    for acao in acao_values:
        acao_l = acao.lower()
        reflected = acao == origin or (origin == "null" and acao_l == "null")
        wildcard = acao == "*"
        if reflected and acac:
            signals.append(
                make_signal(
                    "cors",
                    "cors_arbitrary_origin_with_credentials",
                    "high",
                    "high",
                    "Arbitrary Origin is reflected with Access-Control-Allow-Credentials: true",
                    {
                        "origin": origin,
                        "access_control_allow_origin": acao,
                        "unsafe_methods": methods,
                    },
                    snap,
                    "Confirm against an authenticated sensitive endpoint and capture credentialed data exfiltration.",
                    save_body,
                )
            )
        elif reflected:
            signals.append(
                make_signal(
                    "cors",
                    "cors_arbitrary_origin_reflection",
                    "medium",
                    "high",
                    "Arbitrary Origin is reflected in Access-Control-Allow-Origin",
                    {"origin": origin, "access_control_allow_origin": acao, "unsafe_methods": methods},
                    snap,
                    "Check whether credentials, tokens, or sensitive unauthenticated data are reachable.",
                    save_body,
                )
            )
        elif wildcard:
            severity = "low"
            title = "Wildcard CORS is enabled"
            if acac:
                title = "Wildcard CORS appears with credentials header; browsers block credentialed wildcard reads"
            signals.append(
                make_signal(
                    "cors",
                    "cors_wildcard_origin",
                    severity,
                    "medium",
                    title,
                    {"origin": origin, "access_control_allow_origin": acao, "credentials": acac},
                    snap,
                    "Do not report wildcard CORS alone; chain to credentialed data exfiltration if possible.",
                    save_body,
                )
            )

        if reflected and not vary_has(snap, "origin") and cacheable:
            signals.append(
                make_signal(
                    "cache-poisoning",
                    "cors_cache_poisoning_candidate",
                    "medium",
                    "medium",
                    "Reflected CORS origin on a cacheable response lacks Vary: Origin",
                    {
                        "origin": origin,
                        "access_control_allow_origin": acao,
                        "cache_indicators": indicators,
                    },
                    snap,
                    "Confirm whether a second client receives the poisoned ACAO value from shared cache.",
                    save_body,
                )
            )
    return signals


def default_origin_variants(hostname: str, canary: str, user_origins: list[str], mode: str) -> list[str]:
    origins = [f"https://{canary}.invalid"]
    if mode == "standard":
        origins.append("null")
        if hostname:
            origins.append(f"https://{hostname}.attacker.invalid")
    origins.extend(user_origins)
    deduped: list[str] = []
    for origin in origins:
        if origin not in deduped:
            deduped.append(origin)
    return deduped


def default_header_probe_names(custom_headers: list[str], limit: int) -> list[str]:
    probes = [
        "X-Forwarded-Host",
        "Forwarded",
        "X-Original-URL",
        "X-Host",
        "X-Forwarded-Server",
        "X-Rewrite-URL",
        "X-Forwarded-Prefix",
    ]
    if limit > 0:
        probes = probes[:limit]
    for header in custom_headers:
        probes.append(header)
    return probes


def header_probe_value(header_name: str, canary: str) -> str:
    name = header_name.lower()
    if name == "forwarded":
        return f"for=192.0.2.1;host={canary}.invalid;proto=https"
    if name in {"x-original-url", "x-rewrite-url", "x-forwarded-prefix"}:
        return f"/{canary}"
    return f"{canary}.invalid"


def analyze_header_probe(
    header_name: str,
    canary: str,
    probe_id: str,
    clean_before: HttpSnapshot | None,
    probe: HttpSnapshot,
    victim: HttpSnapshot | None,
    control: HttpSnapshot | None,
    save_body: bool,
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    locations = canary_locations(probe, canary)
    if not locations:
        return signals

    cacheable, indicators = looks_cacheable(probe)
    reflected_headers = [loc for loc in locations if loc["where"] == "response_header"]
    reflected_body = [loc for loc in locations if loc["where"] == "response_body"]

    if reflected_headers:
        header_names = sorted({loc["name"] for loc in reflected_headers})
        signal_type = "header_reflection_candidate"
        severity = "medium"
        title = "Request header value is reflected into response headers"
        if any(name in {"location", "link", "access-control-allow-origin"} for name in header_names):
            signal_type = "header_poisoning_candidate"
            severity = "high"
            title = "Request header value controls a security-relevant response header"
        signals.append(
            make_signal(
                "header-injection",
                signal_type,
                severity,
                "high",
                title,
                {"probe_id": probe_id, "canary": canary, "probe_header": header_name, "locations": reflected_headers},
                probe,
                "Validate exploitability with a victim-context request pair; CRLF is not proven by reflection alone.",
                save_body,
            )
        )

    if reflected_body and is_textual_response(probe):
        signals.append(
            make_signal(
                "content-spoofing",
                "header_based_content_spoofing",
                "medium",
                "high",
                "Request header value is reflected in textual response body",
                {"probe_id": probe_id, "canary": canary, "probe_header": header_name, "locations": reflected_body},
                probe,
                "Check whether the reflected content is reachable by victims and whether it can be cached.",
                save_body,
            )
        )

    if cacheable:
        signals.append(
            make_signal(
                "cache-poisoning",
                "unkeyed_header_cache_poisoning_candidate",
                "medium",
                "medium",
                "Header reflection appears on a cacheable response",
                {
                    "probe_id": probe_id,
                    "canary": canary,
                    "probe_header": header_name,
                    "locations": locations,
                    "cache_indicators": indicators,
                },
                probe,
                "A report needs a clean victim request receiving the poisoned response from shared cache.",
                save_body,
            )
        )

    victim_locations = canary_locations(victim, canary) if victim else []
    victim_indicators = cache_indicators(victim) if victim else []
    shared_markers = shared_cache_hit_markers(victim_indicators)
    clean_before_locations = canary_locations(clean_before, canary) if clean_before else []
    control_locations = canary_locations(control, canary) if control else []
    clean_before_indicators = cache_indicators(clean_before) if clean_before else []
    control_indicators = cache_indicators(control) if control else []
    snapshots = (clean_before, probe, victim, control)
    completed_stages = all(snapshot_completed(item) for item in snapshots)
    cache_key_relationship = bool(
        clean_before
        and victim
        and control
        and clean_before.request_url == probe.request_url == victim.request_url
        and control.request_url != probe.request_url
    )
    client_contexts = [item.client_context for item in snapshots if item is not None]
    isolated_client_contexts = len(client_contexts) == 4 and len(set(client_contexts)) == 4
    status_consistent = bool(
        clean_before
        and victim
        and control
        and clean_before.status == probe.status == victim.status == control.status
    )
    state_machine_checks = {
        "clean_before_completed": snapshot_completed(clean_before),
        "poison_completed": snapshot_completed(probe),
        "clean_victim_completed": snapshot_completed(victim),
        "fresh_control_completed": snapshot_completed(control),
        "cache_key_relationship_valid": cache_key_relationship,
        "isolated_client_contexts": isolated_client_contexts,
        "response_status_consistent": status_consistent,
        "clean_before_has_no_canary": not clean_before_locations,
        "poison_response_contains_canary": bool(locations),
        "clean_victim_contains_canary": bool(victim_locations),
        "fresh_control_has_no_canary": not control_locations,
        "poison_request_contains_canary": request_contains_canary(probe, canary),
        "clean_before_request_has_no_canary": not request_contains_canary(clean_before, canary),
        "clean_victim_request_has_no_canary": not request_contains_canary(victim, canary),
        "fresh_control_request_has_no_canary": not request_contains_canary(control, canary),
        "shared_cache_hit_marker_present": bool(shared_markers),
        "cache_hit_progressed": cache_hit_progressed(clean_before, probe, victim),
    }
    shared_confirmed = (
        completed_stages
        and all(state_machine_checks.values())
    )
    if victim_locations and (cacheable or victim_indicators):
        signal_type = (
            "cache_poisoning_shared_cache_confirmed"
            if shared_confirmed
            else "cache_poisoning_cross_request_reproduction"
        )
        title = (
            "Shared cache served the poisoned canary to a clean client"
            if shared_confirmed
            else "Clean follow-up reproduced the poison, but shared-cache proof is incomplete"
        )
        signals.append(
            make_signal(
                "cache-poisoning",
                signal_type,
                "high",
                "high",
                title,
                {
                    "probe_id": probe_id,
                    "canary": canary,
                    "probe_header": header_name,
                    "poison_locations": locations,
                    "victim_locations": victim_locations,
                    "clean_before_locations": clean_before_locations,
                    "fresh_key_control_locations": control_locations,
                    "clean_follow_up": True,
                    "fresh_key_control": snapshot_completed(control),
                    "cacheable_probe": cacheable,
                    "cache_indicators": sorted(
                        set(indicators + victim_indicators + clean_before_indicators + control_indicators)
                    ),
                    "clean_before_cache_indicators": clean_before_indicators,
                    "victim_cache_indicators": victim_indicators,
                    "fresh_key_control_cache_indicators": control_indicators,
                    "shared_cache_confirmed": shared_confirmed,
                    "shared_cache_hit_markers": shared_markers,
                    "state_machine_checks": state_machine_checks,
                },
                victim,
                "Repeat on an authorized low-traffic path and prove cross-client reachability before reporting.",
                save_body,
            )
        )

    return signals


def analyze_content_param(canary: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    locations = canary_locations(snap, canary)
    if not locations:
        return []
    signals: list[dict[str, Any]] = []
    body_hits = [loc for loc in locations if loc["where"] == "response_body"]
    header_hits = [loc for loc in locations if loc["where"] == "response_header"]
    if body_hits and is_textual_response(snap):
        signals.append(
            make_signal(
                "content-spoofing",
                "query_parameter_content_reflection",
                "low",
                "high",
                "Query parameter value is reflected in textual response body",
                {"locations": body_hits},
                snap,
                "Content spoofing becomes reportable only with victim impact, caching, or script execution.",
                save_body,
            )
        )
    if header_hits:
        signals.append(
            make_signal(
                "header-injection",
                "query_parameter_header_reflection",
                "medium",
                "medium",
                "Query parameter value is reflected into response headers",
                {"locations": header_hits},
                snap,
                "Try controlled response-splitting validation only on authorized targets and without user impact.",
                save_body,
            )
        )
    return signals


def analyze_crlf_probe(canary: str, snap: HttpSnapshot, save_body: bool) -> list[dict[str, Any]]:
    injected_header_values = snap.values("x-pa-injected")
    injected_header_seen = any(value.strip() == canary for value in injected_header_values)
    locations = canary_locations(snap, canary)
    if not injected_header_seen and not locations:
        return []
    severity = "high" if injected_header_seen else "medium"
    confidence = "high" if injected_header_seen else "medium"
    return [
        make_signal(
            "header-injection",
            "response_splitting_crlf_candidate",
            severity,
            confidence,
            "CRLF query probe influenced response headers",
            {
                "injected_header_seen": injected_header_seen,
                "injected_header_values": injected_header_values[:3],
                "locations": locations,
                "probe": "%0d%0aX-PA-Injected:<canary>",
            },
            snap,
            "Re-test manually with a harmless cache-buster and prove a victim-observable header/body change.",
            save_body,
        )
    ]
