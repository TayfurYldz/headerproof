from __future__ import annotations

import re

DEFAULT_CHECKS = {
    "cors",
    "csrf",
    "header-injection",
    "cache-poisoning",
    "content-spoofing",
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LIKELY_AUTH_COOKIE = re.compile(r"(session|sess|sid|auth|token|jwt|sso|remember|login)", re.I)
TEXTUAL_CONTENT = re.compile(r"(text/|json|xml|javascript|html|form-urlencoded)", re.I)
CACHEABLE_STATUSES = {200, 203, 204, 206, 300, 301, 302, 404, 410}
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}
PRODUCT_NAME = "HeaderProof"
VERSION = "1.3.1"
SCHEMA_VERSION = "1.2"
BANNER = r"""
    __  __               __          ____                   __
   / / / /__  ____ _____/ /__  _____/ __ \________  ____  / /
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ /_/ / ___/ _ \/ __ \/ /
 / __  /  __/ /_/ / /_/ /  __/ /  / ____/ /  /  __/ /_/ /_/
/_/ /_/\___/\__,_/\__,_/\___/_/  /_/   /_/   \___/\____(_)
"""
PROFILE_DEFAULTS = {
    "fast": {
        "timeout": 2.0,
        "max_body": 8192,
        "concurrency": 16,
        "per_url_concurrency": 6,
        "origin_mode": "single",
        "header_probe_limit": 3,
        "no_preflight": True,
        "no_cache_confirm": False,
    },
    "balanced": {
        "timeout": 2.5,
        "max_body": 16384,
        "concurrency": 12,
        "per_url_concurrency": 4,
        "origin_mode": "standard",
        "header_probe_limit": 5,
        "no_preflight": False,
        "no_cache_confirm": False,
    },
    "thorough": {
        "timeout": 3.0,
        "max_body": 32768,
        "concurrency": 8,
        "per_url_concurrency": 4,
        "origin_mode": "standard",
        "header_probe_limit": 0,
        "no_preflight": False,
        "no_cache_confirm": False,
    },
}
SUPPRESSED_BY_STRICT = {
    "cors_wildcard_origin",
    "csrf_cookie_samesite_missing",
    "csrf_cookie_cross_site_auth",
    "csrf_cookie_auth_unsafe_methods_exposed",
    "header_reflection_candidate",
    "header_based_content_spoofing",
    "cookie_samesite_none_without_secure",
    "query_parameter_content_reflection",
}
