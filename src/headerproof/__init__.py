"""Public HeaderProof API."""

from .detectors import (
    analyze_content_param,
    analyze_cors_probe,
    analyze_crlf_probe,
    analyze_csrf,
    analyze_header_probe,
    cache_hit_progressed,
    cache_indicators,
    canary_locations,
    default_header_probe_names,
    default_origin_variants,
    header_join,
    header_probe_value,
    looks_cacheable,
    parse_cookie,
    parse_methods,
    shared_cache_hit_markers,
)
from .engine import scan_url
from .evidence import assess_signal, make_signal, signal_passes_fp_filter, verification_template
from .input import add_query, add_raw_query, iter_urls, load_urls, normalise_url
from .models import HttpSnapshot
from .output import print_console_summary, write_outputs
from .transport import HttpClient, UrlBudget, snapshot_summary

__all__ = [
    "HttpClient",
    "HttpSnapshot",
    "UrlBudget",
    "add_query",
    "add_raw_query",
    "analyze_content_param",
    "analyze_cors_probe",
    "analyze_crlf_probe",
    "analyze_csrf",
    "analyze_header_probe",
    "assess_signal",
    "cache_hit_progressed",
    "cache_indicators",
    "canary_locations",
    "default_header_probe_names",
    "default_origin_variants",
    "header_join",
    "header_probe_value",
    "iter_urls",
    "load_urls",
    "looks_cacheable",
    "make_signal",
    "normalise_url",
    "parse_cookie",
    "parse_methods",
    "print_console_summary",
    "scan_url",
    "shared_cache_hit_markers",
    "signal_passes_fp_filter",
    "snapshot_summary",
    "verification_template",
    "write_outputs",
]
