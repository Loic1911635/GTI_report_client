"""GTI client helpers for mock reports and VirusTotal API lookups."""

from __future__ import annotations

import base64
import json
import calendar
import re
from typing import Any
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urljoin, urlparse

import requests


VIRUSTOTAL_DOMAIN_LOOKUP_URL = "https://www.virustotal.com/api/v3/domains/{}"
VIRUSTOTAL_COLLECTIONS_URL = "https://www.virustotal.com/api/v3/collections"
VIRUSTOTAL_SEARCH_URL = "https://www.virustotal.com/api/v3/search"
VIRUSTOTAL_INTELLIGENCE_SEARCH_URL = (
    "https://www.virustotal.com/api/v3/intelligence/search"
)
VIRUSTOTAL_DTM_MONITORS_URL = "https://www.virustotal.com/api/v3/dtm/monitors"
VIRUSTOTAL_DTM_ALERTS_URL = "https://www.virustotal.com/api/v3/dtm/alerts"
VIRUSTOTAL_DTM_EVENTS_URL = "https://www.virustotal.com/api/v3/dtm/events"
VIRUSTOTAL_IOC_STREAM_URL = "https://www.virustotal.com/api/v3/ioc_stream"
VIRUSTOTAL_IP_ADDRESS_LOOKUP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VIRUSTOTAL_URL_LOOKUP_URL = "https://www.virustotal.com/api/v3/urls/{}"
VIRUSTOTAL_FILE_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{}"
DEFAULT_TTP_CANDIDATES = 25
MAX_TTP_CANDIDATES = 100
MAX_SAFE_DTM_PAGES = 5
DEFAULT_IOC_STREAM_LIMIT = 40
IOC_STREAM_API_PAGE_LIMIT = 40
MAX_IOC_STREAM_LIMIT = 500
DEFAULT_IOC_STREAM_PAGES_TO_FETCH = 5
MAX_IOC_STREAM_PAGES_TO_FETCH = 10
IOC_STREAM_ALLOWED_PAGES_TO_FETCH = {1, 2, 5, 10}
IOC_STREAM_SAMPLE_WARNING = (
    "IoC Stream is chronological. This report summarizes the recent pages returned "
    "by the API, not a guaranteed complete time window."
)
DEFAULT_INTELLIGENCE_SEARCH_LIMIT = 10
MAX_INTELLIGENCE_SEARCH_LIMIT = 40
DEFAULT_TOP_TARGETS_MAX_DETAIL_LOOKUPS = 0
MAX_TOP_TARGETS_DETAIL_LOOKUPS = 50
DEFAULT_TOP_RANKINGS_MAX_COLLECTIONS = 1000
TOP_RANKING_KEYS = {
    "targeted_industries",
    "targeted_regions",
    "source_regions",
    "tags",
    "collection_type",
    "timeline",
    "targeted_organizations",
}
TOP_RANKING_ORGANIZATION_FIELDS = (
    "targeted_organizations",
    "affected_organizations",
    "victim_organizations",
    "organizations",
    "victims",
    "companies",
)
TOP_RANKING_FIELD_ALIASES = {
    "targeted_industries": (
        "targeted_industries",
        "targeted_industry",
        "targeted_industries_free",
    ),
    "targeted_regions": (
        "targeted_regions",
        "targeted_region",
        "targeted_regions_hierarchy",
    ),
    "source_regions": (
        "source_regions",
        "source_region",
        "source_regions_hierarchy",
    ),
    "tags": (
        "tags",
        "tag",
        "threat_categories",
        "threat_category",
        "categories",
    ),
    "collection_type": (
        "collection_type",
        "collection_subtype",
        "report_type",
    ),
    "targeted_organizations": TOP_RANKING_ORGANIZATION_FIELDS,
}
DEFAULT_DTM_MONITOR_PAGE_SIZE = 50
DEFAULT_DTM_ALERT_PAGE_SIZE = 25
MAX_DTM_ALERT_PAGE_SIZE = 25
TOP_TARGET_ORG_AGGREGATION_KEYS = (
    "organizations",
    "victims",
    "victim_organizations",
    "affected_organizations",
    "companies",
    "targeted_organizations",
)
IOC_STREAM_ENTITY_TYPES = {"all", "file", "domain", "url", "ip_address"}
IOC_STREAM_ORIGINS = {"all", "subscriptions", "hunting"}
IOC_STREAM_RISK_ORDER = {"Unknown": 0, "Low": 1, "Medium": 2, "High": 3}
IOC_STREAM_DEFINITIONS = [
    {
        "term": "IoC",
        "definition": "Indicator of Compromise: a technical clue such as a domain, URL, IP address, or file hash that may be linked to suspicious or malicious activity.",
    },
    {
        "term": "Domain",
        "definition": "A named internet destination, such as example.com, often used to identify websites, mail infrastructure, or command-and-control endpoints.",
    },
    {
        "term": "URL",
        "definition": "A full web address that can point to a specific page, file, redirect, phishing page, or payload location.",
    },
    {
        "term": "IP address",
        "definition": "A network address used by infrastructure. IP indicators should be reviewed carefully because ownership and hosting can change.",
    },
    {
        "term": "File hash",
        "definition": "A cryptographic fingerprint for a file, commonly used to identify malware samples or suspicious binaries.",
    },
    {
        "term": "Collection",
        "definition": "A GTI intelligence object grouping related indicators, context, reporting, or campaign information.",
    },
    {
        "term": "Livehunt / Hunting ruleset",
        "definition": "A hunting rule or ruleset that detects matching files or indicators and can generate stream notifications.",
    },
    {
        "term": "Retrohunt",
        "definition": "A historical hunt across previously seen data, useful for finding older matches to new detection logic.",
    },
    {
        "term": "Threat Actor",
        "definition": "An individual, group, or activity cluster associated with cyber threat activity.",
    },
    {
        "term": "GTI score",
        "definition": "A numeric risk signal when available. Higher scores indicate stronger malicious or suspicious context.",
    },
    {
        "term": "Verdict",
        "definition": "A GTI assessment label such as malicious, suspicious, benign, or unknown when exposed by the API response.",
    },
]

MOCK_IOC_STREAM_PAYLOAD = {
    "data": [
        {
            "id": "login-security-check.example",
            "type": "domain",
            "attributes": {
                "entity_type": "domain",
                "source_type": "collection",
                "source_name": "Credential Theft Infrastructure",
                "origin": "subscriptions",
                "matched_date": "2026-05-20T10:12:00Z",
                "gti_score": 91,
                "gti_verdict": "malicious",
            },
        },
        {
            "id": "https://billing-example.net/session/verify",
            "type": "url",
            "attributes": {
                "source_type": "Livehunt / Hunting ruleset",
                "source_name": "Brand impersonation hunt",
                "origin": "hunting",
                "matched_date": "2026-05-20T09:42:00Z",
                "score": 67,
                "verdict": "suspicious",
            },
        },
        {
            "id": "44d88612fea8a8f36de82e1278abb02f",
            "type": "file",
            "attributes": {
                "source_type": "Retrohunt",
                "source_name": "Windows loader retrohunt",
                "origin": "hunting",
                "matched_date": "2026-05-19T18:15:00Z",
                "gti_score": 82,
                "gti_verdict": "malicious",
            },
        },
        {
            "id": "203.0.113.42",
            "type": "ip_address",
            "attributes": {
                "source_type": "threat_actor",
                "source_name": "Suspicious infrastructure cluster",
                "origin": "subscriptions",
                "matched_date": "2026-05-19T14:03:00Z",
                "gti_score": 38,
                "gti_verdict": "undetected",
            },
        },
        {
            "id": "cdn-update-check.example",
            "type": "domain",
            "attributes": {
                "source_type": "collection",
                "source_name": "Possible redirector set",
                "origin": "subscriptions",
                "matched_date": "2026-05-18T20:21:00Z",
                "gti_score": 12,
            },
        },
        {
            "id": "https://unknown.example/download",
            "type": "url",
            "attributes": {
                "source_type": "collection",
                "origin": "subscriptions",
                "matched_date": "2026-05-18T08:11:00Z",
            },
        },
        {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "source_type": "collection",
                "source_name": "Context-only network indicator",
                "origin": "subscriptions",
                "matched_date": "2026-05-17T11:00:00Z",
                "gti_verdict": "unknown",
            },
        },
        {
            "id": "275a021bbfb6489e54d471899f7db9d1",
            "type": "file",
            "relationships": {
                "source": {
                    "data": {"id": "rule-loader-family", "type": "hunting_ruleset"}
                }
            },
            "attributes": {
                "origin": "hunting",
                "notification_date": "2026-05-16T16:45:00Z",
                "gti_assessment": {"score": 56, "verdict": "suspicious"},
            },
        },
    ],
    "links": {},
}


class GTIClientError(RuntimeError):
    """Raised when the GTI/VirusTotal client cannot return usable data."""


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert API values to integers without leaking parsing errors."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def lookup_domain(api_key: str, domain: str) -> dict[str, Any]:
    """Look up a domain with the VirusTotal v3 API and normalize the response."""

    normalized_api_key = api_key.strip()
    normalized_domain = domain.strip().lower()

    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for domain lookups.")

    if not normalized_domain:
        raise ValueError("A domain target is required for IoC enrichment.")

    url = VIRUSTOTAL_DOMAIN_LOOKUP_URL.format(quote(normalized_domain, safe=""))

    try:
        response = requests.get(
            url,
            headers={"x-apikey": normalized_api_key},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise GTIClientError(
            f"VirusTotal domain lookup request failed for '{normalized_domain}': {exc}"
        ) from exc

    if response.status_code != 200:
        error_detail = ""

        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {}

        if isinstance(error_payload, dict):
            api_error = error_payload.get("error", {})
            if isinstance(api_error, dict):
                error_detail = str(api_error.get("message", "")).strip()
            elif api_error:
                error_detail = str(api_error).strip()

        if not error_detail:
            error_detail = response.text.strip()

        detail_suffix = f": {error_detail}" if error_detail else ""
        raise GTIClientError(
            "VirusTotal domain lookup failed "
            f"for '{normalized_domain}' with status {response.status_code}{detail_suffix}"
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise GTIClientError(
            f"VirusTotal returned a non-JSON response for '{normalized_domain}'."
        ) from exc

    data = payload.get("data", {})
    attributes = data.get("attributes", {})

    raw_last_analysis_stats = attributes.get("last_analysis_stats", {})
    normalized_last_analysis_stats: dict[str, int] = {}
    if isinstance(raw_last_analysis_stats, dict):
        normalized_last_analysis_stats = {
            str(stat_name): _safe_int(stat_value)
            for stat_name, stat_value in raw_last_analysis_stats.items()
        }

    for key in ("malicious", "suspicious", "harmless", "undetected"):
        normalized_last_analysis_stats.setdefault(key, 0)

    raw_categories = attributes.get("categories", {})
    normalized_categories: dict[str, str] = {}
    if isinstance(raw_categories, dict):
        normalized_categories = {
            str(vendor): str(category)
            for vendor, category in raw_categories.items()
        }

    return {
        "source": "gti_virustotal_v3",
        "indicator_type": "domain",
        "indicator": normalized_domain,
        "reputation": _safe_int(attributes.get("reputation")),
        "last_analysis_stats": normalized_last_analysis_stats,
        "malicious": normalized_last_analysis_stats["malicious"],
        "suspicious": normalized_last_analysis_stats["suspicious"],
        "harmless": normalized_last_analysis_stats["harmless"],
        "undetected": normalized_last_analysis_stats["undetected"],
        "categories": normalized_categories,
    }


def explore_industry_snapshots(api_key: str) -> dict[str, Any]:
    """Probe GTI sources for Industry Snapshot objects without assuming schema."""

    normalized_api_key = api_key.strip()
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for Industry Snapshot exploration.")

    endpoint_results = [
        _probe_json_endpoint(
            api_key=normalized_api_key,
            url=VIRUSTOTAL_COLLECTIONS_URL,
            params={"limit": 20},
            endpoint_name="collections",
        ),
        _probe_json_endpoint(
            api_key=normalized_api_key,
            url=VIRUSTOTAL_SEARCH_URL,
            params={"query": "Industry Snapshot", "limit": 20},
            endpoint_name="search",
        ),
    ]

    snapshots = _collect_industry_snapshot_matches(endpoint_results)
    overall_status_code = next(
        (
            int(result["http_status"])
            for result in endpoint_results
            if int(result["http_status"]) == 200
        ),
        int(endpoint_results[0]["http_status"]),
    )

    return {
        "status_code": overall_status_code,
        "snapshot_count": len(snapshots),
        "snapshots": snapshots,
        "endpoint_results": endpoint_results,
        "raw_json": {result["endpoint_name"]: result["raw_json"] for result in endpoint_results},
    }


def intelligence_search(
    api_key: str,
    query: str,
    limit: int = DEFAULT_INTELLIGENCE_SEARCH_LIMIT,
    descriptors_only: bool = False,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Run a GTI Intelligence Search query and return a safe preview."""

    normalized_api_key = api_key.strip()
    normalized_query = query.strip()
    normalized_cursor = cursor.strip() if cursor else ""

    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for GTI Intelligence Search.")
    if not normalized_query:
        raise ValueError("A search query is required for GTI Intelligence Search.")
    if limit < 1:
        raise ValueError("The GTI Intelligence Search limit must be at least 1.")

    normalized_limit = min(limit, MAX_INTELLIGENCE_SEARCH_LIMIT)
    params: dict[str, Any] = {
        "query": normalized_query,
        "limit": normalized_limit,
        "descriptors_only": "true" if descriptors_only else "false",
    }
    if normalized_cursor:
        params["cursor"] = normalized_cursor

    endpoint_result = _probe_json_endpoint(
        api_key=normalized_api_key,
        url=VIRUSTOTAL_INTELLIGENCE_SEARCH_URL,
        params=params,
        endpoint_name="intelligence_search",
    )

    payload = endpoint_result["raw_json"]
    next_cursor = _extract_next_cursor(payload)

    if not next_cursor:
        next_link_url = _extract_next_link_from_headers(
            endpoint_result.get("response_headers", {})
        )
        if next_link_url:
            next_cursor = _extract_cursor_from_url(next_link_url)

    simplified_preview = [
        _simplify_intelligence_search_item(item)
        for item in _extract_api_items(payload)
    ]

    return {
        "status_code": int(endpoint_result["http_status"]),
        "total_collected": len(simplified_preview),
        "next_cursor": next_cursor,
        "simplified_preview": simplified_preview,
        "raw_data": payload,
    }


def fetch_ioc_stream(
    api_key: str,
    limit: int | None = None,
    entity_type: str = "all",
    origin: str = "all",
    descriptors_only: bool = False,
    cursor: str | None = None,
    order: str = "date",
    pages_to_fetch: int = DEFAULT_IOC_STREAM_PAGES_TO_FETCH,
    max_pages: int | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    time_window: str | None = None,
) -> dict[str, Any]:
    """Fetch recent chronological IoC Stream pages without enriching indicators."""

    normalized_api_key = api_key.strip()
    normalized_entity_type = _normalize_ioc_stream_choice(
        entity_type,
        IOC_STREAM_ENTITY_TYPES,
        "entity_type",
    )
    normalized_origin = _normalize_ioc_stream_choice(
        origin,
        IOC_STREAM_ORIGINS,
        "origin",
    )
    normalized_cursor = cursor.strip() if cursor else ""

    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for IoC Stream.")
    if order and order != "date":
        raise ValueError("The IoC Stream order must be 'date'.")
    # max_pages is accepted as a legacy alias while the UI moves to pages_to_fetch.
    requested_pages = max_pages if max_pages is not None else pages_to_fetch
    if requested_pages not in IOC_STREAM_ALLOWED_PAGES_TO_FETCH:
        raise ValueError(
            "The IoC Stream pages_to_fetch value must be one of: 1, 2, 5, 10."
        )
    if limit is not None and limit < 1:
        raise ValueError("The IoC Stream compatibility limit must be at least 1.")

    normalized_pages_to_fetch = requested_pages
    filters: list[str] = []
    if normalized_entity_type != "all":
        filters.append(f"entity_type:{normalized_entity_type}")
    if normalized_origin != "all":
        filters.append(f"origin:{normalized_origin}")

    base_params: dict[str, Any] = {
        "descriptors_only": "true" if descriptors_only else "false",
        "order": "date",
    }
    if filters:
        base_params["filter"] = " ".join(filters)
    request_params: dict[str, Any] = {
        **base_params,
        "pages_to_fetch": normalized_pages_to_fetch,
        "api_page_limit": IOC_STREAM_API_PAGE_LIMIT,
    }
    if limit is not None:
        request_params["compatibility_limit"] = limit
    if time_window or start_date or end_date:
        request_params["ignored_date_filters"] = {
            "time_window": time_window,
            "start_date": start_date,
            "end_date": end_date,
        }
    if normalized_cursor:
        request_params["cursor"] = normalized_cursor

    if normalized_api_key.casefold() in {"mock", "sample", "demo"}:
        payload, collection_metadata = _filter_mock_ioc_stream_payload(
            MOCK_IOC_STREAM_PAYLOAD,
            entity_type=normalized_entity_type,
            origin=normalized_origin,
            pages_to_fetch=normalized_pages_to_fetch,
        )
        return {
            "status_code": 200,
            "total_collected": len(_extract_api_items(payload)),
            "next_cursor": None,
            "raw_data": payload,
            "collection": {
                **collection_metadata,
                "requested_pages": normalized_pages_to_fetch,
                "page_size": IOC_STREAM_API_PAGE_LIMIT,
            },
            "endpoint_results": [
                {
                    "endpoint_name": "ioc_stream_mock",
                    "http_status": 200,
                    "request_params": {
                        **base_params,
                        "limit": IOC_STREAM_API_PAGE_LIMIT,
                    },
                }
            ],
            "page_diagnostics": [
                {
                    "page_number": 1,
                    "http_status": 200,
                    "raw_page_item_count": len(_extract_api_items(payload)),
                    "next_cursor_found": False,
                    "next_link_found": False,
                    "request_url": VIRUSTOTAL_IOC_STREAM_URL,
                    "request_params": {
                        **base_params,
                        "limit": IOC_STREAM_API_PAGE_LIMIT,
                    },
                }
            ],
            "request_params": request_params,
            "warnings": [IOC_STREAM_SAMPLE_WARNING],
        }

    collected_items: list[dict[str, Any]] = []
    endpoint_results: list[dict[str, Any]] = []
    page_diagnostics: list[dict[str, Any]] = []
    page_payloads: list[Any] = []
    current_cursor = normalized_cursor
    current_url = VIRUSTOTAL_IOC_STREAM_URL
    next_cursor: str | None = None
    final_status_code = 0
    warnings: list[str] = []
    stopped_reason = "requested_pages_reached"
    seen_page_tokens: set[str] = set()

    for page_number in range(1, normalized_pages_to_fetch + 1):
        request_uses_base_url = current_url == VIRUSTOTAL_IOC_STREAM_URL
        params = {**base_params, "limit": IOC_STREAM_API_PAGE_LIMIT} if request_uses_base_url else None
        if params is not None and current_cursor:
            params["cursor"] = current_cursor

        endpoint_result = _probe_json_endpoint(
            api_key=normalized_api_key,
            url=current_url,
            params=params,
            endpoint_name="ioc_stream",
        )
        endpoint_result = {**endpoint_result, "request_params": params or {}}
        endpoint_results.append(endpoint_result)
        payload = endpoint_result["raw_json"]
        final_status_code = int(endpoint_result["http_status"])

        if final_status_code != 200:
            page_diagnostics.append(
                {
                    "page_number": page_number,
                    "http_status": final_status_code,
                    "raw_page_item_count": len(_extract_api_items(payload)),
                    "next_cursor_found": False,
                    "next_link_found": False,
                    "request_url": current_url,
                    "request_params": params or {},
                }
            )
            return {
                "status_code": final_status_code,
                "total_collected": len(collected_items),
                "next_cursor": None,
                "raw_data": payload,
                "endpoint_results": endpoint_results,
                "page_diagnostics": page_diagnostics,
                "request_params": request_params,
                "warnings": [IOC_STREAM_SAMPLE_WARNING, *warnings],
            }

        page_payloads.append(payload)
        page_items = _extract_api_items(payload)
        collected_items.extend(page_items)

        next_cursor = _extract_next_cursor(payload)
        next_link_url = _normalize_ioc_stream_next_url(
            _extract_next_link_from_payload(payload) or _extract_next_link_from_headers(
            endpoint_result.get("response_headers", {})
            )
        )
        if not next_cursor and next_link_url:
            next_cursor = _extract_cursor_from_url(next_link_url)

        page_diagnostics.append(
            {
                "page_number": page_number,
                "http_status": final_status_code,
                "raw_page_item_count": len(page_items),
                "next_cursor_found": bool(next_cursor),
                "next_link_found": bool(next_link_url),
                "request_url": current_url,
                "request_params": params or {},
            }
        )

        if not next_cursor or not page_items:
            if next_link_url:
                page_token = next_link_url
                if page_token in seen_page_tokens:
                    stopped_reason = "pagination_loop_detected"
                    break
                seen_page_tokens.add(page_token)
                current_url = next_link_url
                current_cursor = ""
                continue
            else:
                stopped_reason = "no_more_pages"
                break

        page_token = f"cursor:{next_cursor}"
        if page_token in seen_page_tokens:
            stopped_reason = "pagination_loop_detected"
            break
        seen_page_tokens.add(page_token)
        current_url = VIRUSTOTAL_IOC_STREAM_URL
        current_cursor = next_cursor

    collection_metadata = _build_ioc_stream_collection_metadata(
        items=collected_items,
        pages_fetched=len(endpoint_results),
        requested_pages=normalized_pages_to_fetch,
        page_size=IOC_STREAM_API_PAGE_LIMIT,
        stopped_reason=stopped_reason,
    )
    collection_metadata["page_diagnostics"] = page_diagnostics
    warnings = [IOC_STREAM_SAMPLE_WARNING, *warnings]

    return {
        "status_code": final_status_code,
        "total_collected": len(collected_items),
        "next_cursor": next_cursor,
        "raw_data": {"data": collected_items, "pages": page_payloads},
        "collection": collection_metadata,
        "endpoint_results": endpoint_results,
        "page_diagnostics": page_diagnostics,
        "request_params": request_params,
        "warnings": warnings,
    }


def normalize_ioc_stream_item(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize one IoC Stream item into report-friendly fields."""

    attributes = item.get("attributes", {})
    normalized_attributes = attributes if isinstance(attributes, dict) else {}
    relationships = item.get("relationships", {})
    normalized_relationships = relationships if isinstance(relationships, dict) else {}
    merged_fields = _merge_item_with_attributes(item, normalized_attributes)

    entity_type = _normalize_ioc_entity_type(
        _first_present(
            merged_fields,
            ("entity_type", "indicator_type", "type", "object_type"),
        )
    )
    value = _extract_ioc_value(item, normalized_attributes, entity_type)
    source_type = _extract_ioc_source_type(merged_fields, normalized_relationships)
    source_name = _extract_ioc_source_name(merged_fields, normalized_relationships)
    origin = _stringify_value(
        _first_present(
            merged_fields,
            ("origin", "source_origin", "notification_origin"),
        )
    ) or "Unknown"
    matched_date = _stringify_value(
        _first_present(
            merged_fields,
            (
                "matched_date",
                "notification_date",
                "created_at",
                "creation_date",
                "date",
                "last_modification_date",
            ),
        )
    )
    gti_score = _extract_ioc_score(merged_fields)
    gti_verdict = _extract_ioc_verdict(merged_fields)
    classification = classify_ioc_risk(gti_score, gti_verdict)

    return {
        "value": value,
        "entity_type": entity_type,
        "source_type": source_type,
        "source_name": source_name,
        "origin": origin,
        "matched_date": matched_date,
        "gti_score": gti_score,
        "gti_verdict": gti_verdict,
        "malicious": None,
        "suspicious": None,
        "reputation": None,
        "risk": classification["risk"],
        "severity": classification["risk"],
        "recommended_action": classification["recommended_action"],
        "enrichment_status": "not_requested",
        "explanation": _build_ioc_explanation(
            entity_type=entity_type,
            severity=classification["risk"],
            source_type=source_type,
            verdict=gti_verdict,
            score=gti_score,
        ),
    }


def classify_ioc_risk(
    gti_score: int | float | None,
    gti_verdict: str | None,
) -> dict[str, str]:
    """Classify an IoC using GTI score and verdict guardrails."""

    if gti_score is None:
        risk = "Unknown"
        action = "Manual review"
    elif gti_score >= 80:
        risk = "High"
        action = "Investigate / block if confirmed"
    elif gti_score >= 50:
        risk = "Medium"
        action = "Investigate / monitor"
    else:
        risk = "Low"
        action = "Monitor"

    verdict = (gti_verdict or "").casefold()
    if "malicious" in verdict and IOC_STREAM_RISK_ORDER[risk] < IOC_STREAM_RISK_ORDER["High"]:
        risk = "High"
        action = "Investigate / block if confirmed"
    elif "suspicious" in verdict and IOC_STREAM_RISK_ORDER[risk] < IOC_STREAM_RISK_ORDER["Medium"]:
        risk = "Medium"
        action = "Investigate / monitor"

    return {"risk": risk, "recommended_action": action}


def enrich_ioc_indicator(api_key: str, indicator: dict[str, Any]) -> dict[str, Any]:
    """Best-effort enrichment for one IoC Stream indicator."""

    enriched_indicator = dict(indicator)
    entity_type = str(enriched_indicator.get("entity_type") or "")
    value = str(enriched_indicator.get("value") or "").strip()

    if not value:
        enriched_indicator["enrichment_status"] = "skipped"
        enriched_indicator["enrichment_error"] = "Indicator value is missing."
        return enriched_indicator

    if api_key.strip().casefold() in {"mock", "sample", "demo"}:
        enrichment = _build_mock_ioc_enrichment(enriched_indicator)
    else:
        try:
            enrichment = _fetch_ioc_enrichment(
                api_key=api_key,
                entity_type=entity_type,
                value=value,
            )
        except GTIClientError as exc:
            enriched_indicator["enrichment_status"] = "error"
            enriched_indicator["enrichment_error"] = str(exc)
            return enriched_indicator

    if enrichment.get("status") != "success":
        enriched_indicator["enrichment_status"] = str(enrichment.get("status") or "error")
        enriched_indicator["enrichment_http_status"] = enrichment.get("http_status")
        enriched_indicator["enrichment_error"] = str(
            enrichment.get("error") or "Enrichment failed."
        )
        return enriched_indicator

    malicious = _safe_int(enrichment.get("malicious"))
    suspicious = _safe_int(enrichment.get("suspicious"))
    reputation = _coerce_ioc_number(enrichment.get("reputation"))
    classification = classify_enriched_ioc_risk(
        malicious=malicious,
        suspicious=suspicious,
        reputation=reputation,
        fallback_risk=str(enriched_indicator.get("severity") or "Unknown"),
        has_risk_context=bool(enrichment.get("has_risk_context")),
    )

    enriched_indicator.update(
        {
            "malicious": malicious,
            "suspicious": suspicious,
            "reputation": reputation,
            "risk": classification["risk"],
            "severity": classification["risk"],
            "recommended_action": classification["recommended_action"],
            "enrichment_status": "success",
            "enrichment_http_status": enrichment.get("http_status"),
            "explanation": _build_enriched_ioc_explanation(
                indicator=enriched_indicator,
                malicious=malicious,
                suspicious=suspicious,
                reputation=reputation,
                risk=classification["risk"],
            ),
        }
    )
    return enriched_indicator


def classify_enriched_ioc_risk(
    malicious: int,
    suspicious: int,
    reputation: int | float | None,
    fallback_risk: str = "Unknown",
    has_risk_context: bool = False,
) -> dict[str, str]:
    """Classify an enriched IoC from VT/GTI analysis stats and reputation."""

    if malicious > 0:
        return {
            "risk": "High",
            "recommended_action": "Investigate / block if confirmed",
        }
    if suspicious > 0:
        return {
            "risk": "Medium",
            "recommended_action": "Investigate / monitor",
        }
    if reputation is not None and reputation < -10:
        return {
            "risk": "Medium",
            "recommended_action": "Investigate / monitor",
        }
    if reputation is not None and reputation < 0:
        return {"risk": "Low", "recommended_action": "Monitor"}
    if has_risk_context:
        return {"risk": "Low", "recommended_action": "Monitor"}

    fallback = fallback_risk if fallback_risk in IOC_STREAM_RISK_ORDER else "Unknown"
    if fallback == "High":
        return {
            "risk": "High",
            "recommended_action": "Investigate / block if confirmed",
        }
    if fallback == "Medium":
        return {"risk": "Medium", "recommended_action": "Investigate / monitor"}
    if fallback == "Low":
        return {"risk": "Low", "recommended_action": "Monitor"}
    return {"risk": "Unknown", "recommended_action": "Manual review"}


def build_ioc_stream_report(
    stream_result: dict[str, Any],
    api_key: str | None = None,
    enrich: bool = False,
    enrichment_limit: int | None = None,
) -> dict[str, Any]:
    """Build client-friendly IoC Stream metrics and summaries."""

    payload = stream_result.get("raw_data")
    raw_indicators = [
        normalize_ioc_stream_item(item)
        for item in _extract_api_items(payload)
    ]
    indicators, duplicate_count = _dedupe_ioc_stream_indicators(raw_indicators)
    enrichment_attempted = 0
    enrichment_succeeded = 0
    enrichment_errors = 0
    requested_enrichment_limit = (
        len(indicators)
        if enrichment_limit is None
        else max(enrichment_limit, 0)
    )
    actual_enrichment_limit = (
        min(requested_enrichment_limit, len(indicators))
        if enrich and api_key and indicators
        else 0
    )

    if enrich and api_key and indicators:
        for index in range(actual_enrichment_limit):
            enrichment_attempted += 1
            indicators[index] = enrich_ioc_indicator(api_key, indicators[index])
            if indicators[index].get("enrichment_status") == "success":
                enrichment_succeeded += 1
            else:
                enrichment_errors += 1

    collection_metadata = dict(stream_result.get("collection", {}))
    page_diagnostics = stream_result.get(
        "page_diagnostics",
        collection_metadata.get("page_diagnostics", []),
    )
    diagnostics = {
        "page_diagnostics": page_diagnostics if isinstance(page_diagnostics, list) else [],
        "duplicate_count": duplicate_count,
        "duplicates_removed": duplicate_count,
        "unique_ioc_count": len(indicators),
        "raw_ioc_count": len(raw_indicators),
        "stopped_reason": collection_metadata.get("stopped_reason", "unknown"),
    }
    collection_metadata["total_collected"] = len(indicators)
    collection_metadata["total_enriched"] = enrichment_succeeded
    collection_metadata["unique_ioc_count"] = len(indicators)
    collection_metadata["duplicate_count"] = duplicate_count
    collection_metadata["duplicates_removed"] = duplicate_count
    collection_metadata["raw_ioc_count"] = len(raw_indicators)
    collection_metadata["page_diagnostics"] = diagnostics["page_diagnostics"]
    collection_metadata.setdefault(
        "pages_fetched",
        len(stream_result.get("endpoint_results", [])),
    )
    if not collection_metadata.get("earliest_timestamp") or not collection_metadata.get(
        "latest_timestamp"
    ):
        timestamps = [
            item_datetime
            for item_datetime in (
                _parse_ioc_stream_datetime(indicator.get("matched_date"))
                for indicator in indicators
            )
            if item_datetime is not None
        ]
        if timestamps:
            collection_metadata["earliest_timestamp"] = min(timestamps).isoformat()
            collection_metadata["latest_timestamp"] = max(timestamps).isoformat()

    analytics = build_ioc_stream_analytics(indicators)
    total = len(indicators)
    entity_counts = _count_ioc_field(indicators, "entity_type")
    risk_counts = _count_ioc_field(indicators, "severity")
    source_counts = _count_ioc_field(indicators, "source_type")
    action_counts = _count_ioc_field(indicators, "recommended_action")
    main_entity_type = _main_ioc_bucket(entity_counts)
    main_source_type = _main_ioc_bucket(source_counts)
    sorted_indicators = sorted(
        indicators,
        key=lambda indicator: (
            -IOC_STREAM_RISK_ORDER.get(str(indicator.get("severity")), 0),
            -(indicator.get("gti_score") if indicator.get("gti_score") is not None else -1),
            str(indicator.get("value") or ""),
        ),
    )

    summary = {
        "total_iocs": total,
        "high_risk": risk_counts.get("High", 0),
        "medium_risk": risk_counts.get("Medium", 0),
        "low_risk": risk_counts.get("Low", 0),
        "unknown_risk": risk_counts.get("Unknown", 0),
        "main_entity_type": main_entity_type,
        "main_source_type": main_source_type,
        "pages_fetched": collection_metadata.get("pages_fetched", 0),
        "total_enriched": enrichment_succeeded,
        "raw_ioc_count": len(raw_indicators),
        "unique_ioc_count": len(indicators),
        "duplicates_removed": duplicate_count,
        "earliest_timestamp": collection_metadata.get("earliest_timestamp"),
        "latest_timestamp": collection_metadata.get("latest_timestamp"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "summary": summary,
        "charts": {
            "by_entity_type": _counter_to_chart_rows(entity_counts),
            "by_risk": _counter_to_chart_rows(
                risk_counts,
                preferred_order=("High", "Medium", "Low", "Unknown"),
            ),
            "by_source_type": _counter_to_chart_rows(source_counts),
            "by_recommended_action": _counter_to_chart_rows(action_counts),
        },
        "top_indicators": sorted_indicators[:10],
        "business_summary": build_business_summary(summary),
        "analytics": analytics,
        "collection": collection_metadata,
        "definitions": IOC_STREAM_DEFINITIONS,
        "indicators": indicators,
        "technical_details": {
            "status_code": int(stream_result.get("status_code", 0)),
            "next_cursor": stream_result.get("next_cursor"),
            "request_params": stream_result.get("request_params", {}),
            "endpoint_results": stream_result.get("endpoint_results", []),
            "warnings": stream_result.get("warnings", []),
            "collection": collection_metadata,
            "diagnostics": diagnostics,
            "enrichment": {
                "enabled": bool(enrich),
                "attempted": enrichment_attempted,
                "succeeded": enrichment_succeeded,
                "errors": enrichment_errors,
                "requested_limit": requested_enrichment_limit,
                "actual_limit": actual_enrichment_limit,
            },
        },
    }


def _dedupe_ioc_stream_indicators(
    indicators: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Keep the first indicator for each entity_type + value pair."""

    unique_indicators: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    duplicate_count = 0

    for indicator in indicators:
        entity_type = str(indicator.get("entity_type") or "Unknown").strip().casefold()
        value = str(indicator.get("value") or "").strip().casefold()
        dedupe_key = (entity_type, value)
        if dedupe_key in seen_keys:
            duplicate_count += 1
            continue
        seen_keys.add(dedupe_key)
        unique_indicators.append(indicator)

    return unique_indicators, duplicate_count


def build_ioc_stream_analytics(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Build analyst cross-analysis from successfully enriched indicators only."""

    enriched_indicators = [
        indicator
        for indicator in indicators
        if indicator.get("enrichment_status") == "success"
    ]
    return {
        "source": "enriched_indicators_only",
        "enriched_indicator_count": len(enriched_indicators),
        "highest_risk_by_ioc_type": _build_ioc_type_risk_rows(enriched_indicators),
        "top_dangerous_indicators": _build_top_dangerous_ioc_rows(enriched_indicators),
        "risk_distribution": _build_risk_distribution_rows(enriched_indicators),
        "ioc_type_distribution": _build_ioc_type_distribution_rows(enriched_indicators),
        "recommended_action_distribution": _build_recommended_action_distribution_rows(
            enriched_indicators
        ),
        "business_insights": _build_ioc_business_insights(enriched_indicators),
    }


def build_business_summary(summary: dict[str, Any]) -> list[str]:
    """Generate simple non-technical interpretation text from report stats."""

    total = _safe_int(summary.get("total_iocs"))
    high_risk = _safe_int(summary.get("high_risk"))
    unknown_risk = _safe_int(summary.get("unknown_risk"))
    main_entity_type = str(summary.get("main_entity_type") or "Unknown")
    messages: list[str] = []

    if main_entity_type in {"domain", "url"}:
        messages.append(
            "Most indicators are web-based, which may point to phishing, malicious redirects, credential harvesting pages, or command-and-control infrastructure."
        )
    elif main_entity_type == "file":
        messages.append(
            "File indicators dominate the stream, which makes endpoint protection and malware analysis especially relevant."
        )
    elif main_entity_type == "ip_address":
        messages.append(
            "IP indicators can support firewall and network monitoring use cases, but should be reviewed carefully because IP ownership may change."
        )
    elif total == 0:
        messages.append("No IoC Stream notifications were returned for the selected filters.")
    else:
        messages.append(
            "The stream contains a mixed set of indicator types, so triage should combine endpoint, web, and network review."
        )

    if high_risk > 0:
        messages.append("Several indicators require urgent investigation or blocking after validation.")
    else:
        messages.append(
            "No high-risk indicator was identified from available score, verdict, or enrichment context; this does not make unknown indicators safe."
        )

    if total > 0 and unknown_risk >= max(3, total // 3):
        messages.append(
            "A significant part of the stream lacks enough scoring context and should be reviewed manually."
        )
    elif unknown_risk > 0:
        messages.append("Some indicators lack scoring context and should be checked before action is taken.")
    else:
        messages.append("The returned indicators include scoring context for an initial triage view.")

    return messages[:3]


def get_collection_details(
    api_key: str,
    collection_id: str,
) -> dict[str, Any]:
    """Fetch one GTI collection and extract analyzer-friendly fields."""

    normalized_api_key = api_key.strip()
    normalized_collection_id = collection_id.strip()

    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for collection analysis.")
    if not normalized_collection_id:
        raise ValueError("A collection ID is required for collection analysis.")

    endpoint_result = _probe_json_endpoint(
        api_key=normalized_api_key,
        url=f"{VIRUSTOTAL_COLLECTIONS_URL}/{quote(normalized_collection_id, safe='')}",
        params=None,
        endpoint_name="collection_details",
    )

    payload = endpoint_result["raw_json"]
    collection_item = next(iter(_extract_api_items(payload)), {})
    analyzer_fields = _extract_collection_analyzer_fields(collection_item)

    return {
        "status_code": int(endpoint_result["http_status"]),
        "collection_id": normalized_collection_id,
        "experimental_exposure_score": _compute_gti_exposure_score(
            analyzer_fields.get("counters")
        ),
        "analysis": analyzer_fields,
        "raw_data": payload,
    }


def test_single_mitre_tree(api_key: str, collection_id: str) -> dict[str, Any]:
    """Fetch and parse one collection MITRE tree without ranking context."""

    normalized_api_key = api_key.strip()
    normalized_collection_id = collection_id.strip()

    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for MITRE tree tests.")
    if not normalized_collection_id:
        raise ValueError("A collection ID is required for MITRE tree tests.")

    result = _fetch_mitre_tree(normalized_api_key, normalized_collection_id)
    payload = result.get("raw_data", {})
    tactics = _extract_known_schema_tactics(payload)
    parsed_entries = _parse_mitre_tree_entries(payload)

    return {
        "status_code": int(result.get("status_code", 0)),
        "error_message": _extract_api_error_detail(payload),
        "top_level_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
        "data_keys": (
            sorted(payload.get("data", {}).keys())
            if isinstance(payload, dict) and isinstance(payload.get("data"), dict)
            else []
        ),
        "tactics_count": len(tactics),
        "first_tactic_sample": tactics[0] if tactics else None,
        "parsed_entries_count": len(parsed_entries),
        "first_parsed_entries": parsed_entries[:10],
        "raw_data": payload,
    }


def analyze_top_ttps(
    api_key: str,
    date_filter: str,
    top_n: int = 10,
    source: str = "search_reports",
    max_ttp_candidates: int = DEFAULT_TTP_CANDIDATES,
    ttp_query_filter: str | None = None,
    ranking_collections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build top MITRE tactics, techniques, and subtechniques from report trees."""

    normalized_source = (source or "search_reports").strip()
    if normalized_source not in {"search_reports", "ranking_collections"}:
        normalized_source = "search_reports"

    effective_max_candidates = min(
        max(_safe_int(max_ttp_candidates, DEFAULT_TTP_CANDIDATES), 1),
        MAX_TTP_CANDIDATES,
    )
    normalized_filter = " ".join((ttp_query_filter or "").split())
    ttp_query = _build_ttp_report_query(date_filter, normalized_filter)

    if normalized_source == "ranking_collections":
        candidate_ids = _extract_ttp_candidate_ids_from_ranking(
            ranking_collections or [],
            effective_max_candidates,
        )
        search_status_code = 0
        search_requests = 0
    else:
        search_result = _search_ttp_report_candidates(
            api_key=api_key,
            query=ttp_query,
            max_candidates=effective_max_candidates,
        )
        _raise_for_non_200_top_targets_result(search_result, "TTP report candidate search")
        candidate_ids = search_result["candidate_ids"]
        search_status_code = int(search_result["status_code"])
        search_requests = int(search_result["search_requests"])

    tactic_counter: dict[str, int] = {}
    tactic_display: dict[str, str] = {}
    technique_counter: dict[str, int] = {}
    technique_display: dict[str, str] = {}
    subtechnique_counter: dict[str, int] = {}
    subtechnique_display: dict[str, str] = {}

    lookups_attempted = 0
    lookups_succeeded = 0
    first_successful_collection_id = None
    first_successful_debug: dict[str, Any] = {}
    lookup_attempt_samples: list[dict[str, Any]] = []
    successful_tactics_counts: list[int] = []
    parser_failed = False

    for collection_id in candidate_ids:
        lookups_attempted += 1
        sample: dict[str, Any] = {"collection_id": collection_id}
        try:
            tree_result = _fetch_mitre_tree(api_key, collection_id)
        except GTIClientError as exc:
            sample["status_code"] = 0
            sample["error_message"] = str(exc)
            if len(lookup_attempt_samples) < 10:
                lookup_attempt_samples.append(sample)
            continue

        status_code = int(tree_result.get("status_code", 0))
        payload = tree_result.get("raw_data", {})
        tactics = _extract_known_schema_tactics(payload)
        entries = _parse_mitre_tree_entries(payload)

        sample.update(
            {
                "status_code": status_code,
                "tactics_count": len(tactics),
                "parsed_entries_count": len(entries),
                "error_message": _extract_api_error_detail(payload),
            }
        )
        if len(lookup_attempt_samples) < 10:
            lookup_attempt_samples.append(sample)

        if status_code != 200:
            continue

        lookups_succeeded += 1
        successful_tactics_counts.append(len(tactics))
        if first_successful_collection_id is None:
            first_successful_collection_id = collection_id
            first_successful_debug = {
                "status_code": status_code,
                "tactics_count": len(tactics),
                "parsed_entries_count": len(entries),
                "top_level_keys": (
                    sorted(payload.keys()) if isinstance(payload, dict) else []
                ),
                "data_keys": (
                    sorted(payload.get("data", {}).keys())
                    if isinstance(payload, dict)
                    and isinstance(payload.get("data"), dict)
                    else []
                ),
            }

        if len(tactics) > 0 and len(entries) == 0:
            parser_failed = True

        _count_mitre_entries_for_collection(
            entries,
            tactic_counter,
            tactic_display,
            technique_counter,
            technique_display,
            subtechnique_counter,
            subtechnique_display,
        )

    top_tactics = _build_ranked_collection_results(tactic_counter, tactic_display, top_n)
    top_techniques = _build_ranked_collection_results(
        technique_counter,
        technique_display,
        top_n,
    )
    top_subtechniques = _build_ranked_collection_results(
        subtechnique_counter,
        subtechnique_display,
        top_n,
    )
    all_successful_tactics_empty = (
        lookups_succeeded > 0
        and bool(successful_tactics_counts)
        and all(count == 0 for count in successful_tactics_counts)
    )

    warning_message = ""
    if parser_failed:
        warning_message = (
            "MITRE tree was returned by GTI, but parser failed to extract techniques."
        )
    elif all_successful_tactics_empty:
        warning_message = (
            "MITRE endpoint returned successfully but no tactics were exposed for selected reports."
        )

    return {
        "ttp_source": normalized_source,
        "ttp_query_used": ttp_query,
        "ttp_candidate_search_status_code": search_status_code,
        "ttp_candidate_search_requests": search_requests,
        "max_ttp_candidates": effective_max_candidates,
        "ttp_lookups_attempted": lookups_attempted,
        "ttp_lookups_succeeded": lookups_succeeded,
        "ttp_eligible_collections": len(candidate_ids),
        "ttp_first_successful_collection_id": first_successful_collection_id,
        "ttp_first_successful_debug": first_successful_debug,
        "ttp_lookup_attempt_samples": lookup_attempt_samples,
        "warning_message": warning_message,
        "top_tactics": top_tactics,
        "top_techniques": top_techniques,
        "top_subtechniques": top_subtechniques,
    }


def estimate_top_ranking_requests(
    max_collections: int,
    page_size: int = MAX_INTELLIGENCE_SEARCH_LIMIT,
    deep_lookup: bool = False,
    max_detail_lookups: int = 0,
) -> dict[str, Any]:
    """Estimate GTI API requests for the preview ranking workflow."""

    if max_collections < 1:
        raise ValueError("max_collections must be >= 1.")
    if page_size < 1:
        raise ValueError("page_size must be >= 1.")
    if max_detail_lookups < 0:
        raise ValueError("max_detail_lookups must be >= 0.")

    effective_detail_lookups = (
        min(max_detail_lookups, MAX_TOP_TARGETS_DETAIL_LOOKUPS)
        if deep_lookup
        else 0
    )
    estimated_search_pages = (max_collections + page_size - 1) // page_size

    return {
        "page_size": page_size,
        "max_collections": max_collections,
        "estimated_search_pages": estimated_search_pages,
        "search_requests": estimated_search_pages,
        "deep_lookup_enabled": deep_lookup,
        "max_detail_lookups": effective_detail_lookups,
        "detail_lookup_requests": effective_detail_lookups,
        "estimated_total_requests": estimated_search_pages + effective_detail_lookups,
        "total_requests": estimated_search_pages + effective_detail_lookups,
    }


def _build_top_targets_date_filter(
    year: int,
    month: int | None = None,
) -> tuple[str, str]:
    """Return GTI creation_date filters and a readable period label."""

    if year < 2018:
        raise ValueError("year must be >= 2018.")
    if month is not None and (month < 1 or month > 12):
        raise ValueError("month must be between 1 and 12.")

    if month is None:
        return (
            f"creation_date:{year}-01-01+ creation_date:{year}-12-31-",
            str(year),
        )

    last_day = calendar.monthrange(year, month)[1]
    month_name = calendar.month_name[month]
    return (
        f"creation_date:{year}-{month:02d}-01+ "
        f"creation_date:{year}-{month:02d}-{last_day:02d}-",
        f"{month_name} {year}",
    )


def _get_first_field(item: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    """Return the first usable field from top-level item data or attributes."""

    attributes = item.get("attributes", {})
    normalized_attributes = attributes if isinstance(attributes, dict) else {}

    for alias in aliases:
        if alias in item and _has_usable_field_value(item.get(alias)):
            return item.get(alias)
        if alias in normalized_attributes and _has_usable_field_value(
            normalized_attributes.get(alias)
        ):
            return normalized_attributes.get(alias)

    return None


def _has_usable_field_value(value: Any) -> bool:
    """Return True when a field can plausibly contain ranking data."""

    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (int, float, bool)):
        return True
    if isinstance(value, (list, tuple, set)):
        return any(_has_usable_field_value(item) for item in value)
    if isinstance(value, dict):
        return any(_has_usable_field_value(item) for item in value.values())

    return bool(value)


def aggregate_top_targets(
    api_key: str,
    start_year: int = 2024,
    end_year: int | None = None,
    month: int | None = None,
    top_n: int = 10,
    max_collections: int = DEFAULT_TOP_RANKINGS_MAX_COLLECTIONS,
    selected_rankings: list[str] | None = None,
    deep_organization_lookup: bool = False,
    max_detail_lookups: int | None = None,
    ttp_source: str = "search_reports",
    max_ttp_candidates: int = DEFAULT_TTP_CANDIDATES,
    ttp_query_filter: str | None = None,
    include_ttp_analysis: bool = False,
    include_debug: bool = False,
) -> dict[str, Any]:
    """Aggregate top targeted industries and companies from GTI Intelligence Search.

    Strategy:
    - Search GTI for collections created in the given year range
    - Extract target fields directly from each search result by default
    - Fetch collection details only when explicitly enabled and bounded
    - Return ranked lists for both industries and companies
    Paginates until next_cursor is exhausted or max_collections is reached.
    """

    normalized_api_key = api_key.strip()
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for top targets analysis.")

    effective_end_year = start_year if end_year is None else end_year
    if month is not None and end_year is not None and end_year != start_year:
        raise ValueError("month selection cannot be combined with a multi-year range.")
    if effective_end_year < start_year:
        raise ValueError("end_year must be >= start_year.")

    effective_max_collections = max_collections
    if effective_max_collections < 1:
        raise ValueError("max_collections must be >= 1.")

    normalized_rankings = [
        ranking
        for ranking in (selected_rankings or ["targeted_industries", "targeted_organizations"])
        if ranking in TOP_RANKING_KEYS
    ]
    if not normalized_rankings:
        raise ValueError("At least one ranking must be selected.")

    effective_max_detail_lookups = (
        DEFAULT_TOP_TARGETS_MAX_DETAIL_LOOKUPS
        if max_detail_lookups is None
        else max_detail_lookups
    )

    if effective_max_detail_lookups < 0:
        raise ValueError("max_detail_lookups must be >= 0.")
    if not deep_organization_lookup:
        effective_max_detail_lookups = 0
    effective_max_detail_lookups = min(
        effective_max_detail_lookups,
        MAX_TOP_TARGETS_DETAIL_LOOKUPS,
    )

    if month is None and effective_end_year != start_year:
        date_query = (
            f"creation_date:{start_year}-01-01+ "
            f"creation_date:{effective_end_year}-12-31-"
        )
        period_label = f"{start_year}-{effective_end_year}"
    else:
        date_query, period_label = _build_top_targets_date_filter(start_year, month)
    query = f"entity:collection {date_query}"
    api_request_estimate = estimate_top_ranking_requests(
        max_collections=effective_max_collections,
        page_size=MAX_INTELLIGENCE_SEARCH_LIMIT,
        deep_lookup=deep_organization_lookup,
        max_detail_lookups=effective_max_detail_lookups,
    )

    counters: dict[str, dict[str, int]] = {key: {} for key in normalized_rankings}
    display_names: dict[str, dict[str, str]] = {key: {} for key in normalized_rankings}
    collections_analyzed: list[dict[str, Any]] = []
    collections_requiring_company_details: list[dict[str, Any]] = []
    seen_collection_ids: set[str] = set()
    fields_coverage = {
        "targeted_industries": 0,
        "targeted_regions": 0,
        "source_regions": 0,
        "tags": 0,
        "collection_type": 0,
        "targeted_organizations": 0,
        "timeline": 0,
    }
    debug_attribute_keys_frequency: dict[str, int] = {}
    debug_sample_collection_fields: list[dict[str, Any]] = []
    pages_fetched = 0
    cursor: str | None = None

    while True:
        if len(seen_collection_ids) >= effective_max_collections:
            break

        search_result = intelligence_search(
            api_key=normalized_api_key,
            query=query,
            limit=MAX_INTELLIGENCE_SEARCH_LIMIT,
            cursor=cursor,
        )
        _raise_for_non_200_top_targets_result(
            search_result,
            "intelligence search",
        )
        pages_fetched += 1

        items = search_result.get("simplified_preview", [])
        for item in items:
            if len(seen_collection_ids) >= effective_max_collections:
                break

            coll_id = _stringify_value(item.get("id")) or ""
            if not coll_id or coll_id in seen_collection_ids:
                continue

            seen_collection_ids.add(coll_id)
            attributes_keys = _extract_attribute_keys(item)
            for attribute_key in attributes_keys:
                debug_attribute_keys_frequency[attribute_key] = (
                    debug_attribute_keys_frequency.get(attribute_key, 0) + 1
                )

            extracted_values = {
                "targeted_industries": _extract_names_from_field(
                    _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_industries"])
                ),
                "targeted_regions": _extract_names_from_field(
                    _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_regions"])
                ),
                "source_regions": _extract_names_from_field(
                    _get_first_field(item, TOP_RANKING_FIELD_ALIASES["source_regions"])
                ),
                "tags": _extract_names_from_field(
                    _get_first_field(item, TOP_RANKING_FIELD_ALIASES["tags"])
                ),
                "collection_type": _extract_names_from_field(
                    _get_first_field(item, TOP_RANKING_FIELD_ALIASES["collection_type"])
                ),
                "targeted_organizations": _extract_organization_names_from_preview(item),
            }
            creation_date = _get_first_field(item, ("creation_date", "created_at", "published_date"))
            timeline_value = _build_timeline_bucket(creation_date, month)

            for coverage_key, values in extracted_values.items():
                if values:
                    fields_coverage[coverage_key] += 1
            if timeline_value:
                fields_coverage["timeline"] += 1

            if len(debug_sample_collection_fields) < 5:
                debug_ranking_fields = {
                    key: values
                    for key, values in extracted_values.items()
                    if values
                }
                if timeline_value:
                    debug_ranking_fields["timeline"] = [timeline_value]
                debug_sample_collection_fields.append(
                    {
                        "id": coll_id,
                        "name": _stringify_value(item.get("name") or item.get("title")) or "",
                        "creation_date": creation_date,
                        "attributes_keys": attributes_keys,
                        "non_empty_ranking_fields": debug_ranking_fields,
                    }
                )

            for ranking_key in normalized_rankings:
                if ranking_key == "timeline":
                    values = [timeline_value] if timeline_value else []
                else:
                    values = extracted_values.get(ranking_key, [])
                _count_distinct_collection_mentions(
                    counters[ranking_key],
                    display_names[ranking_key],
                    values,
                )

            collection_metadata = {
                "id": coll_id,
                "name": _stringify_value(item.get("name") or item.get("title")) or "",
                "collection_type": _get_first_field(
                    item, TOP_RANKING_FIELD_ALIASES["collection_type"]
                ),
                "targeted_industries": _get_first_field(
                    item, TOP_RANKING_FIELD_ALIASES["targeted_industries"]
                ),
                "targeted_organizations": _get_first_field(
                    item, TOP_RANKING_FIELD_ALIASES["targeted_organizations"]
                ),
                "targeted_regions": _get_first_field(
                    item, TOP_RANKING_FIELD_ALIASES["targeted_regions"]
                ),
                "source_regions": _get_first_field(
                    item, TOP_RANKING_FIELD_ALIASES["source_regions"]
                ),
                "tags": _get_first_field(item, TOP_RANKING_FIELD_ALIASES["tags"]),
                "threat_categories": _get_first_field(
                    item,
                    ("threat_categories", "threat_category"),
                ),
                "creation_date": creation_date,
                "attributes_keys": attributes_keys,
            }
            collections_analyzed.append(collection_metadata)
            if deep_organization_lookup and not extracted_values["targeted_organizations"]:
                collections_requiring_company_details.append(collection_metadata)

        cursor = search_result.get("next_cursor")
        if not cursor or not items:
            break

    # Phase 2: only use collection details when preview organization fields were absent.
    # This keeps company counts conservative and avoids double-counting one collection.
    company_detail_lookups_attempted = 0
    company_detail_lookups_succeeded = 0
    for coll in collections_requiring_company_details[:effective_max_detail_lookups]:
        company_detail_lookups_attempted += 1
        try:
            details = get_collection_details(normalized_api_key, coll["id"])
            _raise_for_non_200_top_targets_result(
                details,
                f"collection details lookup for '{coll['id']}'",
            )
            detail_company_names = _extract_company_names_from_analysis(
                details.get("analysis", {})
            )
            if "targeted_organizations" in counters:
                _count_distinct_collection_mentions(
                    counters["targeted_organizations"],
                    display_names["targeted_organizations"],
                    detail_company_names,
                )
            company_detail_lookups_succeeded += 1
        except GTIClientError:
            continue

    rankings = {
        ranking_key: (
            _build_timeline_results(counters[ranking_key], display_names[ranking_key])
            if ranking_key == "timeline"
            else _build_ranked_collection_results(
                counters[ranking_key],
                display_names[ranking_key],
                top_n,
            )
        )
        for ranking_key in normalized_rankings
    }
    ranked_industries = rankings.get("targeted_industries", [])
    ranked_companies = rankings.get("targeted_organizations", [])
    top_companies_status = "ok" if ranked_companies else "not enough data"
    if include_ttp_analysis:
        full_ttp_result = analyze_top_ttps(
            api_key=normalized_api_key,
            date_filter=date_query,
            top_n=top_n,
            source=ttp_source,
            max_ttp_candidates=max_ttp_candidates,
            ttp_query_filter=ttp_query_filter,
            ranking_collections=collections_analyzed,
        )
        full_ttp_result["enabled"] = True
    else:
        full_ttp_result = {
            "enabled": False,
            "ttp_source": ttp_source,
            "ttp_query_used": "",
            "ttp_candidate_search_status_code": 0,
            "ttp_candidate_search_requests": 0,
            "max_ttp_candidates": 0,
            "ttp_lookups_attempted": 0,
            "ttp_lookups_succeeded": 0,
            "ttp_eligible_collections": 0,
            "warning_message": "",
            "top_tactics": [],
            "top_techniques": [],
            "top_subtechniques": [],
        }
    ttp_result = _build_public_ttp_analysis(full_ttp_result)
    combined_api_request_estimate = dict(api_request_estimate)
    if include_ttp_analysis:
        combined_api_request_estimate["ttp_candidate_search_requests"] = int(
            full_ttp_result.get("ttp_candidate_search_requests", 0)
        )
        combined_api_request_estimate["ttp_lookup_requests"] = int(
            full_ttp_result.get("max_ttp_candidates", 0)
        )
        combined_api_request_estimate["estimated_total_requests"] = (
            int(api_request_estimate.get("estimated_total_requests", 0))
            + combined_api_request_estimate["ttp_candidate_search_requests"]
            + combined_api_request_estimate["ttp_lookup_requests"]
        )
    combined_api_request_estimate["total_requests"] = combined_api_request_estimate[
        "estimated_total_requests"
    ]

    if company_detail_lookups_attempted:
        company_methodology = (
            "Companies: counted once per collection from preview organization fields, "
            "with collection details used only when preview organization data was absent "
            f"({company_detail_lookups_succeeded}/{company_detail_lookups_attempted} "
            "successful detail lookups)."
        )
    else:
        company_methodology = (
            "Companies: counted once per collection from preview organization fields; "
            "collection detail lookups are disabled unless Deep organization lookup is enabled."
        )

    result = {
        "period": period_label,
        "start_year": start_year,
        "end_year": effective_end_year,
        "month": month,
        "top_n": top_n,
        "selected_rankings": normalized_rankings,
        "collections_analyzed": len(collections_analyzed),
        "collection_preview_fields": collections_analyzed,
        "collections_seen": len(seen_collection_ids),
        "max_collections": effective_max_collections,
        "deep_organization_lookup": deep_organization_lookup,
        "max_detail_lookups": effective_max_detail_lookups,
        "api_request_estimate": combined_api_request_estimate,
        "estimated_api_requests": combined_api_request_estimate["estimated_total_requests"],
        "actual_search_requests": pages_fetched,
        "fields_coverage": fields_coverage,
        "collections_with_targeted_industries": fields_coverage["targeted_industries"],
        "collections_without_targeted_industries": len(collections_analyzed) - fields_coverage["targeted_industries"],
        "unique_industries_count": len(counters.get("targeted_industries", {})),
        "pages_fetched": pages_fetched,
        "company_detail_lookups_attempted": company_detail_lookups_attempted,
        "company_detail_lookups_succeeded": company_detail_lookups_succeeded,
        "top_industries": ranked_industries,
        "top_companies": ranked_companies,
        "top_companies_status": top_companies_status,
        "ttp_analysis": ttp_result,
        "top_tactics": ttp_result["top_tactics"],
        "top_techniques": ttp_result["top_techniques"],
        "top_subtechniques": ttp_result["top_subtechniques"],
        "rankings": rankings,
        "query_used": query,
        "methodology": (
            f"Analyzed {len(collections_analyzed)} distinct GTI collections from "
            f"{period_label}. Each industry or company is counted at most once per "
            "collection. Industries: counted from targeted_industries fields in "
            f"search results. {company_methodology}"
        ),
    }
    if include_debug:
        result["debug_attribute_keys_frequency"] = debug_attribute_keys_frequency
        result["debug_sample_collection_fields"] = debug_sample_collection_fields
        result["technical_debug"] = {
            "ranking_debug": {
                "debug_attribute_keys_frequency": debug_attribute_keys_frequency,
                "debug_sample_collection_fields": debug_sample_collection_fields,
            },
            "ttp_debug": full_ttp_result if include_ttp_analysis else ttp_result,
            "raw_samples": {
                "collection_preview_fields": collections_analyzed[:10],
                "ttp_lookup_attempt_samples": full_ttp_result.get(
                    "ttp_lookup_attempt_samples",
                    [],
                ),
            },
        }
    return result


def _extract_names_from_field(field: Any) -> list[str]:
    """Extract readable leaf names from GTI fields without stringifying raw objects."""

    if field is None:
        return []
    if isinstance(field, str):
        stripped = field.strip()
        return [stripped] if stripped else []
    if isinstance(field, bool):
        return []
    if isinstance(field, (int, float)):
        return [str(field)]
    if isinstance(field, list):
        names: list[str] = []
        for item in field:
            names.extend(_extract_names_from_field(item))
        return _dedupe_preserving_order(names)
    if isinstance(field, dict):
        names: list[str] = []
        for key in ("name", "label", "title", "value", "id"):
            if key in field:
                names.extend(_extract_names_from_field(field.get(key)))
                break

        for key, value in field.items():
            if key in ("name", "label", "title", "value", "id"):
                continue
            names.extend(_extract_names_from_field(value))
        return _dedupe_preserving_order(names)
    return []


def _build_public_ttp_analysis(ttp_result: dict[str, Any]) -> dict[str, Any]:
    """Return the compact TTP object used by the normal UI response."""

    return {
        "enabled": bool(ttp_result.get("enabled")),
        "ttp_source": str(ttp_result.get("ttp_source") or ""),
        "ttp_query_used": str(ttp_result.get("ttp_query_used") or ""),
        "ttp_lookups_attempted": _safe_int(ttp_result.get("ttp_lookups_attempted")),
        "ttp_lookups_succeeded": _safe_int(ttp_result.get("ttp_lookups_succeeded")),
        "ttp_eligible_collections": _safe_int(ttp_result.get("ttp_eligible_collections")),
        "warning_message": str(ttp_result.get("warning_message") or ""),
        "top_tactics": ttp_result.get("top_tactics", [])
        if isinstance(ttp_result.get("top_tactics"), list)
        else [],
        "top_techniques": ttp_result.get("top_techniques", [])
        if isinstance(ttp_result.get("top_techniques"), list)
        else [],
        "top_subtechniques": ttp_result.get("top_subtechniques", [])
        if isinstance(ttp_result.get("top_subtechniques"), list)
        else [],
    }


def _fetch_mitre_tree(api_key: str, collection_id: str) -> dict[str, Any]:
    """Call the GTI collection MITRE tree endpoint for one collection."""

    endpoint_result = _probe_json_endpoint(
        api_key=api_key,
        url=(
            f"{VIRUSTOTAL_COLLECTIONS_URL}/"
            f"{quote(collection_id.strip(), safe='')}/mitre_tree"
        ),
        params=None,
        endpoint_name="collection_mitre_tree",
    )

    return {
        "status_code": int(endpoint_result["http_status"]),
        "collection_id": collection_id,
        "raw_data": endpoint_result["raw_json"],
    }


def _build_ttp_report_query(date_filter: str, ttp_query_filter: str = "") -> str:
    """Build the dedicated report search query used by TTP analysis."""

    parts = ["entity:collection", "collection_type:report", date_filter.strip()]
    if ttp_query_filter.strip():
        parts.append(ttp_query_filter.strip())
    return " ".join(part for part in parts if part)


def _search_ttp_report_candidates(
    api_key: str,
    query: str,
    max_candidates: int,
) -> dict[str, Any]:
    """Search report collections specifically for MITRE tree analysis."""

    candidate_ids: list[str] = []
    seen_ids: set[str] = set()
    cursor: str | None = None
    search_requests = 0
    final_status_code = 0

    while len(candidate_ids) < max_candidates:
        search_result = intelligence_search(
            api_key=api_key,
            query=query,
            limit=min(MAX_INTELLIGENCE_SEARCH_LIMIT, max_candidates - len(candidate_ids)),
            cursor=cursor,
        )
        final_status_code = int(search_result.get("status_code", 0))
        search_requests += 1
        if final_status_code != 200:
            return {
                "status_code": final_status_code,
                "candidate_ids": candidate_ids,
                "search_requests": search_requests,
                "raw_data": search_result.get("raw_data", {}),
            }

        items = search_result.get("simplified_preview", [])
        for item in items:
            collection_id = _stringify_value(item.get("id")) or ""
            if not collection_id or collection_id in seen_ids:
                continue
            seen_ids.add(collection_id)
            candidate_ids.append(collection_id)
            if len(candidate_ids) >= max_candidates:
                break

        cursor = search_result.get("next_cursor")
        if not cursor or not items:
            break

    return {
        "status_code": final_status_code,
        "candidate_ids": candidate_ids,
        "search_requests": search_requests,
        "raw_data": {},
    }


def _extract_ttp_candidate_ids_from_ranking(
    ranking_collections: list[dict[str, Any]],
    max_candidates: int,
) -> list[str]:
    """Use already-ranked collection IDs when the advanced legacy mode is selected."""

    candidate_ids: list[str] = []
    seen_ids: set[str] = set()
    for collection in ranking_collections:
        if not isinstance(collection, dict):
            continue
        collection_id = _stringify_value(collection.get("id")) or ""
        if not collection_id or collection_id in seen_ids:
            continue
        seen_ids.add(collection_id)
        candidate_ids.append(collection_id)
        if len(candidate_ids) >= max_candidates:
            break
    return candidate_ids


def _extract_known_schema_tactics(payload: Any) -> list[dict[str, Any]]:
    """Return payload['data']['tactics'] when GTI exposes the known MITRE schema."""

    if not isinstance(payload, dict):
        return []

    data = payload.get("data")
    if not isinstance(data, dict):
        return []

    tactics = data.get("tactics")
    if not isinstance(tactics, list):
        return []

    return [tactic for tactic in tactics if isinstance(tactic, dict)]


def _parse_mitre_tree_entries(payload: Any) -> list[dict[str, str]]:
    """Parse MITRE tree techniques with a known-schema-first strategy."""

    known_entries = _parse_known_mitre_tactics(_extract_known_schema_tactics(payload))
    if known_entries:
        return known_entries

    return _parse_recursive_mitre_entries(payload)


def _parse_known_mitre_tactics(tactics: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Parse data.tactics using GTI's expected tactic/technique/subtechnique shape."""

    entries: list[dict[str, str]] = []
    for tactic in tactics:
        tactic_id = _first_string_field(
            tactic,
            ("id", "tactic_id", "external_id", "mitre_id"),
        )
        tactic_name = _first_string_field(
            tactic,
            ("name", "tactic_name", "label", "title"),
        )
        for technique in _first_list_field(
            tactic,
            ("techniques", "attack_techniques", "children"),
        ):
            if not isinstance(technique, dict):
                continue
            technique_id = _first_string_field(
                technique,
                ("id", "technique_id", "external_id", "mitre_id", "attack_id"),
            )
            technique_name = _first_string_field(
                technique,
                ("name", "technique_name", "label", "title"),
            )
            if technique_id or technique_name:
                entries.append(
                    {
                        "type": "technique",
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_name,
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "subtechnique_id": "",
                        "subtechnique_name": "",
                    }
                )

            for subtechnique in _first_list_field(
                technique,
                ("subtechniques", "sub_techniques", "children"),
            ):
                if not isinstance(subtechnique, dict):
                    continue
                subtechnique_id = _first_string_field(
                    subtechnique,
                    ("id", "technique_id", "external_id", "mitre_id", "attack_id"),
                )
                subtechnique_name = _first_string_field(
                    subtechnique,
                    ("name", "technique_name", "label", "title"),
                )
                if subtechnique_id or subtechnique_name:
                    entries.append(
                        {
                            "type": "subtechnique",
                            "tactic_id": tactic_id,
                            "tactic_name": tactic_name,
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "subtechnique_id": subtechnique_id,
                            "subtechnique_name": subtechnique_name,
                        }
                    )

    return entries


def _parse_recursive_mitre_entries(payload: Any) -> list[dict[str, str]]:
    """Fallback parser for unexpected MITRE tree shapes."""

    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def visit(node: Any, current_tactic_name: str = "", current_tactic_id: str = "") -> None:
        if isinstance(node, list):
            for child in node:
                visit(child, current_tactic_name, current_tactic_id)
            return
        if not isinstance(node, dict):
            return

        node_id = _first_string_field(
            node,
            ("id", "technique_id", "external_id", "mitre_id", "attack_id", "tactic_id"),
        )
        node_name = _first_string_field(
            node,
            ("name", "technique_name", "tactic_name", "label", "title"),
        )
        if node_id.upper().startswith("TA"):
            current_tactic_id = node_id
            current_tactic_name = node_name
        elif _looks_like_attack_technique_id(node_id):
            entry_type = "subtechnique" if "." in node_id else "technique"
            entry = {
                "type": entry_type,
                "tactic_id": current_tactic_id,
                "tactic_name": current_tactic_name,
                "technique_id": "" if entry_type == "subtechnique" else node_id,
                "technique_name": "" if entry_type == "subtechnique" else node_name,
                "subtechnique_id": node_id if entry_type == "subtechnique" else "",
                "subtechnique_name": node_name if entry_type == "subtechnique" else "",
            }
            key = (entry_type, node_id, node_name)
            if key not in seen:
                seen.add(key)
                entries.append(entry)

        for value in node.values():
            visit(value, current_tactic_name, current_tactic_id)

    visit(payload)
    return entries


def _looks_like_attack_technique_id(value: str) -> bool:
    """Return True for ATT&CK technique IDs such as T1059 or T1059.001."""

    return bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.strip(), flags=re.IGNORECASE))


def _first_string_field(item: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Return the first non-empty string-like value for a set of keys."""

    for key in keys:
        value = item.get(key)
        if isinstance(value, dict):
            nested_value = _first_string_field(
                value,
                ("id", "name", "label", "title", "value"),
            )
            if nested_value:
                return nested_value
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = str(value).strip()
            if text:
                return text
    return ""


def _first_list_field(item: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:
    """Return the first list value from a dictionary for a set of keys."""

    for key in keys:
        value = item.get(key)
        if isinstance(value, list):
            return value
    return []


def _count_mitre_entries_for_collection(
    entries: list[dict[str, str]],
    tactic_counter: dict[str, int],
    tactic_display: dict[str, str],
    technique_counter: dict[str, int],
    technique_display: dict[str, str],
    subtechnique_counter: dict[str, int],
    subtechnique_display: dict[str, str],
) -> None:
    """Count each MITRE tactic, technique, and subtechnique once per collection."""

    tactics = [
        _format_mitre_name(entry.get("tactic_id", ""), entry.get("tactic_name", ""))
        for entry in entries
    ]
    techniques = [
        _format_mitre_name(
            entry.get("technique_id", ""),
            entry.get("technique_name", ""),
        )
        for entry in entries
        if entry.get("type") == "technique"
    ]
    subtechniques = [
        _format_mitre_name(
            entry.get("subtechnique_id", ""),
            entry.get("subtechnique_name", ""),
        )
        for entry in entries
        if entry.get("type") == "subtechnique"
    ]

    _count_distinct_collection_mentions(tactic_counter, tactic_display, tactics)
    _count_distinct_collection_mentions(technique_counter, technique_display, techniques)
    _count_distinct_collection_mentions(
        subtechnique_counter,
        subtechnique_display,
        subtechniques,
    )


def _format_mitre_name(mitre_id: str, name: str) -> str:
    """Return a stable display label for MITRE rankings."""

    clean_id = " ".join((mitre_id or "").split()).strip()
    clean_name = " ".join((name or "").split()).strip()
    if clean_id and clean_name and clean_id.casefold() not in clean_name.casefold():
        return f"{clean_id} - {clean_name}"
    return clean_name or clean_id


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    """Remove duplicate readable values while keeping API order."""

    deduped_values: list[str] = []
    seen_values: set[str] = set()
    for value in values:
        normalized_value = value.casefold()
        if not normalized_value or normalized_value in seen_values:
            continue
        seen_values.add(normalized_value)
        deduped_values.append(value)

    return deduped_values


def _extract_attribute_keys(item: dict[str, Any]) -> list[str]:
    """Return attribute keys exposed by an Intelligence Search preview item."""

    raw_keys = item.get("attributes_keys")
    if isinstance(raw_keys, list):
        return sorted(str(key) for key in raw_keys)

    attributes = item.get("attributes")
    if isinstance(attributes, dict):
        return sorted(str(key) for key in attributes.keys())

    return []


def _extract_organization_names_from_preview(item: dict[str, Any]) -> list[str]:
    """Collect organization names exposed directly in Intelligence Search preview data."""

    return _extract_names_from_field(
        _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_organizations"])
    )


def _build_timeline_bucket(creation_date: Any, month: int | None) -> str | None:
    """Group creation dates by month for year mode, and by day for month mode."""

    if creation_date is None:
        return None

    if isinstance(creation_date, (int, float)) and not isinstance(creation_date, bool):
        timestamp = float(creation_date)
        if timestamp > 1_000_000_000_000:
            timestamp = timestamp / 1000
        try:
            parsed_date = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
        return parsed_date.strftime("%Y-%m-%d" if month else "%Y-%m")

    creation_date_text = str(creation_date).strip()
    if not creation_date_text:
        return None

    if re.fullmatch(r"\d+(?:\.\d+)?", creation_date_text):
        timestamp = float(creation_date_text)
        if timestamp > 1_000_000_000_000:
            timestamp = timestamp / 1000
        try:
            parsed_date = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
        return parsed_date.strftime("%Y-%m-%d" if month else "%Y-%m")

    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", creation_date_text)
    if not match:
        return None

    year_part, month_part, day_part = match.groups()
    if month is None:
        return f"{year_part}-{month_part}"

    return f"{year_part}-{month_part}-{day_part}"


def _count_distinct_collection_mentions(
    counter: dict[str, int],
    display_names: dict[str, str],
    raw_names: list[str],
) -> None:
    """Increment a ranking counter once per normalized name within one collection."""

    seen_names: set[str] = set()

    for raw_name in raw_names:
        cleaned_name = _clean_rank_name(raw_name)
        normalized_name = cleaned_name.casefold()
        if not normalized_name or normalized_name in seen_names:
            continue

        seen_names.add(normalized_name)
        display_names.setdefault(normalized_name, cleaned_name)
        counter[normalized_name] = counter.get(normalized_name, 0) + 1


def _clean_rank_name(raw_name: str) -> str:
    """Normalize spacing while keeping a human-readable display label."""

    return " ".join(raw_name.split()).strip()


def _build_ranked_collection_results(
    counter: dict[str, int],
    display_names: dict[str, str],
    top_n: int,
) -> list[dict[str, Any]]:
    """Return ranked collection counts with stable alphabetical tie-breaking."""

    ranked_items = sorted(
        counter.items(),
        key=lambda item: (-item[1], display_names[item[0]].casefold()),
    )[:top_n]

    return [
        {
            "rank": index + 1,
            "name": display_names[normalized_name],
            "collection_count": count,
            # Keep the legacy key while exposing the stricter metric name.
            "report_count": count,
        }
        for index, (normalized_name, count) in enumerate(ranked_items)
    ]


def _build_timeline_results(
    counter: dict[str, int],
    display_names: dict[str, str],
) -> list[dict[str, Any]]:
    """Return timeline buckets in chronological order."""

    return [
        {
            "rank": index + 1,
            "name": display_names[normalized_name],
            "collection_count": count,
            "report_count": count,
        }
        for index, (normalized_name, count) in enumerate(
            sorted(counter.items(), key=lambda item: display_names[item[0]])
        )
    ]


def _extract_company_names_from_analysis(analysis: Any) -> list[str]:
    """Collect organization names from analyzer fields and org aggregations."""

    if not isinstance(analysis, dict):
        return []

    names = _extract_names_from_field(analysis.get("targeted_organizations"))
    aggregations = analysis.get("aggregations") or {}
    if isinstance(aggregations, dict):
        for aggregation_key in TOP_TARGET_ORG_AGGREGATION_KEYS:
            names.extend(_extract_names_from_field(aggregations.get(aggregation_key)))

    return names


def _raise_for_non_200_top_targets_result(
    result: dict[str, Any],
    operation: str,
) -> None:
    """Turn GTI non-200 responses into explicit ranking failures."""

    status_code = _safe_int(
        result.get("status_code", result.get("http_status")),
        default=0,
    )
    if status_code in (0, 200):
        return

    payload = result.get("raw_data", result.get("raw_json"))
    error_detail = _extract_api_error_detail(payload)
    detail_suffix = f": {error_detail}" if error_detail else ""
    raise GTIClientError(
        f"VirusTotal {operation} failed with status {status_code}{detail_suffix}"
    )


def _extract_api_error_detail(payload: Any) -> str:
    """Extract a short upstream API error message when one is present."""

    if not isinstance(payload, dict):
        return ""

    error = payload.get("error")
    if isinstance(error, dict):
        for key in ("message", "code"):
            value = error.get(key)
            if value is not None:
                return str(value).strip()
    elif error:
        return str(error).strip()

    for key in ("message", "detail"):
        value = payload.get(key)
        if value is not None:
            return str(value).strip()

    return ""


def list_dtm_monitors(
    api_key: str,
    primary_domain: str | None = None,
    size: int = DEFAULT_DTM_MONITOR_PAGE_SIZE,
) -> dict[str, Any]:
    """List DTM monitors and optionally filter locally on a primary domain."""

    normalized_api_key = api_key.strip()
    normalized_primary_domain = primary_domain.strip().casefold() if primary_domain else ""
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for DTM Monitor exploration.")
    if size < 1:
        raise ValueError("The DTM monitor page size must be at least 1.")

    paginated_result = _fetch_paginated_endpoint(
        api_key=normalized_api_key,
        url=VIRUSTOTAL_DTM_MONITORS_URL,
        endpoint_name="dtm_monitors",
        initial_params={"size": size},
        max_pages=MAX_SAFE_DTM_PAGES,
    )

    all_monitors = []
    for item in paginated_result["items"]:
        attributes = item.get("attributes", {})
        normalized_attributes = attributes if isinstance(attributes, dict) else {}
        monitor_fields = _merge_item_with_attributes(item, normalized_attributes)
        all_monitors.append(
            {
                "monitor_id": _stringify_value(item.get("id")),
                "monitor_name": _stringify_value(monitor_fields.get("name")),
                "monitor_type": _stringify_value(monitor_fields.get("type")),
                "monitor_template": _stringify_value(
                    _first_present(
                        monitor_fields,
                        ("template", "template_id"),
                    )
                ),
                "created_date": _stringify_value(
                    _first_present(
                        monitor_fields,
                        ("created_date", "creation_date", "created_at"),
                    )
                ),
                "raw_json": item,
            }
        )

    monitors = [
        item
        for item in all_monitors
        if _matches_primary_domain_raw_json(item["raw_json"], normalized_primary_domain)
    ]

    return {
        "status_code": int(paginated_result["http_status"]),
        "domain_filter": normalized_primary_domain,
        "requested_size": size,
        "page_count": int(paginated_result["page_count"]),
        "truncated": bool(paginated_result["truncated"]),
        "total_collected": len(all_monitors),
        "total_monitor_count": len(all_monitors),
        "monitor_count": len(monitors),
        "monitors": monitors,
        "endpoint_results": paginated_result["endpoint_results"],
        "raw_json": paginated_result["raw_json"],
    }


def list_dtm_alerts(
    api_key: str,
    size: int = DEFAULT_DTM_ALERT_PAGE_SIZE,
    max_pages: int = MAX_SAFE_DTM_PAGES,
    monitor_id: str | None = None,
) -> dict[str, Any]:
    """List paginated DTM alerts without assuming a stable response schema."""

    normalized_api_key = api_key.strip()
    normalized_monitor_id = monitor_id.strip() if monitor_id else ""
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for DTM Alert exploration.")
    if size < 1:
        raise ValueError("The DTM alert page size must be at least 1.")
    if max_pages < 1:
        raise ValueError("The DTM alert max_pages value must be at least 1.")

    # GTI DTM alerts using refs are limited to 25 items per page.
    normalized_size = min(size, MAX_DTM_ALERT_PAGE_SIZE)

    initial_params: dict[str, Any] = {
        "size": normalized_size,
        "sort": "created_at",
        "order": "desc",
    }
    if normalized_monitor_id:
        initial_params["monitor_id"] = normalized_monitor_id

    paginated_result = _fetch_paginated_endpoint(
        api_key=normalized_api_key,
        url=VIRUSTOTAL_DTM_ALERTS_URL,
        endpoint_name="dtm_alerts",
        initial_params=initial_params,
        max_pages=max_pages,
    )

    all_alerts = []
    for item in paginated_result["items"]:
        attributes = item.get("attributes", {})
        normalized_attributes = attributes if isinstance(attributes, dict) else {}
        alert_fields = _merge_item_with_attributes(item, normalized_attributes)
        title_or_name = _extract_first_available_text(
            item,
            alert_fields,
            ("title", "summary", "name"),
        )
        monitor_context = _extract_alert_monitor_id(item, alert_fields)

        all_alerts.append(
            {
                "alert_id": _stringify_value(item.get("id")),
                "id": _stringify_value(item.get("id")),
                "type": _stringify_value(item.get("type")),
                "title_or_name": title_or_name,
                "severity": _stringify_value(alert_fields.get("severity")),
                "status": _stringify_value(alert_fields.get("status")),
                "created_at": _stringify_value(
                    _first_present(alert_fields, ("created_at", "created_date", "creation_date"))
                ),
                "updated_at": _stringify_value(
                    _first_present(alert_fields, ("updated_at", "updated_date", "modification_date"))
                ),
                "monitor_id": monitor_context,
                "alert_type_or_category": _stringify_value(
                    _first_present(
                        alert_fields,
                        ("alert_category", "alert_type", "category", "type"),
                    )
                ),
                "matched_indicator": _stringify_value(
                    _first_present(
                        alert_fields,
                        (
                            "matched_domain",
                            "matched_url",
                            "matched_email",
                            "matched_keyword",
                            "matched_asset",
                            "domain",
                            "url",
                            "email",
                            "keyword",
                        ),
                    )
                ),
                "raw_attribute_keys": sorted(
                    str(key) for key in normalized_attributes.keys()
                ),
                "raw_json": item,
            }
        )

    return {
        "status_code": int(paginated_result["http_status"]),
        "requested_size": normalized_size,
        "monitor_id": normalized_monitor_id,
        "page_count": int(paginated_result["page_count"]),
        "truncated": bool(paginated_result["truncated"]),
        "total_collected": len(all_alerts),
        "total_alert_count": len(all_alerts),
        "alert_count": len(all_alerts),
        "alerts": all_alerts,
        "simplified_preview": all_alerts,
        "endpoint_results": paginated_result["endpoint_results"],
        "raw_data": paginated_result["raw_json"],
        "raw_json": paginated_result["raw_json"],
    }


def _probe_json_endpoint(
    api_key: str,
    url: str,
    params: dict[str, Any] | None,
    endpoint_name: str,
) -> dict[str, Any]:
    """Call a JSON endpoint and return its status plus parsed payload."""

    try:
        response = requests.get(
            url,
            headers={"x-apikey": api_key},
            params=params,
            timeout=20,
        )
    except requests.RequestException as exc:
        raise GTIClientError(f"VirusTotal {endpoint_name} request failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise GTIClientError(
            f"VirusTotal returned a non-JSON response for {endpoint_name}."
        ) from exc

    return {
        "endpoint_name": endpoint_name,
        "url": url,
        "http_status": int(response.status_code),
        "response_headers": dict(response.headers),
        "raw_json": payload,
    }


def _fetch_paginated_endpoint(
    api_key: str,
    url: str,
    endpoint_name: str,
    initial_params: dict[str, Any] | None = None,
    max_pages: int = MAX_SAFE_DTM_PAGES,
) -> dict[str, Any]:
    """Fetch up to a safe number of pages using Link-header or cursor pagination."""

    endpoint_results: list[dict[str, Any]] = []
    page_payloads: list[Any] = []
    items: list[dict[str, Any]] = []
    base_params = dict(initial_params or {})
    requested_cursor: str | None = None
    next_url: str | None = url
    seen_cursors: set[str] = set()
    seen_next_urls: set[str] = set()
    final_http_status = 0
    truncated = False

    for page_number in range(1, max_pages + 1):
        if not next_url:
            break

        request_url = next_url if page_number > 1 else url
        params = None
        if page_number == 1:
            params = dict(base_params)
            if requested_cursor:
                params["cursor"] = requested_cursor

        endpoint_result = _probe_json_endpoint(
            api_key=api_key,
            url=request_url,
            params=params or None,
            endpoint_name=endpoint_name,
        )
        payload = endpoint_result["raw_json"]
        response_headers = endpoint_result.get("response_headers", {})
        next_link_url = _extract_next_link_from_headers(response_headers)
        next_cursor = _extract_next_cursor(payload)

        endpoint_result["page_number"] = page_number
        endpoint_result["request_url"] = request_url
        endpoint_result["request_params"] = params or {}
        endpoint_result["requested_cursor"] = requested_cursor
        endpoint_result["next_link_url"] = next_link_url
        endpoint_result["next_cursor"] = next_cursor
        endpoint_results.append(endpoint_result)
        page_payloads.append(payload)
        items.extend(_extract_api_items(payload))
        final_http_status = int(endpoint_result["http_status"])

        if next_link_url:
            if next_link_url in seen_next_urls:
                break
            seen_next_urls.add(next_link_url)

            if page_number == max_pages:
                truncated = True
                break

            next_url = next_link_url
            requested_cursor = _extract_cursor_from_url(next_link_url)
            continue

        if not next_cursor:
            break

        if next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)

        if page_number == max_pages:
            truncated = True
            break

        requested_cursor = next_cursor
        next_url = url

    return {
        "http_status": final_http_status,
        "page_count": len(endpoint_results),
        "truncated": truncated,
        "endpoint_results": endpoint_results,
        "items": items,
        "raw_json": {"pages": page_payloads},
    }


def _extract_api_items(payload: Any) -> list[dict[str, Any]]:
    """Extract API items without depending on a single response schema."""

    if isinstance(payload, dict):
        if "data" in payload:
            raw_data = payload.get("data", [])
        elif "monitors" in payload:
            raw_data = payload.get("monitors", [])
        elif "alerts" in payload:
            raw_data = payload.get("alerts", [])
        elif any(
            key in payload for key in ("id", "type", "attributes", "relationships")
        ):
            raw_data = payload
        else:
            raw_data = []
    elif isinstance(payload, list):
        raw_data = payload
    else:
        raw_data = []

    if isinstance(raw_data, dict):
        items = [raw_data]
    elif isinstance(raw_data, list):
        items = [item for item in raw_data if isinstance(item, dict)]
    else:
        items = []

    return items


def _merge_item_with_attributes(
    item: dict[str, Any],
    attributes: dict[str, Any],
) -> dict[str, Any]:
    """Return a flat view where top-level DTM fields are also available."""

    merged_fields = dict(attributes)
    for key, value in item.items():
        if key not in merged_fields:
            merged_fields[key] = value

    return merged_fields


def _extract_next_cursor(payload: Any) -> str | None:
    """Extract a next-page cursor when the API exposes one."""

    if not isinstance(payload, dict):
        return None

    for direct_key in ("next_cursor", "cursor", "next"):
        direct_value = payload.get(direct_key)
        if isinstance(direct_value, str) and direct_value.strip():
            return direct_value

    meta = payload.get("meta", {})
    if isinstance(meta, dict):
        for meta_key in ("next_cursor", "cursor", "next"):
            meta_value = meta.get(meta_key)
            if isinstance(meta_value, str) and meta_value.strip():
                return meta_value

    links = payload.get("links", {})
    if not isinstance(links, dict):
        return None

    next_link = links.get("next")
    if isinstance(next_link, dict):
        next_link = _first_present(next_link, ("href", "url", "link"))
    if not isinstance(next_link, str) or not next_link.strip():
        return None

    parsed_next_link = urlparse(next_link)
    cursor_values = parse_qs(parsed_next_link.query).get("cursor", [])
    if cursor_values and cursor_values[0]:
        return cursor_values[0]

    return None


def _normalize_ioc_stream_next_url(url: str | None) -> str | None:
    """Return an absolute next-page URL for IoC Stream pagination."""

    if not url:
        return None
    normalized_url = str(url).strip()
    if not normalized_url:
        return None
    return urljoin(VIRUSTOTAL_IOC_STREAM_URL, normalized_url)


def _extract_next_link_from_payload(payload: Any) -> str | None:
    """Extract a rel=next URL from a payload links object when available."""

    if not isinstance(payload, dict):
        return None
    links = payload.get("links")
    if not isinstance(links, dict):
        return None
    next_link = links.get("next")
    if isinstance(next_link, dict):
        next_link = _first_present(next_link, ("href", "url", "link"))
    if isinstance(next_link, str) and next_link.strip():
        return next_link.strip()
    return None


def _extract_next_link_from_headers(headers: Any) -> str | None:
    """Extract the rel=next URL from an HTTP Link header when present."""

    if not isinstance(headers, dict):
        return None

    link_header = None
    for header_name, header_value in headers.items():
        if str(header_name).casefold() == "link":
            link_header = str(header_value)
            break

    if not link_header:
        return None

    for link_part in link_header.split(","):
        relation_match = re.search(
            r'rel\s*=\s*"?([^";,\s]+)"?',
            link_part,
            flags=re.IGNORECASE,
        )
        if not relation_match or relation_match.group(1).casefold() != "next":
            continue
        url_match = re.search(r"<([^>]+)>", link_part)
        if url_match:
            return url_match.group(1)

    return None


def _extract_cursor_from_url(url: str) -> str | None:
    """Extract a cursor query parameter from a URL when present."""

    parsed_url = urlparse(url)
    query_values = parse_qs(parsed_url.query)
    for key, cursor_values in query_values.items():
        if key.casefold() in {"cursor", "page[cursor]", "page_cursor"}:
            if cursor_values and cursor_values[0]:
                return cursor_values[0]

    return None


def _collect_industry_snapshot_matches(
    endpoint_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect objects whose title or name contains 'Industry Snapshot'."""

    snapshots: list[dict[str, Any]] = []
    seen_ids: set[tuple[str | None, str]] = set()

    for endpoint_result in endpoint_results:
        for item in _extract_api_items(endpoint_result["raw_json"]):
            attributes = item.get("attributes", {})
            normalized_attributes = attributes if isinstance(attributes, dict) else {}
            name = _stringify_value(
                _first_present(
                    {**normalized_attributes, "item_name": item.get("name")},
                    ("name", "item_name"),
                )
            )
            title = _stringify_value(
                _first_present(
                    {**normalized_attributes, "item_title": item.get("title")},
                    ("title", "item_title"),
                )
            )

            if not _contains_industry_snapshot(name, title):
                continue

            dedupe_key = (_stringify_value(item.get("id")), endpoint_result["endpoint_name"])
            if dedupe_key in seen_ids:
                continue
            seen_ids.add(dedupe_key)

            snapshots.append(
                {
                    "id": _stringify_value(item.get("id")),
                    "type": _stringify_value(item.get("type")),
                    "endpoint_name": endpoint_result["endpoint_name"],
                    "name": name,
                    "title": title,
                    "published_date": _stringify_value(
                        _first_present(
                            normalized_attributes,
                            ("published_date", "publication_date"),
                        )
                    ),
                    "targeted_industries": _normalize_collection_field(
                        _first_present(
                            normalized_attributes,
                            ("targeted_industries", "targeted_industries_free"),
                        )
                    ),
                    "targeted_regions": _normalize_collection_field(
                        _first_present(
                            normalized_attributes,
                            ("targeted_regions", "targeted_regions_hierarchy"),
                        )
                    ),
                    "source_regions": _normalize_collection_field(
                        _first_present(
                            normalized_attributes,
                            ("source_regions", "source_regions_hierarchy"),
                        )
                    ),
                    "summary_or_description": _stringify_value(
                        _first_present(
                            normalized_attributes,
                            ("summary", "description"),
                        )
                    ),
                    "raw_json": item,
                }
            )

    return snapshots


def _simplify_intelligence_search_item(item: dict[str, Any]) -> dict[str, Any]:
    """Keep only explicitly requested intelligence-search preview fields."""

    attributes = item.get("attributes", {})
    normalized_attributes = attributes if isinstance(attributes, dict) else {}
    normalized_type = _stringify_value(
        _extract_exact_field(item, normalized_attributes, "type")
    )

    base_preview = {
        "id": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "id")
        ),
        "type": _normalize_collection_field(normalized_type),
    }

    if normalized_type and normalized_type.casefold() == "file":
        return {
            **base_preview,
            "meaningful_name": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "meaningful_name")
            ),
            "reputation": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "reputation")
            ),
            "last_analysis_stats": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "last_analysis_stats")
            ),
        }

    if normalized_type and normalized_type.casefold() == "collection":
        return {
            **base_preview,
            "name": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "name")
            ),
            "title": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "title")
            ),
            "collection_type": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["collection_type"])
            ),
            "creation_date": _normalize_collection_field(
                _get_first_field(item, ("creation_date", "created_at", "published_date"))
            ),
            "targeted_industries": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_industries"])
            ),
            "targeted_organizations": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_organizations"])
            ),
            "affected_organizations": _normalize_collection_field(
                _get_first_field(item, ("affected_organizations",))
            ),
            "victim_organizations": _normalize_collection_field(
                _get_first_field(item, ("victim_organizations",))
            ),
            "organizations": _normalize_collection_field(
                _get_first_field(item, ("organizations",))
            ),
            "victims": _normalize_collection_field(
                _get_first_field(item, ("victims",))
            ),
            "companies": _normalize_collection_field(
                _get_first_field(item, ("companies",))
            ),
            "targeted_regions": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["targeted_regions"])
            ),
            "source_regions": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["source_regions"])
            ),
            "tags": _normalize_collection_field(
                _get_first_field(item, TOP_RANKING_FIELD_ALIASES["tags"])
            ),
            "attributes_keys": sorted(str(key) for key in normalized_attributes.keys()),
        }

    return {
        **base_preview,
        "name": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "name")
        ),
        "title": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "title")
        ),
        "meaningful_name": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "meaningful_name")
        ),
        "attributes_keys": sorted(str(key) for key in normalized_attributes.keys()),
    }


def _extract_collection_analyzer_fields(item: dict[str, Any]) -> dict[str, Any]:
    """Return the requested Industry Profile Analyzer fields for one collection."""

    attributes = item.get("attributes", {})
    normalized_attributes = attributes if isinstance(attributes, dict) else {}

    return {
        "name": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "name")
        ),
        "collection_type": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "collection_type")
        ),
        "osint_summary": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "osint_summary")
        ),
        "recent_activity_summary": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "recent_activity_summary")
        ),
        "counters": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "counters")
        ),
        "aggregations": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "aggregations")
        ),
        "profile_stats": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "profile_stats")
        ),
        "targeted_industries": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "targeted_industries")
        ),
        "targeted_organizations": _normalize_collection_field(
            _first_present(normalized_attributes, (
                "targeted_organizations",
                "affected_organizations",
                "victim_organizations",
                "organizations",
                "victims",
            ))
        ),
        "targeted_regions": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "targeted_regions")
        ),
        "source_region": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "source_region")
        ),
        "source_regions_hierarchy": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "source_regions_hierarchy")
        ),
        "malware_roles": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "malware_roles")
        ),
        "motivations": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "motivations")
        ),
        "merged_actors": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "merged_actors")
        ),
        "threat_activity_drivers": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "threat_activity_drivers")
        ),
        "collection_links": _normalize_collection_field(
            _extract_exact_field(item, normalized_attributes, "collection_links")
        ),
    }


def _extract_monitor_context(
    item: dict[str, Any],
    attributes: dict[str, Any],
) -> str | None:
    """Return a monitor name or id if one is exposed in the alert payload."""

    direct_value = _first_present(attributes, ("monitor_name", "monitor_id"))
    if direct_value is not None:
        return _stringify_value(direct_value)

    relationships = item.get("relationships", {})
    if not isinstance(relationships, dict):
        return None

    monitor_relationship = relationships.get("monitor")
    if not isinstance(monitor_relationship, dict):
        return None

    monitor_data = monitor_relationship.get("data")
    if isinstance(monitor_data, dict):
        return _stringify_value(monitor_data.get("id"))
    if isinstance(monitor_data, list):
        for candidate in monitor_data:
            if isinstance(candidate, dict) and candidate.get("id") is not None:
                return _stringify_value(candidate.get("id"))

    return None


def _extract_alert_monitor_id(
    item: dict[str, Any],
    attributes: dict[str, Any],
) -> str | None:
    """Return the monitor identifier exposed by an alert payload when present."""

    direct_value = _first_present(
        attributes,
        ("monitor_id", "monitor", "source_monitor_id"),
    )
    if direct_value is not None:
        return _stringify_value(direct_value)

    relationships = item.get("relationships", {})
    if not isinstance(relationships, dict):
        return None

    monitor_relationship = relationships.get("monitor")
    if not isinstance(monitor_relationship, dict):
        return None

    monitor_data = monitor_relationship.get("data")
    if isinstance(monitor_data, dict):
        return _stringify_value(monitor_data.get("id"))

    if isinstance(monitor_data, list):
        for candidate in monitor_data:
            if isinstance(candidate, dict) and candidate.get("id") is not None:
                return _stringify_value(candidate.get("id"))

    return None


def _extract_name_or_title(
    item: dict[str, Any],
    attributes: dict[str, Any],
) -> str | None:
    """Return a human-readable collection label when one is present."""

    for candidate in (
        item.get("name"),
        item.get("title"),
        attributes.get("name"),
        attributes.get("title"),
    ):
        if candidate is None:
            continue
        return str(candidate)

    return None


def _extract_first_available_text(
    item: dict[str, Any],
    attributes: dict[str, Any],
    keys: tuple[str, ...],
) -> str | None:
    """Return the first present text value from top-level or attributes."""

    for key in keys:
        for candidate in (item.get(key), attributes.get(key)):
            if candidate is None:
                continue
            return str(candidate)

    return None


def _contains_industry_snapshot(name: str | None, title: str | None) -> bool:
    """Return True when the name or title contains 'Industry Snapshot'."""

    for candidate in (name, title):
        if candidate and "industry snapshot" in candidate.casefold():
            return True

    return False


def _first_present(attributes: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Return the first present attribute value for the provided keys."""

    for key in keys:
        if key in attributes:
            return attributes.get(key)

    return None


def _extract_exact_field(
    item: dict[str, Any],
    attributes: dict[str, Any],
    key: str,
) -> Any:
    """Return an exact top-level or attributes field without schema guessing."""

    if key in item:
        return item.get(key)
    if key in attributes:
        return attributes.get(key)

    return None


def _normalize_collection_field(value: Any) -> Any:
    """Keep simple API values as-is while making complex types renderable."""

    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [
            _normalize_collection_field(item)
            for item in value
        ]
    if isinstance(value, dict):
        return {str(key): _normalize_collection_field(item) for key, item in value.items()}

    return str(value)


def _compute_gti_exposure_score(counters: Any) -> int:
    """Compute the experimental score from GTI counter fields when present."""

    if not isinstance(counters, dict):
        return 0

    return sum(
        _safe_int(counters.get(counter_name))
        for counter_name in (
            "domains_count",
            "urls_count",
            "ip_addresses_count",
            "files_count",
            "references_count",
        )
    )


def _matches_primary_domain_raw_json(raw_item: Any, normalized_primary_domain: str) -> bool:
    """Return True when no domain filter is set or the raw JSON contains it."""

    if not normalized_primary_domain:
        return True

    try:
        serialized_item = json.dumps(raw_item, sort_keys=True, default=str)
    except TypeError:
        serialized_item = str(raw_item)

    return normalized_primary_domain in serialized_item.casefold()


def _stringify_value(value: Any) -> str | None:
    """Convert a value to string only when it is present."""

    if value is None:
        return None

    return str(value)


def _normalize_ioc_stream_choice(
    value: str,
    allowed_values: set[str],
    field_name: str,
) -> str:
    normalized_value = (value or "all").strip().casefold()
    if normalized_value not in allowed_values:
        allowed_display = ", ".join(sorted(allowed_values))
        raise ValueError(f"Invalid {field_name}. Allowed values: {allowed_display}.")
    return normalized_value


def _normalize_ioc_stream_date(value: str | None, field_name: str) -> str | None:
    normalized_value = (value or "").strip()
    if not normalized_value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", normalized_value):
        raise ValueError(f"Invalid {field_name}. Expected YYYY-MM-DD.")
    return normalized_value


def _filter_mock_ioc_stream_payload(
    payload: dict[str, Any],
    entity_type: str,
    origin: str,
    pages_to_fetch: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    items = []
    for item in _extract_api_items(payload):
        normalized_item = normalize_ioc_stream_item(item)
        if entity_type != "all" and normalized_item["entity_type"] != entity_type:
            continue
        if origin != "all" and normalized_item["origin"].casefold() != origin:
            continue
        items.append(item)

    collection_metadata = _build_ioc_stream_collection_metadata(
        items=items,
        pages_fetched=1,
        requested_pages=pages_to_fetch,
        page_size=IOC_STREAM_API_PAGE_LIMIT,
        stopped_reason="no_more_pages",
    )
    return {"data": items, "links": payload.get("links", {})}, collection_metadata


def _extract_ioc_item_datetime(item: dict[str, Any]) -> datetime | None:
    attributes = item.get("attributes", {})
    normalized_attributes = attributes if isinstance(attributes, dict) else {}
    fields = _merge_item_with_attributes(item, normalized_attributes)
    value = _first_present(
        fields,
        (
            "matched_date",
            "notification_date",
            "created_at",
            "creation_date",
            "date",
            "last_modification_date",
        ),
    )
    return _parse_ioc_stream_datetime(value)


def _parse_ioc_stream_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000:
            timestamp = timestamp / 1000
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return _parse_ioc_stream_datetime(float(text))
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text = f"{text}T00:00:00+00:00"
    elif text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_ioc_stream_collection_metadata(
    items: list[dict[str, Any]],
    pages_fetched: int,
    requested_pages: int,
    page_size: int,
    stopped_reason: str,
) -> dict[str, Any]:
    timestamps = [
        item_datetime
        for item_datetime in (_extract_ioc_item_datetime(item) for item in items)
        if item_datetime is not None
    ]
    earliest_timestamp = min(timestamps).isoformat() if timestamps else None
    latest_timestamp = max(timestamps).isoformat() if timestamps else None
    return {
        "total_collected": len(items),
        "raw_ioc_count": len(items),
        "total_enriched": 0,
        "requested_pages": requested_pages,
        "pages_fetched": pages_fetched,
        "page_size": page_size,
        "earliest_timestamp": earliest_timestamp,
        "latest_timestamp": latest_timestamp,
        "stopped_reason": stopped_reason,
    }


def _normalize_ioc_entity_type(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("-", "_")
    aliases = {
        "ip": "ip_address",
        "ip-address": "ip_address",
        "ipaddress": "ip_address",
        "ipv4": "ip_address",
        "ipv6": "ip_address",
        "hash": "file",
        "file_hash": "file",
    }
    return aliases.get(text, text or "Unknown")


def _extract_ioc_value(
    item: dict[str, Any],
    attributes: dict[str, Any],
    entity_type: str,
) -> str:
    candidate_keys = (
        "value",
        "indicator",
        "ioc",
        "entity_id",
        entity_type,
        "url",
        "domain",
        "ip_address",
        "sha256",
        "sha1",
        "md5",
        "meaningful_name",
    )
    for source in (attributes, item):
        value = _first_present(source, candidate_keys)
        text = _stringify_value(value)
        if text and text.strip():
            return text.strip()

    item_id = _stringify_value(item.get("id"))
    return item_id.strip() if item_id else "Unknown"


def _extract_ioc_source_type(
    fields: dict[str, Any],
    relationships: dict[str, Any],
) -> str:
    direct_value = _first_present(
        fields,
        (
            "source_type",
            "source_kind",
            "source_entity_type",
            "collection_type",
            "ruleset_type",
        ),
    )
    text = _readable_ioc_value(direct_value)
    if text:
        return text

    for relationship_name, relationship_value in relationships.items():
        relationship_type = _extract_relationship_type(relationship_value)
        if relationship_type:
            return relationship_type
        if relationship_name:
            return str(relationship_name)

    return "Unknown"


def _extract_ioc_source_name(
    fields: dict[str, Any],
    relationships: dict[str, Any],
) -> str:
    direct_value = _first_present(
        fields,
        (
            "source_name",
            "source_title",
            "collection_name",
            "collection_title",
            "ruleset_name",
            "rule_name",
            "actor_name",
            "name",
            "title",
        ),
    )
    text = _readable_ioc_value(direct_value)
    if text:
        return text

    for relationship_value in relationships.values():
        relationship_name = _extract_relationship_name(relationship_value)
        if relationship_name:
            return relationship_name

    return "Unknown"


def _extract_relationship_type(value: Any) -> str | None:
    if isinstance(value, dict):
        data = value.get("data")
        if isinstance(data, dict):
            return _readable_ioc_value(data.get("type"))
        if isinstance(data, list) and data:
            return _extract_relationship_type({"data": data[0]})
        return _readable_ioc_value(value.get("type"))
    return None


def _extract_relationship_name(value: Any) -> str | None:
    if isinstance(value, dict):
        data = value.get("data")
        if isinstance(data, dict):
            return _readable_ioc_value(
                _first_present(data, ("name", "title", "id", "label"))
            )
        if isinstance(data, list) and data:
            return _extract_relationship_name({"data": data[0]})
        return _readable_ioc_value(
            _first_present(value, ("name", "title", "id", "label"))
        )
    return None


def _extract_ioc_score(fields: dict[str, Any]) -> int | float | None:
    direct_score = _first_present(
        fields,
        (
            "gti_score",
            "score",
            "threat_score",
            "risk_score",
            "maliciousness_score",
        ),
    )
    score = _coerce_ioc_number(direct_score)
    if score is not None:
        return score

    assessment = fields.get("gti_assessment")
    if isinstance(assessment, dict):
        for key in ("score", "gti_score", "threat_score", "risk_score"):
            score = _coerce_ioc_number(assessment.get(key))
            if score is not None:
                return score

    return None


def _extract_ioc_verdict(fields: dict[str, Any]) -> str:
    direct_value = _first_present(
        fields,
        (
            "gti_verdict",
            "verdict",
            "assessment_verdict",
            "maliciousness",
            "classification",
        ),
    )
    text = _readable_ioc_value(direct_value)
    if text:
        return text

    assessment = fields.get("gti_assessment")
    if isinstance(assessment, dict):
        text = _readable_ioc_value(
            _first_present(
                assessment,
                ("verdict", "gti_verdict", "assessment_verdict", "classification"),
            )
        )
        if text:
            return text

    return "Unknown"


def _fetch_ioc_enrichment(
    api_key: str,
    entity_type: str,
    value: str,
) -> dict[str, Any]:
    lookup_url = _build_ioc_enrichment_url(entity_type, value)
    if not lookup_url:
        return {
            "status": "unsupported",
            "http_status": None,
            "error": f"Unsupported IoC type for enrichment: {entity_type}.",
        }

    endpoint_result = _probe_json_endpoint(
        api_key=api_key.strip(),
        url=lookup_url,
        params=None,
        endpoint_name=f"ioc_enrichment_{entity_type}",
    )
    http_status = int(endpoint_result.get("http_status", 0))
    if http_status != 200:
        return {
            "status": "rate_limited" if http_status == 429 else "error",
            "http_status": http_status,
            "error": _extract_api_error_detail(endpoint_result.get("raw_json")),
        }

    attributes = _extract_ioc_enrichment_attributes(endpoint_result.get("raw_json"))
    stats = attributes.get("last_analysis_stats")
    normalized_stats = stats if isinstance(stats, dict) else {}
    reputation = _coerce_ioc_number(attributes.get("reputation"))
    return {
        "status": "success",
        "http_status": http_status,
        "malicious": _safe_int(normalized_stats.get("malicious")),
        "suspicious": _safe_int(normalized_stats.get("suspicious")),
        "reputation": reputation,
        "has_risk_context": bool(normalized_stats) or reputation is not None,
    }


def _build_ioc_enrichment_url(entity_type: str, value: str) -> str | None:
    normalized_type = _normalize_ioc_entity_type(entity_type)
    if normalized_type == "domain":
        return VIRUSTOTAL_DOMAIN_LOOKUP_URL.format(quote(value, safe=""))
    if normalized_type == "ip_address":
        return VIRUSTOTAL_IP_ADDRESS_LOOKUP_URL.format(quote(value, safe=""))
    if normalized_type == "url":
        encoded_url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        return VIRUSTOTAL_URL_LOOKUP_URL.format(encoded_url_id)
    if normalized_type == "file":
        return VIRUSTOTAL_FILE_LOOKUP_URL.format(quote(value, safe=""))
    return None


def _extract_ioc_enrichment_attributes(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _build_mock_ioc_enrichment(indicator: dict[str, Any]) -> dict[str, Any]:
    severity = str(indicator.get("severity") or "Unknown")
    if severity == "High":
        malicious, suspicious, reputation = 7, 1, -45
    elif severity == "Medium":
        malicious, suspicious, reputation = 0, 4, -12
    elif severity == "Low":
        malicious, suspicious, reputation = 0, 0, -2
    else:
        malicious, suspicious, reputation = 0, 0, None
    return {
        "status": "success",
        "http_status": 200,
        "malicious": malicious,
        "suspicious": suspicious,
        "reputation": reputation,
        "has_risk_context": severity != "Unknown" or reputation is not None,
    }


def _build_enriched_ioc_explanation(
    indicator: dict[str, Any],
    malicious: int,
    suspicious: int,
    reputation: int | float | None,
    risk: str,
) -> str:
    reputation_text = "not returned" if reputation is None else str(reputation)
    return (
        f"{indicator.get('entity_type', 'Unknown')} indicator enriched with "
        f"{malicious} malicious and {suspicious} suspicious vendor result(s); "
        f"reputation {reputation_text}. Classified as {risk}."
    )


def _coerce_ioc_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
        return int(number) if number.is_integer() else number
    return None


def _readable_ioc_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        nested_value = _first_present(
            value,
            ("name", "title", "label", "value", "id", "type"),
        )
        return _readable_ioc_value(nested_value)
    if isinstance(value, list):
        for item in value:
            text = _readable_ioc_value(item)
            if text:
                return text
        return None
    text = str(value).strip()
    return text or None


def _build_ioc_explanation(
    entity_type: str,
    severity: str,
    source_type: str,
    verdict: str,
    score: int | float | None,
) -> str:
    score_text = "no GTI score" if score is None else f"GTI score {score}"
    verdict_text = verdict if verdict and verdict != "Unknown" else "no explicit verdict"
    return (
        f"{entity_type} indicator from {source_type}; {score_text} and "
        f"{verdict_text}. Classified as {severity} for initial triage."
    )


def _count_ioc_field(
    indicators: list[dict[str, Any]],
    field_name: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for indicator in indicators:
        label = str(indicator.get(field_name) or "Unknown")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _main_ioc_bucket(counts: dict[str, int]) -> str:
    if not counts:
        return "Unknown"
    return sorted(counts.items(), key=lambda item: (-item[1], item[0].casefold()))[0][0]


def _counter_to_chart_rows(
    counts: dict[str, int],
    preferred_order: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    order_index = {label: index for index, label in enumerate(preferred_order)}
    return [
        {"label": label, "value": count}
        for label, count in sorted(
            counts.items(),
            key=lambda item: (
                order_index.get(item[0], len(order_index)),
                -item[1],
                item[0].casefold(),
            ),
        )
    ]


def _percentage(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((part / total) * 100, 1)


def _normalized_ioc_type_bucket(value: Any) -> str:
    normalized_type = _normalize_ioc_entity_type(value)
    return (
        normalized_type
        if normalized_type in {"domain", "url", "file", "ip_address"}
        else "others"
    )


def _build_ioc_type_risk_rows(
    enriched_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for indicator in enriched_indicators:
        entity_type = _normalized_ioc_type_bucket(indicator.get("entity_type"))
        grouped.setdefault(entity_type, []).append(indicator)

    rows: list[dict[str, Any]] = []
    for entity_type, items in grouped.items():
        scores = [
            score
            for score in (_coerce_ioc_number(item.get("gti_score")) for item in items)
            if score is not None
        ]
        malicious_count = sum(
            1 for item in items if _safe_int(item.get("malicious")) > 0
        )
        suspicious_count = sum(
            1 for item in items if _safe_int(item.get("suspicious")) > 0
        )
        average_score = (
            round(sum(float(score) for score in scores) / len(scores), 1)
            if scores
            else None
        )
        rows.append(
            {
                "ioc_type": entity_type,
                "total_count": len(items),
                "average_risk_score": average_score,
                "malicious_indicator_count": malicious_count,
                "suspicious_indicator_count": suspicious_count,
                "malicious_percentage": _percentage(malicious_count, len(items)),
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            -(row["average_risk_score"] if row["average_risk_score"] is not None else -1),
            -row["malicious_percentage"],
            -row["total_count"],
            row["ioc_type"],
        ),
    )


def _build_top_dangerous_ioc_rows(
    enriched_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    def sort_key(indicator: dict[str, Any]) -> tuple[Any, ...]:
        reputation = _coerce_ioc_number(indicator.get("reputation"))
        return (
            -_safe_int(indicator.get("malicious")),
            -_safe_int(indicator.get("suspicious")),
            reputation is None,
            reputation if reputation is not None else 0,
            str(indicator.get("value") or "").casefold(),
        )

    return [
        {
            "indicator": indicator.get("value"),
            "type": indicator.get("entity_type"),
            "malicious": _safe_int(indicator.get("malicious")),
            "suspicious": _safe_int(indicator.get("suspicious")),
            "reputation": _coerce_ioc_number(indicator.get("reputation")),
            "recommended_action": indicator.get("recommended_action"),
        }
        for indicator in sorted(enriched_indicators, key=sort_key)[:10]
    ]


def _build_distribution_rows(
    counts: dict[str, int],
    total: int,
    preferred_order: tuple[str, ...],
) -> list[dict[str, Any]]:
    return [
        {
            "label": label,
            "count": counts.get(label, 0),
            "value": counts.get(label, 0),
            "percentage": _percentage(counts.get(label, 0), total),
        }
        for label in preferred_order
    ]


def _build_risk_distribution_rows(
    enriched_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts = {label: 0 for label in ("High", "Medium", "Low", "Unknown")}
    for indicator in enriched_indicators:
        risk = str(indicator.get("severity") or "Unknown")
        counts[risk if risk in counts else "Unknown"] += 1
    return _build_distribution_rows(
        counts,
        len(enriched_indicators),
        ("High", "Medium", "Low", "Unknown"),
    )


def _build_ioc_type_distribution_rows(
    enriched_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts = {label: 0 for label in ("domain", "url", "file", "ip_address", "others")}
    for indicator in enriched_indicators:
        counts[_normalized_ioc_type_bucket(indicator.get("entity_type"))] += 1
    return _build_distribution_rows(
        counts,
        len(enriched_indicators),
        ("domain", "url", "file", "ip_address", "others"),
    )


def _recommended_action_bucket(action: Any) -> str:
    normalized_action = str(action or "").casefold()
    if "escalate" in normalized_action:
        return "Escalate"
    if "block" in normalized_action:
        return "Block"
    if "investigate" in normalized_action:
        return "Investigate"
    if "manual" in normalized_action:
        return "Manual Review"
    if "monitor" in normalized_action:
        return "Monitor"
    return "Manual Review"


def _build_recommended_action_distribution_rows(
    enriched_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    labels = ("Block", "Monitor", "Investigate", "Manual Review", "Escalate")
    counts = {label: 0 for label in labels}
    for indicator in enriched_indicators:
        counts[_recommended_action_bucket(indicator.get("recommended_action"))] += 1
    return _build_distribution_rows(counts, len(enriched_indicators), labels)


def _build_ioc_business_insights(
    enriched_indicators: list[dict[str, Any]],
) -> list[str]:
    if not enriched_indicators:
        return [
            "No successfully enriched IoCs are available for analyst cross-analysis.",
            "Risk distribution cannot be computed until enrichment succeeds.",
            "Manual review should focus on indicators where enrichment failed or returned no risk context.",
        ]

    type_risk_rows = _build_ioc_type_risk_rows(enriched_indicators)
    type_distribution = _build_ioc_type_distribution_rows(enriched_indicators)
    risk_distribution = _build_risk_distribution_rows(enriched_indicators)
    action_distribution = _build_recommended_action_distribution_rows(enriched_indicators)
    dangerous_rows = _build_top_dangerous_ioc_rows(enriched_indicators)
    insights: list[str] = []

    highest_score_row = next(
        (row for row in type_risk_rows if row["average_risk_score"] is not None),
        None,
    )
    if highest_score_row:
        insights.append(
            f"{highest_score_row['ioc_type']} indicators carry the highest average GTI score "
            f"({highest_score_row['average_risk_score']})."
        )
    elif type_risk_rows:
        highest_malicious_row = sorted(
            type_risk_rows,
            key=lambda row: (-row["malicious_percentage"], -row["total_count"], row["ioc_type"]),
        )[0]
        insights.append(
            f"{highest_malicious_row['ioc_type']} indicators have the highest malicious detection rate "
            f"({highest_malicious_row['malicious_percentage']}%)."
        )

    dominant_type = sorted(
        type_distribution,
        key=lambda row: (-row["count"], row["label"]),
    )[0]
    risk_leader = type_risk_rows[0] if type_risk_rows else None
    if risk_leader and dominant_type["label"] != risk_leader["ioc_type"]:
        insights.append(
            f"{dominant_type['label']} indicators dominate total enriched volume, "
            f"but {risk_leader['ioc_type']} indicators carry stronger risk signals."
        )
    else:
        insights.append(
            f"{dominant_type['label']} indicators dominate the enriched IoC volume."
        )

    unknown_row = next(
        row for row in risk_distribution if row["label"] == "Unknown"
    )
    if unknown_row["count"] > 0:
        insights.append(
            "Manual review should focus on unknown indicators where enrichment returned no usable risk context."
        )
    else:
        insights.append(
            "All successfully enriched indicators have enough context for an initial risk bucket."
        )

    top_dangerous = dangerous_rows[0] if dangerous_rows else None
    if top_dangerous and top_dangerous["malicious"] > 0:
        insights.append(
            f"The most dangerous enriched indicator is {top_dangerous['indicator']} "
            f"with {top_dangerous['malicious']} malicious detection(s)."
        )
    else:
        insights.append(
            "No successfully enriched indicator has malicious vendor detections in this result set."
        )

    leading_action = sorted(
        action_distribution,
        key=lambda row: (-row["count"], row["label"]),
    )[0]
    if leading_action["count"] > 0:
        insights.append(
            f"The most common recommended action is {leading_action['label']} "
            f"for {leading_action['count']} enriched indicator(s)."
        )

    return insights[:5]


def get_top_industries(
    api_key: str,
    year: int = 2024,
    top_n: int = 10,
    target: str | None = None,
    max_collections: int | None = None,
) -> dict[str, Any]:
    """Aggregate top targeted industries for a year via GTI Intelligence Search."""

    normalized_api_key = api_key.strip()
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for industry ranking.")

    normalized_target = target.strip() if target else None
    date_filter = f"creation_date:{year}-01-01+ creation_date:{year}-12-31-"
    query = (
        f"entity:collection {normalized_target} {date_filter}"
        if normalized_target
        else f"entity:collection {date_filter}"
    )

    industry_counter: dict[str, int] = {}
    industry_display_names: dict[str, str] = {}
    seen_collection_ids: set[str] = set()
    collections_with_industries = 0
    collections_without_industries = 0
    pages_fetched = 0
    cursor: str | None = None

    while True:
        if max_collections is not None and len(seen_collection_ids) >= max_collections:
            break

        search_result = intelligence_search(
            api_key=normalized_api_key,
            query=query,
            limit=MAX_INTELLIGENCE_SEARCH_LIMIT,
            cursor=cursor,
        )
        if _safe_int(search_result.get("status_code")) not in (0, 200):
            break
        pages_fetched += 1

        items = search_result.get("simplified_preview", [])
        for item in items:
            if max_collections is not None and len(seen_collection_ids) >= max_collections:
                break

            coll_id = _stringify_value(item.get("id")) or ""
            if not coll_id or coll_id in seen_collection_ids:
                continue
            seen_collection_ids.add(coll_id)
            industries = _extract_names_from_field(item.get("targeted_industries"))
            _count_distinct_collection_mentions(
                industry_counter,
                industry_display_names,
                industries,
            )
            if industries:
                collections_with_industries += 1
            else:
                collections_without_industries += 1

        cursor = search_result.get("next_cursor")
        if not cursor or not items:
            break

    return {
        "year": year,
        "source": "search",
        "collections_seen": len(seen_collection_ids),
        "collections_with_targeted_industries": collections_with_industries,
        "collections_without_targeted_industries": collections_without_industries,
        "unique_industries_count": len(industry_counter),
        "pages_fetched": pages_fetched,
        "data": _build_ranked_collection_results(
            industry_counter, industry_display_names, top_n
        ),
    }


def get_top_companies(
    api_key: str,
    year: int = 2024,
    top_n: int = 10,
    target: str | None = None,
    max_pages: int = 3,
) -> dict[str, Any]:
    """Aggregate top targeted companies using DTM → Search → Actors fallback chain."""

    normalized_api_key = api_key.strip()
    if not normalized_api_key:
        raise ValueError("A GTI/VirusTotal API key is required for company ranking.")

    normalized_target = target.strip() if target else None

    # Attempt 1: DTM events
    try:
        dtm_companies = _fetch_companies_from_dtm(normalized_api_key, normalized_target)
        if dtm_companies is not None:
            print(f"[companies] Source: DTM ({len(dtm_companies)} entries before slice)")
            return {"year": year, "source": "dtm", "data": dtm_companies[:top_n]}
    except Exception as exc:
        print(f"[companies] DTM attempt skipped: {exc}")

    # Attempt 2: Intelligence Search
    try:
        search_companies = _fetch_companies_from_search(
            normalized_api_key, year, normalized_target, top_n, max_pages
        )
        if search_companies is not None:
            print(f"[companies] Source: Search ({len(search_companies)} entries)")
            return {"year": year, "source": "search", "data": search_companies}
    except Exception as exc:
        print(f"[companies] Search attempt skipped: {exc}")

    # Attempt 3: Actors fallback — reuse aggregate_top_targets and extract companies
    print("[companies] Source: Actors fallback")
    fallback = aggregate_top_targets(
        api_key=normalized_api_key,
        start_year=year,
        top_n=top_n,
        max_collections=max_pages * MAX_INTELLIGENCE_SEARCH_LIMIT,
    )
    return {
        "year": year,
        "source": "actors",
        "data": fallback.get("top_companies", []),
    }


def _fetch_companies_from_dtm(
    api_key: str,
    target: str | None,
) -> list[dict[str, Any]] | None:
    """Query DTM events endpoint for company names. Returns None on 403/404 or empty result."""

    params: dict[str, Any] = {"limit": 40}
    if target:
        params["query"] = target

    result = _probe_json_endpoint(
        api_key=api_key,
        url=VIRUSTOTAL_DTM_EVENTS_URL,
        params=params,
        endpoint_name="dtm_events",
    )

    status = int(result["http_status"])
    if status in (403, 404):
        print(f"[companies] DTM events HTTP {status} — plan insufficient, skipping.")
        return None
    if status != 200:
        return None

    items = _extract_api_items(result["raw_json"])
    company_counter: dict[str, int] = {}
    company_display: dict[str, str] = {}

    for item in items:
        raw_attributes = item.get("attributes")
        attributes = raw_attributes if isinstance(raw_attributes, dict) else {}
        for key in ("entity", "organization", "victim", "target_org", "company", "target"):
            value = attributes.get(key) or item.get(key)
            if value:
                _count_distinct_collection_mentions(
                    company_counter,
                    company_display,
                    _extract_names_from_field(value),
                )

    if not company_counter:
        return None

    return _build_ranked_collection_results(company_counter, company_display, 50)


def _fetch_companies_from_search(
    api_key: str,
    year: int,
    target: str | None,
    top_n: int,
    max_pages: int,
) -> list[dict[str, Any]] | None:
    """Extract organizations from GTI Intelligence Search preview fields. Returns None if empty."""

    date_filter = f"creation_date:{year}-01-01+ creation_date:{year}-12-31-"
    query = (
        f"entity:collection {target} {date_filter}"
        if target
        else f"entity:collection {date_filter}"
    )

    company_counter: dict[str, int] = {}
    company_display: dict[str, str] = {}
    seen_ids: set[str] = set()
    cursor: str | None = None

    for _ in range(max_pages):
        search_result = intelligence_search(
            api_key=api_key,
            query=query,
            limit=MAX_INTELLIGENCE_SEARCH_LIMIT,
            cursor=cursor,
        )
        if _safe_int(search_result.get("status_code")) not in (0, 200):
            return None

        items = search_result.get("simplified_preview", [])
        for item in items:
            coll_id = _stringify_value(item.get("id")) or ""
            if not coll_id or coll_id in seen_ids:
                continue
            seen_ids.add(coll_id)
            for key in ("targeted_organizations", "victims", "organizations"):
                _count_distinct_collection_mentions(
                    company_counter,
                    company_display,
                    _extract_names_from_field(item.get(key)),
                )

        cursor = search_result.get("next_cursor")
        if not cursor or not items:
            break

    if not company_counter:
        return None

    return _build_ranked_collection_results(company_counter, company_display, top_n)


class MockGTIClient:
    """Very small mock client that imitates a future GTI integration."""

    def __init__(self, api_key: str) -> None:
        # We keep the API key because the real client will need it later.
        # In this MVP, we do not validate or send it anywhere.
        self.api_key = api_key

    def fetch_threat_landscape(
        self,
        report_type: str,
        year: int,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Return sample GTI-like data for report generation.

        The returned structure is intentionally predictable so the report
        generator can work with a stable payload during early development.
        """

        # The target is optional in the API request, so we provide a friendly
        # fallback label to keep the report content readable.
        scoped_target = target or "Global threat landscape"

        return {
            "metadata": {
                "source": "mock_gti_client",
                "report_type": report_type,
                "year": year,
                "target": scoped_target,
                "notes": (
                    "This is sample data for the internship MVP. "
                    "Replace this client with a real GTI integration later."
                ),
            },
            "industries": [
                "Financial Services",
                "Healthcare",
                "Technology",
                "Manufacturing",
            ],
            "affected_companies": [
                {
                    "name": "Northbridge Bank",
                    "industry": "Financial Services",
                    "summary": "Credential theft campaign linked to phishing portals.",
                },
                {
                    "name": "MediCore Labs",
                    "industry": "Healthcare",
                    "summary": "Ransomware intrusion caused temporary lab system outages.",
                },
                {
                    "name": "Vertex Dynamics",
                    "industry": "Technology",
                    "summary": "Cloud identity abuse exposed internal development assets.",
                },
            ],
            "threat_actors": [
                {
                    "name": "UNC3944",
                    "motivation": "Financial gain",
                    "activity": "Social engineering and credential compromise.",
                },
                {
                    "name": "FIN7",
                    "motivation": "Financial gain",
                    "activity": "Targeting enterprise environments for malware delivery.",
                },
                {
                    "name": "APT29",
                    "motivation": "Espionage",
                    "activity": "Stealthy persistence and collection against strategic targets.",
                },
            ],
            "iocs": [
                {
                    "type": "domain",
                    "value": "secure-employee-portal[.]com",
                    "context": "Phishing infrastructure",
                },
                {
                    "type": "hash",
                    "value": "44d88612fea8a8f36de82e1278abb02f",
                    "context": "Known malware sample",
                },
                {
                    "type": "ip",
                    "value": "185.220.101.45",
                    "context": "Suspicious command-and-control node",
                },
            ],
        }
