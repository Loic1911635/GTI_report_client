"""GTI client helpers for mock reports and VirusTotal API lookups."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import requests


VIRUSTOTAL_DOMAIN_LOOKUP_URL = "https://www.virustotal.com/api/v3/domains/{}"
VIRUSTOTAL_COLLECTIONS_URL = "https://www.virustotal.com/api/v3/collections"
VIRUSTOTAL_SEARCH_URL = "https://www.virustotal.com/api/v3/search"
VIRUSTOTAL_INTELLIGENCE_SEARCH_URL = (
    "https://www.virustotal.com/api/v3/intelligence/search"
)
VIRUSTOTAL_DTM_MONITORS_URL = "https://www.virustotal.com/api/v3/dtm/monitors"
VIRUSTOTAL_DTM_ALERTS_URL = "https://www.virustotal.com/api/v3/dtm/alerts"
MAX_SAFE_DTM_PAGES = 5
DEFAULT_INTELLIGENCE_SEARCH_LIMIT = 10
MAX_INTELLIGENCE_SEARCH_LIMIT = 40
DEFAULT_DTM_MONITOR_PAGE_SIZE = 50
DEFAULT_DTM_ALERT_PAGE_SIZE = 25
MAX_DTM_ALERT_PAGE_SIZE = 25


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
    if not isinstance(next_link, str) or not next_link.strip():
        return None

    parsed_next_link = urlparse(next_link)
    cursor_values = parse_qs(parsed_next_link.query).get("cursor", [])
    if cursor_values and cursor_values[0]:
        return cursor_values[0]

    if "http" not in next_link.casefold():
        return next_link

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

    for match in re.finditer(r"<([^>]+)>\s*;\s*rel=\"([^\"]+)\"", link_header):
        link_url, relation = match.groups()
        if relation.casefold() == "next":
            return link_url

    return None


def _extract_cursor_from_url(url: str) -> str | None:
    """Extract a cursor query parameter from a URL when present."""

    parsed_url = urlparse(url)
    cursor_values = parse_qs(parsed_url.query).get("cursor", [])
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
                _extract_exact_field(item, normalized_attributes, "collection_type")
            ),
            "creation_date": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "creation_date")
            ),
            "targeted_industries": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "targeted_industries")
            ),
            "targeted_regions": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "targeted_regions")
            ),
            "source_regions": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "source_regions")
            ),
            "tags": _normalize_collection_field(
                _extract_exact_field(item, normalized_attributes, "tags")
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
