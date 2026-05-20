"""Read-only DTM Monitor & Alert Dashboard routes."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
import time
from typing import Any
from urllib.parse import urljoin

import requests
from fastapi import APIRouter, HTTPException, Query


router = APIRouter()

GTI_BASE_URL = "https://www.virustotal.com/api/v3/"
DTM_MONITORS_URL = f"{GTI_BASE_URL}dtm/monitors"
DTM_ALERTS_URL = f"{GTI_BASE_URL}dtm/alerts"
DEFAULT_MONITOR_QUOTA = 100
DEFAULT_PAGE_SIZE = 25
MAX_429_RETRIES = 3
HIGH_ALERT_VOLUME_THRESHOLD = 50

logger = logging.getLogger("fastapi")


@router.get("/dtm/dashboard")
def get_dtm_dashboard(
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    max_pages: int = Query(default=20, ge=1, le=100),
    include_raw: bool = Query(default=False),
    api_key: str | None = Query(default=None),
) -> dict[str, Any]:
    """Construit un dashboard DTM read-only a partir des monitors et alertes existants."""

    api_key = (api_key or os.environ.get("GTI_API_KEY") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="A GTI API key is required via the api_key query parameter or the GTI_API_KEY environment variable.",
        )
    logger.info(
        "DTM dashboard using GTI_API_KEY length=%s sha256_prefix=%s",
        len(api_key),
        hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12],
    )

    try:
        period = _resolve_period(since, until)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    monitors_payloads: list[dict[str, Any]] = []
    alerts_payloads: list[dict[str, Any]] = []
    monitors_items: list[dict[str, Any]] = []
    alerts_items: list[dict[str, Any]] = []
    warnings = ["Dashboard is read-only and does not modify DTM monitors or alerts."]
    fetch_errors: list[str] = []
    monitors_truncated = False
    alerts_truncated = False
    monitors_fetch_succeeded = False
    alerts_fetch_succeeded = False
    monitor_page_count: int | None = None
    alert_page_count: int | None = None

    try:
        monitor_fetch = _fetch_paginated_gti(
            url=DTM_MONITORS_URL,
            api_key=api_key,
            params={
                "size": DEFAULT_PAGE_SIZE,
            },
            max_pages=max_pages,
            collection_key="monitors",
        )
        monitors_items = monitor_fetch["items"]
        monitors_payloads = monitor_fetch["payloads"]
        monitors_truncated = monitor_fetch["truncated"]
        monitor_page_count = monitor_fetch.get("page_count")
        monitors_fetch_succeeded = True
    except GTIDashboardUpstreamError as exc:
        logger.error("DTM dashboard monitor fetch failed with status=%s: %s", exc.status_code, exc)
        fetch_errors.append(f"monitors: {exc}")

    try:
        alert_fetch = _fetch_paginated_gti(
            url=DTM_ALERTS_URL,
            api_key=api_key,
            params={
                "sort": "created_at",
                "order": "desc",
                "size": DEFAULT_PAGE_SIZE,
                "refs": "false",
                "monitor_name": "true",
                "sanitize": "true",
                **period,
            },
            max_pages=max_pages,
            collection_key="alerts",
        )
        alerts_items = alert_fetch["items"]
        alerts_payloads = alert_fetch["payloads"]
        alerts_truncated = alert_fetch["truncated"]
        alert_page_count = alert_fetch.get("page_count")
        alerts_fetch_succeeded = True
    except GTIDashboardUpstreamError as exc:
        logger.error("DTM dashboard alert fetch failed with status=%s: %s", exc.status_code, exc)
        fetch_errors.append(f"alerts: {exc}")

    if not monitors_items and not alerts_items and fetch_errors:
        raise HTTPException(
            status_code=502,
            detail=f"DTM dashboard fetch failed: {'; '.join(fetch_errors)}",
        )

    if monitors_truncated or alerts_truncated:
        warnings.append("Results are limited by max_pages.")
    if monitors_fetch_succeeded and alerts_fetch_succeeded and not alerts_items:
        warnings.append(
            "No DTM alerts were returned for the selected period. "
            "Try a wider date range or verify that alerts exist in GTI."
        )
    warnings.extend(fetch_errors)

    dashboard = _build_dashboard_response(
        period=period,
        monitors=monitors_items,
        alerts=alerts_items,
        warnings=warnings,
    )
    dashboard["limits"] = {
        "alert_page_size": DEFAULT_PAGE_SIZE,
        "max_pages": max_pages,
        "max_alerts": max_pages * DEFAULT_PAGE_SIZE,
    }
    if include_raw:
        dashboard["raw"] = {
            "monitors": monitors_payloads,
            "alerts": alerts_payloads,
        }
        dashboard["raw_debug"] = {
            "monitor_items_count": len(monitors_items),
            "alert_items_count": len(alerts_items),
            "monitor_pages": monitor_page_count,
            "alert_pages": alert_page_count,
            "first_alert_keys": _first_item_keys(alerts_items),
            "first_monitor_keys": _first_item_keys(monitors_items),
        }

    return dashboard


def _resolve_period(since: str | None, until: str | None) -> dict[str, str]:
    """Normalise la periode demandee; par defaut, les 30 derniers jours en UTC."""

    now = datetime.now(timezone.utc)
    until_dt = _parse_rfc3339(until) if until else now
    since_dt = _parse_rfc3339(since) if since else until_dt - timedelta(days=30)

    if since_dt >= until_dt:
        raise ValueError("since must be earlier than until.")

    return {
        "since": _format_rfc3339(since_dt),
        "until": _format_rfc3339(until_dt),
    }


def _fetch_paginated_gti(
    url: str,
    api_key: str,
    params: dict[str, Any],
    max_pages: int,
    collection_key: str | None = None,
) -> dict[str, Any]:
    """Recupere les pages GTI en suivant uniquement le Link header pour la suite."""

    current_url = url
    current_params: dict[str, Any] | None = params
    payloads: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    truncated = False

    for page_index in range(max_pages):
        payload, headers = _request_gti(
            url=current_url,
            api_key=api_key,
            params=current_params,
        )
        payloads.append(payload)
        items.extend(_extract_items(payload, collection_key=collection_key))

        next_url = _extract_next_link(headers)
        if not next_url:
            return {
                "items": items,
                "payloads": payloads,
                "page_count": page_index + 1,
                "truncated": False,
            }

        current_url = urljoin(GTI_BASE_URL, next_url)
        current_params = None

    if _extract_next_link(headers):
        truncated = True

    return {
        "items": items,
        "payloads": payloads,
        "page_count": max_pages,
        "truncated": truncated,
    }


def _request_gti(
    url: str,
    api_key: str,
    params: dict[str, Any] | None,
) -> tuple[dict[str, Any], requests.structures.CaseInsensitiveDict[str]]:
    """Appelle GTI en GET avec retry exponentiel sur les limites 429."""

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    for attempt in range(MAX_429_RETRIES + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise GTIDashboardUpstreamError(0, f"Request failed: {exc}") from exc

        if response.status_code == 429 and attempt < MAX_429_RETRIES:
            delay_seconds = 2**attempt
            logger.warning(
                "GTI returned 429 for dashboard request %s; retrying in %s second(s).",
                url,
                delay_seconds,
            )
            time.sleep(delay_seconds)
            continue

        if response.status_code in {401, 403, 429, 500} or response.status_code >= 400:
            raise GTIDashboardUpstreamError(
                response.status_code,
                _extract_error_message(response),
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise GTIDashboardUpstreamError(
                response.status_code,
                "GTI returned a non-JSON response.",
            ) from exc

        if not isinstance(payload, dict):
            raise GTIDashboardUpstreamError(
                response.status_code,
                "GTI returned an unexpected JSON payload.",
            )

        return payload, response.headers

    raise GTIDashboardUpstreamError(429, "GTI rate limit exceeded after retries.")


def _build_dashboard_response(
    period: dict[str, str],
    monitors: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    """Agrege les monitors et alertes en donnees pretes pour les graphiques."""

    monitor_rows = _build_monitor_rows(monitors)
    severity_counter = Counter({"high": 0, "medium": 0, "low": 0})
    type_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    timeline_counter: Counter[str] = Counter()

    for alert in alerts:
        alert_view = _extract_alert(alert)
        monitor_key = _monitor_key(alert_view["monitor_id"], alert_view["monitor_name"])
        if monitor_key not in monitor_rows:
            monitor_rows[monitor_key] = _new_monitor_row(
                monitor_id=alert_view["monitor_id"],
                name=alert_view["monitor_name"],
                created_at="",
                updated_at="",
            )

        row = monitor_rows[monitor_key]
        row["alert_count"] += 1
        row[alert_view["severity"]] += 1
        row["type_counts"][alert_view["alert_type"]] += 1
        row["status_counts"][alert_view["status"]] += 1
        if alert_view["is_compromised_credentials"]:
            row["compromised_credentials"] += 1
        if alert_view["is_duplicate"]:
            row["duplicate_count"] += 1
        if alert_view["is_not_relevant"]:
            row["not_relevant_count"] += 1
        if alert_view["created_date"]:
            row["last_alert_date"] = _max_date(row["last_alert_date"], alert_view["created_date"])
            timeline_counter[alert_view["created_date"]] += 1

        severity_counter[alert_view["severity"]] += 1
        type_counter[alert_view["alert_type"]] += 1
        status_counter[alert_view["status"]] += 1

    monitors_output = [_finalize_monitor_row(row) for row in monitor_rows.values()]
    monitors_output.sort(
        key=lambda item: (
            -int(item["risk_score"]),
            -int(item["alert_count"]),
            str(item["name"]).casefold(),
        )
    )

    monitors_with_alerts = sum(1 for item in monitors_output if int(item["alert_count"]) > 0)
    monitors_without_alerts = sum(1 for item in monitors_output if int(item["alert_count"]) == 0)
    top_risky = max(monitors_output, key=lambda item: int(item["risk_score"]), default=None)
    top_noisy = max(monitors_output, key=lambda item: int(item["noise_score"]), default=None)
    top_risky_monitor = (
        top_risky["name"] if top_risky and int(top_risky["risk_score"]) > 0 else ""
    )
    top_noisy_monitor = (
        top_noisy["name"] if top_noisy and int(top_noisy["noise_score"]) > 0 else ""
    )

    return {
        "period": period,
        "quota": _build_quota(len(monitors)),
        "summary": {
            "total_monitors": len(monitors_output),
            "total_alerts": len(alerts),
            "high_alerts": severity_counter["high"],
            "medium_alerts": severity_counter["medium"],
            "low_alerts": severity_counter["low"],
            "monitors_with_alerts": monitors_with_alerts,
            "monitors_without_alerts": monitors_without_alerts,
            "top_risky_monitor": top_risky_monitor,
            "top_noisy_monitor": top_noisy_monitor,
        },
        "charts": {
            "top_monitors_by_alert_count": _top_alert_count(monitors_output),
            "top_monitors_by_risk_score": _top_risk_score(monitors_output),
            "alerts_by_severity": [
                {"severity": "high", "count": severity_counter["high"]},
                {"severity": "medium", "count": severity_counter["medium"]},
                {"severity": "low", "count": severity_counter["low"]},
            ],
            "alerts_by_type": _counter_rows(type_counter, "type"),
            "alerts_by_status": _counter_rows(status_counter, "status"),
            "alerts_timeline": [
                {"date": date, "count": count}
                for date, count in sorted(timeline_counter.items())
            ],
            "noisy_monitors": _noisy_monitors(monitors_output),
            "inactive_monitors": [
                {
                    "monitor_id": item["monitor_id"],
                    "monitor_name": item["name"],
                    "last_alert_date": item["last_alert_date"],
                }
                for item in monitors_output
                if int(item["alert_count"]) == 0
            ],
        },
        "monitors": monitors_output,
        "warnings": warnings,
    }


def _build_monitor_rows(monitors: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Indexe les monitors existants avant d'y rattacher les alertes."""

    rows: dict[str, dict[str, Any]] = {}
    for monitor in monitors:
        monitor_view = _extract_monitor(monitor)
        key = _monitor_key(monitor_view["monitor_id"], monitor_view["name"])
        rows[key] = _new_monitor_row(
            monitor_id=monitor_view["monitor_id"],
            name=monitor_view["name"],
            created_at=monitor_view["created_at"],
            updated_at=monitor_view["updated_at"],
        )
    return rows


def _new_monitor_row(
    monitor_id: str,
    name: str,
    created_at: str,
    updated_at: str,
) -> dict[str, Any]:
    return {
        "monitor_id": monitor_id,
        "name": name or monitor_id or "Unknown monitor",
        "created_at": created_at,
        "updated_at": updated_at,
        "alert_count": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "type_counts": Counter(),
        "status_counts": Counter(),
        "compromised_credentials": 0,
        "duplicate_count": 0,
        "not_relevant_count": 0,
        "last_alert_date": None,
    }


def _finalize_monitor_row(row: dict[str, Any]) -> dict[str, Any]:
    """Calcule les scores finaux d'un monitor."""

    high = int(row["high"])
    medium = int(row["medium"])
    low = int(row["low"])
    alert_count = int(row["alert_count"])
    duplicate_count = int(row["duplicate_count"])
    not_relevant_count = int(row["not_relevant_count"])
    compromised_credentials = int(row["compromised_credentials"])
    risk_score = high * 5 + medium * 2 + low + compromised_credentials * 5
    noise_score = low + duplicate_count + not_relevant_count
    if alert_count >= HIGH_ALERT_VOLUME_THRESHOLD and high == 0:
        noise_score += alert_count

    return {
        "monitor_id": row["monitor_id"],
        "name": row["name"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "alert_count": alert_count,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": risk_score,
        "noise_score": noise_score,
        "last_alert_date": row["last_alert_date"],
    }


def _extract_monitor(item: dict[str, Any]) -> dict[str, str]:
    attributes = _attributes(item)
    monitor_id = _first_text(
        item.get("id"),
        attributes.get("id"),
        attributes.get("monitor_id"),
    )
    return {
        "monitor_id": monitor_id or "",
        "name": _first_text(
            attributes.get("name"),
            attributes.get("monitor_name"),
            attributes.get("display_name"),
            item.get("name"),
            monitor_id,
            "Unknown monitor",
        ) or "Unknown monitor",
        "created_at": _first_text(attributes.get("created_at"), item.get("created_at"), "") or "",
        "updated_at": _first_text(attributes.get("updated_at"), item.get("updated_at"), "") or "",
    }


def _extract_alert(item: dict[str, Any]) -> dict[str, Any]:
    attributes = _attributes(item)
    alert_type = _first_field_text(
        item,
        attributes,
        ("alert_type", "type", "category"),
        "Unknown",
    )
    status = _normalize_status(
        _first_field_text(item, attributes, ("status",), "unknown")
    )
    created_at = _first_field_text(
        item,
        attributes,
        ("created_at", "creation_date", "date", "first_seen", "last_seen"),
        "",
    )
    severity = _normalize_severity(
        _first_field_text(item, attributes, ("severity", "threat_severity", "risk"), "low")
    )
    monitor_name = _extract_alert_monitor_name(item, attributes)

    return {
        "monitor_id": _extract_alert_monitor_id(item, attributes),
        "monitor_name": monitor_name,
        "severity": severity,
        "alert_type": alert_type,
        "status": status,
        "created_date": _date_part(created_at),
        "is_compromised_credentials": "compromised credentials" in alert_type.casefold(),
        "is_duplicate": _is_duplicate_alert(attributes, status, alert_type),
        "is_not_relevant": _is_not_relevant_alert(attributes, status),
    }


def _extract_alert_monitor_id(item: dict[str, Any], attributes: dict[str, Any]) -> str:
    direct_value = _first_text(
        item.get("monitor_id"),
        item.get("source_monitor_id"),
        _extract_monitor_reference_value(item.get("monitor"), "id"),
        attributes.get("monitor_id"),
        attributes.get("source_monitor_id"),
        _extract_monitor_reference_value(attributes.get("monitor"), "id"),
    )
    if direct_value:
        return direct_value

    relationships = item.get("relationships")
    if not isinstance(relationships, dict):
        return ""

    monitor_relationship = relationships.get("monitor")
    if not isinstance(monitor_relationship, dict):
        return ""

    monitor_data = monitor_relationship.get("data")
    if isinstance(monitor_data, dict):
        return _first_text(monitor_data.get("id"), "") or ""
    if isinstance(monitor_data, list):
        for candidate in monitor_data:
            if isinstance(candidate, dict):
                candidate_id = _first_text(candidate.get("id"), "")
                if candidate_id:
                    return candidate_id

    return ""


def _extract_alert_monitor_name(item: dict[str, Any], attributes: dict[str, Any]) -> str:
    direct_name = _first_text(
        item.get("monitor_name"),
        item.get("monitor_display_name"),
        _extract_monitor_reference_value(item.get("monitor"), "name"),
        attributes.get("monitor_name"),
        attributes.get("monitor_display_name"),
        _extract_monitor_reference_value(attributes.get("monitor"), "name"),
        "Unknown monitor",
    )
    return direct_name or "Unknown monitor"


def _extract_monitor_reference_value(value: Any, preferred_key: str) -> str | None:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None

    candidate_keys = (
        (preferred_key, "id", "monitor_id", "name", "display_name")
        if preferred_key == "id"
        else (preferred_key, "name", "display_name", "id", "monitor_id")
    )
    for key in candidate_keys:
        candidate = _first_text(value.get(key))
        if candidate:
            return candidate
    return None


def _extract_items(payload: Any, collection_key: str | None = None) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    candidate_keys = [
        key
        for key in (
            collection_key,
            "data",
            "monitors",
            "alerts",
            "items",
            "results",
        )
        if key
    ]

    for key in candidate_keys:
        data = payload.get(key)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [data]

    return []


def _extract_next_link(headers: requests.structures.CaseInsensitiveDict[str]) -> str | None:
    link_header = headers.get("Link") or headers.get("link")
    if not link_header:
        return None

    for part in link_header.split(","):
        segments = [segment.strip() for segment in part.split(";")]
        if not segments:
            continue
        raw_url = segments[0]
        if raw_url.startswith("<") and raw_url.endswith(">"):
            raw_url = raw_url[1:-1]
        rel_values = {
            segment.split("=", 1)[1].strip('"')
            for segment in segments[1:]
            if segment.startswith("rel=") and "=" in segment
        }
        if "next" in rel_values and raw_url:
            return raw_url

    return None


def _counter_rows(counter: Counter[str], key_name: str) -> list[dict[str, Any]]:
    return [
        {key_name: key, "count": count}
        for key, count in counter.most_common()
    ]


def _top_alert_count(monitors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "monitor_id": item["monitor_id"],
            "monitor_name": item["name"],
            "alert_count": item["alert_count"],
        }
        for item in sorted(monitors, key=lambda row: (-int(row["alert_count"]), str(row["name"]).casefold()))[:10]
        if int(item["alert_count"]) > 0
    ]


def _top_risk_score(monitors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "monitor_id": item["monitor_id"],
            "monitor_name": item["name"],
            "risk_score": item["risk_score"],
            "high": item["high"],
            "medium": item["medium"],
            "low": item["low"],
        }
        for item in sorted(monitors, key=lambda row: (-int(row["risk_score"]), str(row["name"]).casefold()))[:10]
        if int(item["risk_score"]) > 0
    ]


def _noisy_monitors(monitors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "monitor_id": item["monitor_id"],
            "monitor_name": item["name"],
            "alert_count": item["alert_count"],
            "high": item["high"],
            "medium": item["medium"],
            "low": item["low"],
            "noise_score": item["noise_score"],
        }
        for item in sorted(monitors, key=lambda row: (-int(row["noise_score"]), str(row["name"]).casefold()))[:10]
        if int(item["noise_score"]) > 0
    ]


def _build_quota(monitor_count: int) -> dict[str, Any]:
    used_percent = round((monitor_count / DEFAULT_MONITOR_QUOTA) * 100, 1)
    return {
        "monitor_count": monitor_count,
        "default_monitor_quota": DEFAULT_MONITOR_QUOTA,
        "used_percent": used_percent,
        "remaining_estimate": max(DEFAULT_MONITOR_QUOTA - monitor_count, 0),
    }


def _normalize_severity(value: str | None) -> str:
    normalized = (value or "low").strip().casefold()
    if normalized in {"critical", "high"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    return "low"


def _normalize_status(value: str) -> str:
    return " ".join(value.strip().casefold().replace("_", " ").split()) or "unknown"


def _is_duplicate_alert(attributes: dict[str, Any], status: str, alert_type: str) -> bool:
    if _safe_int(attributes.get("duplicate_count")) > 0:
        return True
    normalized_type = alert_type.casefold()
    return status in {"duplicate", "duplicated"} or "duplicate" in normalized_type


def _is_not_relevant_alert(attributes: dict[str, Any], status: str) -> bool:
    if _safe_int(attributes.get("not_relevant_count")) > 0:
        return True
    return status in {
        "not relevant",
        "irrelevant",
        "false positive",
        "not applicable",
    }


def _attributes(item: dict[str, Any]) -> dict[str, Any]:
    raw_attributes = item.get("attributes")
    return raw_attributes if isinstance(raw_attributes, dict) else {}


def _first_field_text(
    item: dict[str, Any],
    attributes: dict[str, Any],
    keys: tuple[str, ...],
    default: str,
) -> str:
    for key in keys:
        value = _first_text(item.get(key))
        if value:
            return value
    for key in keys:
        value = _first_text(attributes.get(key))
        if value:
            return value
    return default


def _first_item_keys(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return []
    return sorted(str(key) for key in items[0].keys())


def _parse_rfc3339(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("since and until must be RFC3339 datetime strings.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _date_part(value: str | None) -> str:
    if not value:
        return ""
    try:
        return _parse_rfc3339(value).date().isoformat()
    except ValueError:
        return value[:10] if len(value) >= 10 else ""


def _max_date(current: str | None, candidate: str) -> str:
    if not current:
        return candidate
    return max(current, candidate)


def _monitor_key(monitor_id: str, monitor_name: str) -> str:
    if monitor_id:
        return f"id:{monitor_id}"
    return f"name:{monitor_name.casefold()}"


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            normalized = str(value).strip()
            if normalized:
                return normalized
    return None


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _extract_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            message = _first_text(error.get("message"), error.get("code"))
            if message:
                return message
        if error:
            return str(error)

    text = response.text.strip()
    if text:
        return text[:1000]

    return f"GTI request failed with status {response.status_code}."


class GTIDashboardUpstreamError(RuntimeError):
    """Raised when a read-only DTM dashboard GTI request fails."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
