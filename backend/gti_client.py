"""GTI client helpers for mock reports and VirusTotal v3 domain lookups."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests


VIRUSTOTAL_DOMAIN_LOOKUP_URL = "https://www.virustotal.com/api/v3/domains/{}"


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
