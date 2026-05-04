"""Helpers for normalizing GTI data and building Markdown reports."""

from __future__ import annotations

from typing import Any


def normalize_threat_landscape(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize the raw data into a stable structure for report generation.

    Even though the mock client already returns clean data, this function is
    useful because a real API may later return missing keys, extra fields, or
    inconsistent value types.
    """

    metadata = raw_data.get("metadata", {})

    normalized_companies = []
    for company in raw_data.get("affected_companies", []):
        normalized_companies.append(
            {
                "name": str(company.get("name", "Unknown company")),
                "industry": str(company.get("industry", "Unknown industry")),
                "summary": str(company.get("summary", "No summary provided.")),
            }
        )

    normalized_actors = []
    for actor in raw_data.get("threat_actors", []):
        normalized_actors.append(
            {
                "name": str(actor.get("name", "Unknown actor")),
                "motivation": str(actor.get("motivation", "Unknown motivation")),
                "activity": str(actor.get("activity", "No activity details provided.")),
            }
        )

    normalized_iocs = []
    for ioc in raw_data.get("iocs", []):
        normalized_iocs.append(
            {
                "type": str(ioc.get("type", "unknown")),
                "value": str(ioc.get("value", "unknown")),
                "context": str(ioc.get("context", "No context provided.")),
            }
        )

    return {
        "metadata": {
            "source": str(metadata.get("source", "unknown")),
            "report_type": str(metadata.get("report_type", "unknown")),
            "year": metadata.get("year"),
            "target": str(metadata.get("target", "Global threat landscape")),
            "notes": str(metadata.get("notes", "")),
        },
        "industries": [str(industry) for industry in raw_data.get("industries", [])],
        "affected_companies": normalized_companies,
        "threat_actors": normalized_actors,
        "iocs": normalized_iocs,
    }


def generate_markdown_report(
    normalized_data: dict[str, Any],
    report_type: str,
    year: int,
    target: str | None = None,
) -> str:
    """Build a simple Markdown report from normalized threat data."""

    # We use list accumulation because it is easier to read and maintain than
    # one very large multi-line f-string for longer student projects.
    lines: list[str] = []
    report_target = target or "Global threat landscape"

    lines.append(f"# GTI Report: {report_type.title()} ({year})")
    lines.append("")
    lines.append(f"**Target:** {report_target}")
    lines.append(f"**Source:** {normalized_data['metadata']['source']}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(
        "This MVP report summarizes mock GTI findings for a quick internship "
        "demo workflow."
    )
    lines.append("")
    lines.append("## Industries Impacted")

    if normalized_data["industries"]:
        for industry in normalized_data["industries"]:
            lines.append(f"- {industry}")
    else:
        lines.append("- No industries were returned by the data source.")

    lines.append("")
    lines.append("## Affected Companies")

    if normalized_data["affected_companies"]:
        for company in normalized_data["affected_companies"]:
            lines.append(
                f"- **{company['name']}** ({company['industry']}): {company['summary']}"
            )
    else:
        lines.append("- No affected companies were returned by the data source.")

    lines.append("")
    lines.append("## Threat Actors")

    if normalized_data["threat_actors"]:
        for actor in normalized_data["threat_actors"]:
            lines.append(
                f"- **{actor['name']}** | Motivation: {actor['motivation']} | "
                f"Activity: {actor['activity']}"
            )
    else:
        lines.append("- No threat actors were returned by the data source.")

    lines.append("")
    lines.append("## Indicators of Compromise (IOCs)")

    if normalized_data["iocs"]:
        for ioc in normalized_data["iocs"]:
            lines.append(
                f"- **{ioc['type']}** `{ioc['value']}`: {ioc['context']}"
            )
    else:
        lines.append("- No IOCs were returned by the data source.")

    notes = normalized_data["metadata"].get("notes")
    if notes:
        lines.append("")
        lines.append("## Notes")
        lines.append(notes)

    return "\n".join


def generate_ioc_enrichment_markdown_report(enrichment_data: dict[str, Any]) -> str:
    """Build a Markdown report for a VirusTotal domain enrichment lookup."""

    target = str(enrichment_data.get("indicator", "unknown"))
    source = str(enrichment_data.get("source", "gti_virustotal_v3"))
    indicator_type = str(enrichment_data.get("indicator_type", "domain"))
    reputation = int(enrichment_data.get("reputation", 0))
    malicious = int(enrichment_data.get("malicious", 0))
    suspicious = int(enrichment_data.get("suspicious", 0))
    harmless = int(enrichment_data.get("harmless", 0))
    undetected = int(enrichment_data.get("undetected", 0))
    categories = enrichment_data.get("categories", {})

    lines: list[str] = []
    lines.append("# GTI Report: IoC Enrichment")
    lines.append("")
    lines.append(f"**Target:** {target}")
    lines.append(f"**Source:** {source}")
    lines.append(f"**Indicator Type:** {indicator_type}")
    lines.append(f"**Reputation:** {reputation}")
    lines.append("")
    lines.append("## Detection Overview")
    lines.append(f"- Malicious: {malicious}")
    lines.append(f"- Suspicious: {suspicious}")
    lines.append(f"- Harmless: {harmless}")
    lines.append(f"- Undetected: {undetected}")
    lines.append("")
    lines.append("## Categories")

    if isinstance(categories, dict) and categories:
        for vendor, category in categories.items():
            lines.append(f"- **{vendor}**: {category}")
    else:
        lines.append("- No categories were returned by the data source.")

    lines.append("")
    lines.append("## Analyst Summary")
    lines.append(
        _build_ioc_analyst_summary(
            target=target,
            reputation=reputation,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            categories=categories,
        )
    )

    return "\n".join(lines)


def _build_ioc_analyst_summary(
    target: str,
    reputation: int,
    malicious: int,
    suspicious: int,
    harmless: int,
    undetected: int,
    categories: Any,
) -> str:
    """Create a short analyst-style summary from enrichment signals."""

    if malicious > 0 or suspicious > 0:
        verdict_summary = (
            f"`{target}` shows elevated risk with {malicious} malicious verdict(s) "
            f"and {suspicious} suspicious verdict(s) in the latest VirusTotal snapshot."
        )
    elif reputation < 0:
        verdict_summary = (
            f"`{target}` has a negative reputation score of {reputation} even though "
            "the current snapshot does not show malicious or suspicious counts."
        )
    elif harmless > 0 and malicious == 0 and suspicious == 0:
        verdict_summary = (
            f"`{target}` currently appears lower risk in this snapshot, with "
            f"{harmless} harmless verdict(s) and no malicious or suspicious detections."
        )
    else:
        verdict_summary = (
            f"`{target}` returned limited telemetry, including {undetected} undetected "
            "verdict(s), so it should be correlated with surrounding context."
        )

    if isinstance(categories, dict) and categories:
        category_summary = ", ".join(
            f"{vendor}: {category}" for vendor, category in categories.items()
        )
        return (
            f"{verdict_summary} Reported categories include {category_summary}. "
            "Use the enrichment result alongside DNS, WHOIS, and internal detections "
            "before making a trust decision."
        )

    return (
        f"{verdict_summary} No category labels were returned by the API. Use the "
        "enrichment result alongside DNS, WHOIS, and internal detections before "
        "making a trust decision."
    )
