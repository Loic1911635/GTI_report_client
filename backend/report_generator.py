"""Helpers for normalizing GTI data and building configurable reports."""

from __future__ import annotations

import json
import re
from typing import Any


SUPPORTED_REPORT_SECTIONS = (
    "Executive Summary",
    "Technical Details",
    "IoCs",
    "Threat Actors",
    "Industries Impacted",
    "Affected Companies",
    "Recommended SOC Actions",
    "Raw GTI Data",
)

DEFAULT_REPORT_SECTIONS = tuple(
    section for section in SUPPORTED_REPORT_SECTIONS if section != "Raw GTI Data"
)

SUPPORTED_OUTPUT_FORMATS = {
    "markdown": ".md",
    "html": ".html",
}


def normalize_requested_sections(sections: list[str] | None) -> list[str]:
    """Return supported report sections in a predictable order."""

    requested_sections = sections or list(DEFAULT_REPORT_SECTIONS)
    normalized_sections: list[str] = []
    seen_sections: set[str] = set()

    for section in requested_sections:
        normalized_section = str(section).strip()
        if (
            normalized_section in SUPPORTED_REPORT_SECTIONS
            and normalized_section not in seen_sections
        ):
            normalized_sections.append(normalized_section)
            seen_sections.add(normalized_section)

    if not normalized_sections:
        raise ValueError("Select at least one supported report section.")

    return normalized_sections


def normalize_output_format(output_format: str | None) -> str:
    """Validate the requested output format."""

    normalized_output_format = str(output_format or "markdown").strip().lower()

    if normalized_output_format == "docx":
        raise ValueError("DOCX output is not available yet.")

    if normalized_output_format not in SUPPORTED_OUTPUT_FORMATS:
        supported_formats = ", ".join(sorted(SUPPORTED_OUTPUT_FORMATS))
        raise ValueError(
            f"Unsupported output format '{normalized_output_format}'. "
            f"Use one of: {supported_formats}."
        )

    return normalized_output_format


def build_downloadable_filename(
    report_type: str,
    year: int,
    output_format: str,
    target: str | None = None,
) -> str:
    """Build a safe downloadable filename for the generated report."""

    scope = target or str(year)
    slug_source = f"{report_type}-{scope}-{year}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug_source).strip("-")

    if not slug:
        slug = "gti-report"

    return f"{slug}{SUPPORTED_OUTPUT_FORMATS[output_format]}"


def normalize_threat_landscape(raw_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize the raw data into a stable structure for report generation."""

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
    sections: list[str],
    raw_data: dict[str, Any],
    target: str | None = None,
) -> str:
    """Build a configurable Markdown report from normalized threat data."""

    lines: list[str] = []
    report_target = target or "Global threat landscape"

    lines.append(f"# GTI Report: {report_type} ({year})")
    lines.append("")
    lines.append(f"**Target:** {report_target}")
    lines.append(f"**Source:** {normalized_data['metadata']['source']}")

    if "Executive Summary" in sections:
        _append_section(
            lines,
            "Executive Summary",
            [
                _build_threat_landscape_summary(
                    normalized_data=normalized_data,
                    report_type=report_type,
                    year=year,
                    report_target=report_target,
                )
            ],
        )

    if "Technical Details" in sections:
        technical_details = [
            f"- Report Type: {report_type}",
            f"- Reporting Year: {year}",
            f"- Industries Returned: {len(normalized_data['industries'])}",
            f"- Affected Companies Returned: {len(normalized_data['affected_companies'])}",
            f"- Threat Actors Returned: {len(normalized_data['threat_actors'])}",
            f"- IoCs Returned: {len(normalized_data['iocs'])}",
        ]
        notes = normalized_data["metadata"].get("notes")
        if notes:
            technical_details.append(f"- Data Source Notes: {notes}")
        _append_section(lines, "Technical Details", technical_details)

    if "IoCs" in sections:
        ioc_lines = []
        if normalized_data["iocs"]:
            for ioc in normalized_data["iocs"]:
                ioc_lines.append(
                    f"- **{ioc['type']}** `{ioc['value']}`: {ioc['context']}"
                )
        else:
            ioc_lines.append("- No IoCs were returned by the data source.")
        _append_section(lines, "IoCs", ioc_lines)

    if "Threat Actors" in sections:
        actor_lines = []
        if normalized_data["threat_actors"]:
            for actor in normalized_data["threat_actors"]:
                actor_lines.append(
                    f"- **{actor['name']}** | Motivation: {actor['motivation']} | "
                    f"Activity: {actor['activity']}"
                )
        else:
            actor_lines.append("- No threat actors were returned by the data source.")
        _append_section(lines, "Threat Actors", actor_lines)

    if "Industries Impacted" in sections:
        industry_lines = []
        if normalized_data["industries"]:
            for industry in normalized_data["industries"]:
                industry_lines.append(f"- {industry}")
        else:
            industry_lines.append("- No industries were returned by the data source.")
        _append_section(lines, "Industries Impacted", industry_lines)

    if "Affected Companies" in sections:
        company_lines = []
        if normalized_data["affected_companies"]:
            for company in normalized_data["affected_companies"]:
                company_lines.append(
                    f"- **{company['name']}** ({company['industry']}): "
                    f"{company['summary']}"
                )
        else:
            company_lines.append(
                "- No affected companies were returned by the data source."
            )
        _append_section(lines, "Affected Companies", company_lines)

    if "Recommended SOC Actions" in sections:
        _append_section(
            lines,
            "Recommended SOC Actions",
            _build_threat_landscape_soc_actions(normalized_data, report_target),
        )

    if "Raw GTI Data" in sections:
        _append_section(lines, "Raw GTI Data", _format_raw_data_block(raw_data))

    return "\n".join(lines)


def generate_ioc_enrichment_markdown_report(
    enrichment_data: dict[str, Any],
    sections: list[str],
) -> str:
    """Build a configurable Markdown report for a domain enrichment lookup."""

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

    if "Executive Summary" in sections:
        _append_section(
            lines,
            "Executive Summary",
            [
                _build_ioc_analyst_summary(
                    target=target,
                    reputation=reputation,
                    malicious=malicious,
                    suspicious=suspicious,
                    harmless=harmless,
                    undetected=undetected,
                    categories=categories,
                )
            ],
        )

    if "Technical Details" in sections:
        category_summary = _summarize_categories(categories)
        _append_section(
            lines,
            "Technical Details",
            [
                f"- Indicator Type: {indicator_type}",
                f"- Reputation: {reputation}",
                (
                    "- Detection Stats: "
                    f"malicious {malicious} | suspicious {suspicious} | "
                    f"harmless {harmless} | undetected {undetected}"
                ),
                f"- Categories: {category_summary}",
            ],
        )

    if "IoCs" in sections:
        _append_section(
            lines,
            "IoCs",
            [
                (
                    f"- **{indicator_type}** `{target}`: Reputation {reputation} | "
                    f"Malicious {malicious} | Suspicious {suspicious}"
                )
            ],
        )

    if "Threat Actors" in sections:
        _append_section(
            lines,
            "Threat Actors",
            [
                "- No threat actor attribution was returned by the current "
                "VirusTotal domain lookup."
            ],
        )

    if "Industries Impacted" in sections:
        _append_section(
            lines,
            "Industries Impacted",
            [
                "- The current VirusTotal domain lookup does not provide industry "
                "impact mapping."
            ],
        )

    if "Affected Companies" in sections:
        _append_section(
            lines,
            "Affected Companies",
            [
                "- The current VirusTotal domain lookup does not identify "
                "affected companies."
            ],
        )

    if "Recommended SOC Actions" in sections:
        _append_section(
            lines,
            "Recommended SOC Actions",
            _build_ioc_soc_actions(
                target=target,
                reputation=reputation,
                malicious=malicious,
                suspicious=suspicious,
            ),
        )

    if "Raw GTI Data" in sections:
        _append_section(lines, "Raw GTI Data", _format_raw_data_block(enrichment_data))

    return "\n".join(lines)


def _append_section(lines: list[str], title: str, content_lines: list[str]) -> None:
    """Append a titled section to the report."""

    lines.append("")
    lines.append(f"## {title}")
    lines.extend(content_lines)


def _build_threat_landscape_summary(
    normalized_data: dict[str, Any],
    report_type: str,
    year: int,
    report_target: str,
) -> str:
    """Create a short analyst-style summary for a threat landscape report."""

    industry_count = len(normalized_data["industries"])
    company_count = len(normalized_data["affected_companies"])
    actor_count = len(normalized_data["threat_actors"])
    ioc_count = len(normalized_data["iocs"])

    return (
        f"This {report_type.lower()} report for {report_target} in {year} summarizes "
        f"{industry_count} impacted industries, {company_count} affected companies, "
        f"{actor_count} tracked threat actors, and {ioc_count} reported IoCs. "
        "Use the selected sections below as a lightweight analyst handoff for "
        "triage, threat hunting, and stakeholder updates."
    )


def _build_threat_landscape_soc_actions(
    normalized_data: dict[str, Any],
    report_target: str,
) -> list[str]:
    """Generate simple SOC actions from the mock threat landscape data."""

    actions = [
        (
            "- Hunt across email, DNS, proxy, EDR, and identity telemetry for the "
            f"listed indicators associated with {report_target}."
        ),
        (
            "- Prioritize detections tied to phishing, ransomware, and cloud identity "
            "abuse themes highlighted in the current dataset."
        ),
    ]

    if normalized_data["threat_actors"]:
        actor_names = ", ".join(
            actor["name"] for actor in normalized_data["threat_actors"][:3]
        )
        actions.append(
            f"- Track tradecraft associated with {actor_names} in watchlists and "
            "ongoing detection tuning."
        )

    if normalized_data["affected_companies"]:
        actions.append(
            "- Review whether peer organizations, suppliers, or internal business "
            "units share exposure patterns with the affected companies in this report."
        )

    return actions


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

    return (
        f"{verdict_summary} Categories reported by the data source: "
        f"{_summarize_categories(categories)}."
    )


def _build_ioc_soc_actions(
    target: str,
    reputation: int,
    malicious: int,
    suspicious: int,
) -> list[str]:
    """Generate simple SOC actions from an enrichment lookup."""

    if malicious > 0 or suspicious > 0:
        return [
            (
                f"- Block or closely monitor `{target}` across DNS, proxy, email, "
                "and endpoint telemetry while triage is in progress."
            ),
            (
                "- Pivot on passive DNS, WHOIS, certificate history, and related "
                "infrastructure to uncover adjacent indicators."
            ),
            (
                "- Review recent user clicks, outbound connections, and credential "
                "events that reference this domain."
            ),
        ]

    if reputation < 0:
        return [
            (
                f"- Flag `{target}` for enhanced monitoring and review any recent "
                "connections before applying a hard block."
            ),
            (
                "- Correlate the domain with DNS history, sandbox results, and "
                "internal detections to confirm whether the negative reputation is actionable."
            ),
        ]

    return [
        (
            f"- Keep `{target}` under observation and re-check enrichment if new "
            "alerts, user reports, or infrastructure pivots appear."
        ),
        (
            "- Preserve the lookup context in the case notes so analysts can compare "
            "future changes in reputation and detection counts."
        ),
    ]


def _format_raw_data_block(raw_data: dict[str, Any]) -> list[str]:
    """Format raw JSON data as a fenced code block."""

    return [
        "```json",
        json.dumps(raw_data, indent=2, sort_keys=True),
        "```",
    ]


def _summarize_categories(categories: Any) -> str:
    """Return category labels as a compact string."""

    if isinstance(categories, dict) and categories:
        return "; ".join(
            f"{vendor}: {category}" for vendor, category in categories.items()
        )

    return "none returned"
