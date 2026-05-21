"""DOCX export helpers for GTI IoC Stream reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from docx import Document
from docx.shared import Pt


def generate_ioc_stream_docx(report_data: dict[str, Any], output_path: str) -> str:
    """Render an IoC Stream report as a readable DOCX document."""

    document = Document()
    core = document.core_properties
    core.title = "GTI IoC Stream Report"
    core.subject = "Client-friendly summary of GTI IoC Stream notifications"

    styles = document.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10)

    summary = _as_dict(report_data.get("summary"))
    document.add_heading("GTI IoC Stream Report", level=0)
    document.add_paragraph(f"Generated at: {summary.get('generated_at') or 'Unknown'}")

    document.add_heading("Executive Summary", level=1)
    for sentence in _as_list(report_data.get("business_summary")):
        document.add_paragraph(str(sentence), style="List Bullet")

    document.add_heading("Key Metrics", level=1)
    technical_details = _as_dict(report_data.get("technical_details"))
    enrichment = _as_dict(technical_details.get("enrichment"))
    metrics = [
        ("Total IoCs", summary.get("total_iocs", 0)),
        ("High risk", summary.get("high_risk", 0)),
        ("Medium risk", summary.get("medium_risk", 0)),
        ("Low risk", summary.get("low_risk", 0)),
        ("Unknown risk", summary.get("unknown_risk", 0)),
        ("Main IoC type", summary.get("main_entity_type", "Unknown")),
        ("Main source type", summary.get("main_source_type", "Unknown")),
        ("Enrichment enabled", enrichment.get("enabled", False)),
        ("Enrichment attempted", enrichment.get("attempted", 0)),
        ("Enrichment succeeded", enrichment.get("succeeded", 0)),
        ("Enrichment errors", enrichment.get("errors", 0)),
    ]
    _add_key_value_table(document, metrics)
    document.add_paragraph(
        "Risk is Unknown unless GTI Stream provides a score/verdict or enrichment is enabled. "
        "Unknown indicators are not treated as safe."
    )

    date_filtering = _as_dict(technical_details.get("date_filtering"))
    if date_filtering.get("start_date") or date_filtering.get("end_date"):
        document.add_heading("Date Filters", level=1)
        _add_key_value_table(
            document,
            [
                ("Selected start", date_filtering.get("start_date") or "none"),
                ("Selected end", date_filtering.get("end_date") or "none"),
                ("API filter applied", date_filtering.get("api_filter_applied", False)),
                (
                    "Note",
                    date_filtering.get("note")
                    or "Local post-filtering not yet implemented.",
                ),
            ],
        )

    document.add_heading("Chart Data", level=1)
    document.add_paragraph(
        "TODO: embed chart images when the frontend export pipeline passes chart images. "
        "For now, the chart data is exported as readable tables."
    )
    charts = _as_dict(report_data.get("charts"))
    for title, rows in (
        ("IoCs by entity type", charts.get("by_entity_type")),
        ("IoCs by risk", charts.get("by_risk")),
        ("IoCs by source type", charts.get("by_source_type")),
        ("Recommended actions", charts.get("by_recommended_action")),
    ):
        document.add_heading(title, level=2)
        _add_label_value_table(document, _as_list(rows))

    document.add_heading("Top Indicators Requiring Attention", level=1)
    _add_top_indicators_table(document, _as_list(report_data.get("top_indicators"))[:10])

    document.add_heading("Business Interpretation", level=1)
    for sentence in _as_list(report_data.get("business_summary")):
        document.add_paragraph(str(sentence), style="List Bullet")

    document.add_heading("Definitions", level=1)
    _add_definitions_table(document, _as_list(report_data.get("definitions")))

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    document.save(output)
    return str(output)


def _add_key_value_table(document: Document, rows: list[tuple[str, Any]]) -> None:
    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    table.rows[0].cells[0].text = "Metric"
    table.rows[0].cells[1].text = "Value"
    for label, value in rows:
        cells = table.add_row().cells
        cells[0].text = str(label)
        cells[1].text = str(value)


def _add_label_value_table(document: Document, rows: list[Any]) -> None:
    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    table.rows[0].cells[0].text = "Label"
    table.rows[0].cells[1].text = "Value"
    if not rows:
        cells = table.add_row().cells
        cells[0].text = "No data"
        cells[1].text = "0"
        return
    for row in rows:
        row_dict = _as_dict(row)
        cells = table.add_row().cells
        cells[0].text = str(row_dict.get("label", "Unknown"))
        cells[1].text = str(row_dict.get("value", 0))


def _add_top_indicators_table(document: Document, indicators: list[Any]) -> None:
    headers = (
        "Indicator",
        "Type",
        "Risk",
        "Malicious",
        "Suspicious",
        "Reputation",
        "Source",
        "Recommended action",
    )
    table = document.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    for index, header in enumerate(headers):
        table.rows[0].cells[index].text = header
    if not indicators:
        cells = table.add_row().cells
        cells[0].text = "No IoC Stream notifications were returned."
        return
    for indicator in indicators:
        item = _as_dict(indicator)
        cells = table.add_row().cells
        cells[0].text = str(item.get("value") or "Unknown")
        cells[1].text = str(item.get("entity_type") or "Unknown")
        cells[2].text = str(item.get("severity") or "Unknown")
        cells[3].text = _format_optional(item.get("malicious"))
        cells[4].text = _format_optional(item.get("suspicious"))
        cells[5].text = _format_optional(item.get("reputation"))
        cells[6].text = str(item.get("source_name") or item.get("source_type") or "Unknown")
        cells[7].text = str(item.get("recommended_action") or "Manual review")


def _add_definitions_table(document: Document, definitions: list[Any]) -> None:
    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    table.rows[0].cells[0].text = "Term"
    table.rows[0].cells[1].text = "Definition"
    for definition in definitions:
        item = _as_dict(definition)
        cells = table.add_row().cells
        cells[0].text = str(item.get("term") or "")
        cells[1].text = str(item.get("definition") or "")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _format_optional(value: Any) -> str:
    return "n/a" if value is None else str(value)
