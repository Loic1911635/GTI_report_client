"""DOCX export helpers for GTI Top Rankings results."""

from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from docx import Document
from docx.shared import Inches, Pt
from docxtpl import DocxTemplate, InlineImage


EMPTY_RANKING_NOTE = (
    "Field not present in GTI Intelligence Search preview for this sample."
)

RANKING_LABELS = {
    "top_industries": "Top targeted industries",
    "top_targeted_regions": "Top targeted regions",
    "top_source_regions": "Top source regions",
    "top_tags": "Top tags / themes",
    "collection_type_distribution": "Collection type distribution",
    "timeline": "Timeline",
    "top_targeted_organizations": "Top targeted organizations",
}

RANKING_RESULT_KEYS = {
    "top_industries": "targeted_industries",
    "top_targeted_regions": "targeted_regions",
    "top_source_regions": "source_regions",
    "top_tags": "tags",
    "collection_type_distribution": "collection_type",
    "timeline": "timeline",
    "top_targeted_organizations": "targeted_organizations",
}


def ensure_default_top_ranking_template(template_path: str | Path) -> Path:
    """Create the default importable DOCX template when it is missing."""

    resolved_template_path = Path(template_path)
    if resolved_template_path.exists():
        return resolved_template_path

    resolved_template_path.parent.mkdir(parents=True, exist_ok=True)

    document = Document()
    core = document.core_properties
    core.title = "GTI Top Targets Ranking Template"
    core.subject = "docxtpl template for GTI Top Rankings exports"

    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)

    styles = document.styles
    styles["Normal"].font.name = "Aptos"
    styles["Normal"].font.size = Pt(10)
    styles["Title"].font.name = "Aptos Display"
    styles["Title"].font.size = Pt(24)

    document.add_heading("{{ report_title }}", level=0)
    document.add_paragraph("Period: {{ period }}")
    document.add_paragraph("Generated at: {{ generated_at }}")
    document.add_paragraph("Scope / query: {{ query_used }}")
    document.add_paragraph("{{ preview_mode_note }}")

    document.add_page_break()
    document.add_heading("Executive Summary", level=1)
    document.add_paragraph("{{ executive_summary }}")
    document.add_paragraph("Selected rankings: {{ selected_rankings_text }}")
    document.add_paragraph("Main top results: {{ main_top_results }}")

    document.add_heading("Methodology", level=1)
    document.add_paragraph("GTI query used: {{ query_used }}")
    document.add_paragraph("{{ preview_only_explanation }}")
    document.add_paragraph("Request estimate: {{ estimated_api_requests }} estimated API request(s).")
    document.add_paragraph("Actual Intelligence Search requests: {{ actual_search_requests }}.")
    document.add_paragraph("{{ methodology }}")

    document.add_heading("Rankings", level=1)
    document.add_paragraph(
        "Ranking tables are inserted after template rendering from the computed result object."
    )
    document.add_paragraph("Industry chart: {{ industry_chart_note }}")
    document.add_paragraph("Targeted regions chart: {{ targeted_regions_chart_note }}")
    document.add_paragraph("Source regions chart: {{ source_regions_chart_note }}")
    document.add_paragraph("Tags chart: {{ tags_chart_note }}")
    document.add_paragraph("Collection type chart: {{ collection_type_chart_note }}")
    document.add_paragraph("Timeline chart: {{ timeline_chart_note }}")

    document.add_heading("Limitations", level=1)
    document.add_paragraph("Counts represent GTI collections, not confirmed incident counts.", style=None)
    document.add_paragraph("Preview-only fields may be incomplete.", style=None)
    document.add_paragraph("Crowdsourced collections may introduce noise.", style=None)

    document.add_heading("Appendix", level=1)
    document.add_paragraph("Field coverage is inserted after template rendering.")
    document.add_paragraph("{{ technical_debug_note }}")

    document.save(resolved_template_path)
    return resolved_template_path


def generate_top_ranking_docx(
    ranking_result: dict,
    template_path: str,
    output_path: str,
) -> str:
    """Render a GTI Top Rankings DOCX report from an existing result object."""

    resolved_template = ensure_default_top_ranking_template(template_path)
    resolved_output = Path(output_path)
    resolved_output.parent.mkdir(parents=True, exist_ok=True)

    sanitized_result = _sanitize_ranking_result(ranking_result)
    include_debug = bool(sanitized_result.get("include_technical_debug"))
    chart_temp_paths = _write_chart_images(sanitized_result.get("charts", {}))

    template = DocxTemplate(str(resolved_template))
    context = _build_docx_context(
        sanitized_result,
        include_debug=include_debug,
        chart_temp_paths=chart_temp_paths,
        template=template,
    )
    template.render(context)

    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as temp_file:
        rendered_path = Path(temp_file.name)
    template.save(rendered_path)

    document = Document(rendered_path)
    _append_ranking_tables(document, context)
    _append_chart_notes(document, context)
    _append_field_coverage(document, context)
    _append_optional_debug(document, context, include_debug)

    document.save(resolved_output)
    rendered_path.unlink(missing_ok=True)
    for chart_path in chart_temp_paths.values():
        chart_path.unlink(missing_ok=True)

    return str(resolved_output)


def _sanitize_ranking_result(ranking_result: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive or overly raw fields from the export input."""

    sanitized = dict(ranking_result or {})
    for key in (
        "api_key",
        "x_api_key",
        "raw_data",
        "raw_json",
        "collection_preview_fields",
    ):
        sanitized.pop(key, None)
    return sanitized


def _build_docx_context(
    ranking_result: dict[str, Any],
    include_debug: bool,
    chart_temp_paths: dict[str, Path],
    template: DocxTemplate,
) -> dict[str, Any]:
    """Build a docxtpl-safe context from the Top Rankings response."""

    rankings = ranking_result.get("rankings") if isinstance(ranking_result.get("rankings"), dict) else {}
    fields_coverage = ranking_result.get("fields_coverage") if isinstance(ranking_result.get("fields_coverage"), dict) else {}
    collections_analyzed = _safe_int(ranking_result.get("collections_analyzed"))
    selected_rankings = [
        str(item)
        for item in ranking_result.get("selected_rankings", [])
        if item is not None
    ]

    ranking_tables = {
        template_key: _normalize_ranking_rows(rankings.get(result_key, []))
        for template_key, result_key in RANKING_RESULT_KEYS.items()
    }
    ranking_notes = {
        f"{key}_note": "" if rows else EMPTY_RANKING_NOTE
        for key, rows in ranking_tables.items()
    }

    context: dict[str, Any] = {
        "report_title": "GTI Top Targets Ranking",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "period": str(ranking_result.get("period") or ""),
        "start_year": ranking_result.get("start_year"),
        "month": ranking_result.get("month"),
        "query_used": str(ranking_result.get("query_used") or ""),
        "collections_analyzed": collections_analyzed,
        "collections_seen": _safe_int(ranking_result.get("collections_seen")),
        "max_collections": _safe_int(ranking_result.get("max_collections")),
        "pages_fetched": _safe_int(ranking_result.get("pages_fetched")),
        "actual_search_requests": _safe_int(ranking_result.get("actual_search_requests")),
        "estimated_api_requests": _safe_int(ranking_result.get("estimated_api_requests")),
        "selected_rankings": selected_rankings,
        "selected_rankings_text": ", ".join(selected_rankings) if selected_rankings else "None",
        "fields_coverage": fields_coverage,
        "methodology": str(ranking_result.get("methodology") or ""),
        "preview_mode_note": "Preview-only mode: uses only fields returned by GTI Intelligence Search.",
        "preview_only_explanation": (
            "This report uses Intelligence Search preview fields and avoids expensive "
            "per-collection detail calls."
        ),
        "executive_summary": (
            f"Analyzed {collections_analyzed} GTI collections for "
            f"{ranking_result.get('period') or 'the selected period'}."
        ),
        "main_top_results": _build_main_top_results(ranking_tables),
        "technical_debug_note": (
            "Technical debug appendix included."
            if include_debug
            else "Technical debug appendix was not included."
        ),
        "debug_attribute_keys_frequency": ranking_result.get("debug_attribute_keys_frequency", {}),
        "debug_sample_collection_fields": ranking_result.get("debug_sample_collection_fields", []),
        "_chart_temp_paths": chart_temp_paths,
    }
    context.update(ranking_tables)
    context.update(ranking_notes)
    context.update(_build_chart_context(template, chart_temp_paths))
    return context


def _normalize_ranking_rows(rows: Any) -> list[dict[str, Any]]:
    """Normalize ranking rows for tables."""

    if not isinstance(rows, list):
        return []

    normalized_rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        normalized_rows.append(
            {
                "rank": _safe_int(row.get("rank"), index),
                "name": str(row.get("name") or "Unknown"),
                "collection_count": _safe_int(
                    row.get("collection_count", row.get("report_count"))
                ),
            }
        )
    return normalized_rows


def _build_main_top_results(ranking_tables: dict[str, list[dict[str, Any]]]) -> str:
    """Summarize the first row of each available ranking."""

    summary_items = []
    for ranking_key, ranking_label in RANKING_LABELS.items():
        rows = ranking_tables.get(ranking_key, [])
        if not rows:
            continue
        first_row = rows[0]
        summary_items.append(
            f"{ranking_label}: {first_row['name']} ({first_row['collection_count']} collections)"
        )

    return "; ".join(summary_items) if summary_items else EMPTY_RANKING_NOTE


def _build_chart_context(
    template: DocxTemplate,
    chart_temp_paths: dict[str, Path],
) -> dict[str, Any]:
    """Prepare chart notes/placeholders for docxtpl templates."""

    chart_keys = (
        "industry_chart",
        "targeted_regions_chart",
        "source_regions_chart",
        "tags_chart",
        "collection_type_chart",
        "timeline_chart",
    )
    context: dict[str, Any] = {}
    for chart_key in chart_keys:
        context[f"{chart_key}_note"] = (
            "Chart image supplied."
            if chart_key in chart_temp_paths
            else "Chart image was not supplied by the app; table is included instead."
        )
        context[chart_key] = (
            InlineImage(template, str(chart_temp_paths[chart_key]), width=Inches(6.2))
            if chart_key in chart_temp_paths
            else ""
        )
    return context


def _write_chart_images(charts: Any) -> dict[str, Path]:
    """Decode optional client-supplied PNG data URLs into temporary image files."""

    if not isinstance(charts, dict):
        return {}

    chart_paths: dict[str, Path] = {}
    for chart_key, chart_data in charts.items():
        if not isinstance(chart_data, str) or not chart_data.startswith("data:image/png;base64,"):
            continue
        # Chart support is intentionally tolerant. The default app currently does
        # not generate PNG charts, so a malformed or missing chart must not fail export.
        try:
            import base64

            png_bytes = base64.b64decode(chart_data.split(",", 1)[1], validate=True)
        except Exception:
            continue
        temp_path = Path(tempfile.gettempdir()) / f"gti_{_slugify(str(chart_key))}.png"
        temp_path.write_bytes(png_bytes)
        chart_paths[str(chart_key)] = temp_path

    return chart_paths


def _append_ranking_tables(document: Document, context: dict[str, Any]) -> None:
    """Append ranking tables to the rendered report document."""

    document.add_page_break()
    document.add_heading("Rankings", level=1)
    for ranking_key, ranking_label in RANKING_LABELS.items():
        rows = context.get(ranking_key, [])
        document.add_heading(ranking_label, level=2)
        if not rows:
            document.add_paragraph(context.get(f"{ranking_key}_note") or EMPTY_RANKING_NOTE)
            continue

        table = document.add_table(rows=1, cols=3)
        table.style = "Table Grid"
        header_cells = table.rows[0].cells
        header_cells[0].text = "#"
        header_cells[1].text = "Name"
        header_cells[2].text = "Collections"
        for row in rows:
            cells = table.add_row().cells
            cells[0].text = str(row["rank"])
            cells[1].text = str(row["name"])
            cells[2].text = str(row["collection_count"])


def _append_chart_notes(document: Document, context: dict[str, Any]) -> None:
    """Append chart images when supplied, otherwise append fallback notes."""

    document.add_heading("Charts", level=1)
    chart_temp_paths = context.get("_chart_temp_paths", {})
    for chart_key in (
        "industry_chart",
        "targeted_regions_chart",
        "source_regions_chart",
        "tags_chart",
        "collection_type_chart",
        "timeline_chart",
    ):
        document.add_heading(chart_key.replace("_", " ").title(), level=2)
        chart_path = chart_temp_paths.get(chart_key) if isinstance(chart_temp_paths, dict) else None
        if chart_path and Path(chart_path).exists():
            try:
                document.add_picture(str(chart_path), width=Inches(6.2))
                continue
            except Exception:
                pass
        document.add_paragraph(context.get(f"{chart_key}_note", "Chart not available."))


def _append_field_coverage(document: Document, context: dict[str, Any]) -> None:
    """Append field coverage diagnostics."""

    document.add_heading("Appendix: Field Coverage", level=1)
    coverage = context.get("fields_coverage", {})
    total = _safe_int(context.get("collections_analyzed"))
    table = document.add_table(rows=1, cols=3)
    table.style = "Table Grid"
    header_cells = table.rows[0].cells
    header_cells[0].text = "Field"
    header_cells[1].text = "Collections with data"
    header_cells[2].text = "Collections analyzed"
    for field_name in (
        "targeted_industries",
        "targeted_regions",
        "source_regions",
        "tags",
        "collection_type",
        "timeline",
        "targeted_organizations",
    ):
        cells = table.add_row().cells
        cells[0].text = field_name
        cells[1].text = str(_safe_int(coverage.get(field_name)))
        cells[2].text = str(total)


def _append_optional_debug(
    document: Document,
    context: dict[str, Any],
    include_debug: bool,
) -> None:
    """Append technical debug data only when explicitly requested."""

    if not include_debug:
        return

    document.add_heading("Technical Debug Appendix", level=1)
    document.add_heading("Attribute Key Frequency", level=2)
    frequency = context.get("debug_attribute_keys_frequency", {})
    if isinstance(frequency, dict) and frequency:
        for key, count in sorted(frequency.items(), key=lambda item: (-_safe_int(item[1]), str(item[0]))):
            document.add_paragraph(f"{key}: {count}")
    else:
        document.add_paragraph("No attribute key diagnostics were available.")

    document.add_heading("Sample Collection Fields", level=2)
    samples = context.get("debug_sample_collection_fields", [])
    if isinstance(samples, list) and samples:
        for sample in samples:
            document.add_paragraph(json.dumps(sample, indent=2, default=str))
    else:
        document.add_paragraph("No sample collection diagnostics were available.")


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert values to int without leaking parsing errors."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _slugify(value: str) -> str:
    """Return a conservative filename slug."""

    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "chart"
