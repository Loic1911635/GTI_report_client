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
    "threat_categories": "Threat categories",
    "collection_type_distribution": "Collection type distribution",
    "timeline": "Timeline",
    "top_targeted_organizations": "Top targeted organizations",
    "top_tactics": "Top MITRE tactics",
    "top_techniques": "Top MITRE techniques",
    "top_subtechniques": "Top MITRE subtechniques",
}

RANKING_RESULT_KEYS = {
    "top_industries": "targeted_industries",
    "top_targeted_regions": "targeted_regions",
    "top_source_regions": "source_regions",
    "top_tags": "tags",
    "threat_categories": "threat_categories",
    "collection_type_distribution": "collection_type",
    "timeline": "timeline",
    "top_targeted_organizations": "targeted_organizations",
}

CROSS_ANALYSIS_LABELS = {
    "industries_by_tags": "Industries by tags / themes",
    "industries_by_collection_type": "Industries by collection type",
    "industries_by_targeted_region": "Industries by targeted region",
    "timeline_by_collection_type": "Timeline by collection type",
    "source_region_by_targeted_region": "Source region by targeted region",
}


def ensure_default_top_ranking_template(template_path: str | Path) -> Path:
    """Create the default importable DOCX template when it is missing."""

    resolved_template_path = Path(template_path)
    if resolved_template_path.exists() and not _template_contains_legacy_text(
        resolved_template_path
    ):
        return resolved_template_path

    _create_default_top_ranking_template(resolved_template_path)
    return resolved_template_path


def _template_contains_legacy_text(template_path: Path) -> bool:
    """Return True when the bundled default template still has old dev copy."""

    try:
        document = Document(template_path)
    except Exception:
        return True

    legacy_markers = (
        "Ranking tables are inserted after template rendering",
        "Chart image supplied.",
        "Field coverage is inserted after template rendering.",
    )
    template_text = "\n".join(paragraph.text for paragraph in document.paragraphs)
    return any(marker in template_text for marker in legacy_markers)


def _create_default_top_ranking_template(template_path: Path) -> None:
    """Write the default clean DOCX template."""

    resolved_template_path = template_path
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
    document.add_paragraph("Field coverage: {{ field_coverage_summary }}")

    document.add_heading("Methodology", level=1)
    document.add_paragraph("GTI query used: {{ query_used }}")
    document.add_paragraph("{{ preview_only_explanation }}")
    document.add_paragraph("Request estimate: {{ estimated_api_requests }} estimated API request(s).")
    document.add_paragraph("Actual Intelligence Search requests: {{ actual_search_requests }}.")
    document.add_paragraph("{{ methodology }}")

    document.add_heading("Rankings", level=1)
    document.add_paragraph("The ranking tables and charts below use already computed preview fields.")

    document.add_heading("Limitations", level=1)
    document.add_paragraph("Counts represent GTI collections, not confirmed incident counts.", style=None)
    document.add_paragraph("Preview-only fields may be incomplete.", style=None)
    document.add_paragraph("Crowdsourced collections may introduce noise.", style=None)

    document.add_heading("Appendix", level=1)
    document.add_paragraph("Detailed field coverage is included below.")
    document.add_paragraph("{{ technical_debug_note }}")

    document.save(resolved_template_path)


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
    _append_cross_analysis(document, context)
    _append_field_coverage(document, context)
    _append_ttp_diagnostics(document, context)
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
    ranking_tables["top_tactics"] = _normalize_ranking_rows(
        ranking_result.get("top_tactics", [])
    )
    ranking_tables["top_techniques"] = _normalize_ranking_rows(
        ranking_result.get("top_techniques", [])
    )
    ranking_tables["top_subtechniques"] = _normalize_ranking_rows(
        ranking_result.get("top_subtechniques", [])
    )
    preview_collections = ranking_result.get("collection_preview_fields", [])
    threat_categories = _build_single_field_ranking(
        preview_collections,
        "threat_categories",
    )
    if threat_categories:
        ranking_tables["threat_categories"] = threat_categories
    cross_analysis = build_cross_analysis_matrices(preview_collections)
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
        "field_coverage_summary": _build_field_coverage_summary(
            fields_coverage,
            collections_analyzed,
        ),
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
        "ttp_analysis": (
            ranking_result.get("ttp_analysis", {})
            if isinstance(ranking_result.get("ttp_analysis"), dict)
            else {}
        ),
        "debug_attribute_keys_frequency": (
            ranking_result.get("debug_attribute_keys_frequency", {})
            if include_debug
            else {}
        ),
        "debug_sample_collection_fields": (
            ranking_result.get("debug_sample_collection_fields", [])
            if include_debug
            else []
        ),
        "_chart_temp_paths": chart_temp_paths,
        "cross_analysis": cross_analysis,
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


def _build_single_field_ranking(
    collections: Any,
    field_name: str,
    top_n: int = 25,
) -> list[dict[str, Any]]:
    """Build a simple distinct-per-collection ranking from preview fields."""

    if not isinstance(collections, list):
        return []

    counter: dict[str, int] = {}
    display: dict[str, str] = {}
    for collection in collections:
        if not isinstance(collection, dict):
            continue
        values = _extract_docx_names(collection.get(field_name))
        for value in set(values):
            normalized = value.casefold()
            display.setdefault(normalized, value)
            counter[normalized] = counter.get(normalized, 0) + 1

    return [
        {
            "rank": index + 1,
            "name": display[key],
            "collection_count": count,
        }
        for index, (key, count) in enumerate(
            sorted(counter.items(), key=lambda item: (-item[1], display[item[0]].casefold()))[:top_n]
        )
    ]


def build_cross_analysis_matrices(
    collections: Any,
    top_rows: int = 8,
    top_columns: int = 8,
) -> dict[str, Any]:
    """Build co-occurrence matrices from collection preview fields only."""

    if not isinstance(collections, list):
        collections = []

    matrix_specs = {
        "industries_by_tags": ("targeted_industries", "tags"),
        "industries_by_collection_type": ("targeted_industries", "collection_type"),
        "industries_by_targeted_region": ("targeted_industries", "targeted_regions"),
        "timeline_by_collection_type": ("timeline", "collection_type"),
        "source_region_by_targeted_region": ("source_regions", "targeted_regions"),
    }

    return {
        matrix_key: _build_cooccurrence_matrix(
            collections=collections,
            row_field=row_field,
            column_field=column_field,
            top_rows=top_rows,
            top_columns=top_columns,
        )
        for matrix_key, (row_field, column_field) in matrix_specs.items()
    }


def _build_cooccurrence_matrix(
    collections: list[Any],
    row_field: str,
    column_field: str,
    top_rows: int,
    top_columns: int,
) -> dict[str, Any]:
    """Build one distinct-per-collection co-occurrence matrix."""

    pair_counter: dict[tuple[str, str], int] = {}
    row_counter: dict[str, int] = {}
    column_counter: dict[str, int] = {}
    row_display: dict[str, str] = {}
    column_display: dict[str, str] = {}
    eligible_collections = 0

    for collection in collections:
        if not isinstance(collection, dict):
            continue
        row_values = _extract_matrix_values(collection, row_field)
        column_values = _extract_matrix_values(collection, column_field)
        if not row_values or not column_values:
            continue

        eligible_collections += 1
        normalized_rows = {_normalize_matrix_value(value): value for value in row_values}
        normalized_columns = {_normalize_matrix_value(value): value for value in column_values}
        for row_key, row_label in normalized_rows.items():
            if not row_key:
                continue
            row_display.setdefault(row_key, row_label)
            row_counter[row_key] = row_counter.get(row_key, 0) + 1
        for column_key, column_label in normalized_columns.items():
            if not column_key:
                continue
            column_display.setdefault(column_key, column_label)
            column_counter[column_key] = column_counter.get(column_key, 0) + 1
        for row_key in normalized_rows:
            for column_key in normalized_columns:
                if not row_key or not column_key:
                    continue
                pair_counter[(row_key, column_key)] = pair_counter.get((row_key, column_key), 0) + 1

    selected_rows = [
        key
        for key, _ in sorted(
            row_counter.items(),
            key=lambda item: (-item[1], row_display[item[0]].casefold()),
        )[:top_rows]
    ]
    selected_columns = [
        key
        for key, _ in sorted(
            column_counter.items(),
            key=lambda item: (-item[1], column_display[item[0]].casefold()),
        )[:top_columns]
    ]
    table_rows = []
    for row_key in selected_rows:
        cells = [
            pair_counter.get((row_key, column_key), 0)
            for column_key in selected_columns
        ]
        table_rows.append(
            {
                "label": row_display[row_key],
                "cells": cells,
            }
        )

    top_cells = [
        {
            "row": row_display[row_key],
            "column": column_display[column_key],
            "count": count,
        }
        for (row_key, column_key), count in pair_counter.items()
    ]
    top_cells = sorted(
        top_cells,
        key=lambda item: (-item["count"], item["row"].casefold(), item["column"].casefold()),
    )[:5]

    return {
        "eligible_collections": eligible_collections,
        "columns": [column_display[key] for key in selected_columns],
        "rows": table_rows,
        "top_cells": top_cells,
        "interpretation": _build_cross_analysis_interpretation(top_cells, eligible_collections),
    }


def _extract_matrix_values(collection: dict[str, Any], field_name: str) -> list[str]:
    """Extract field values for cross-analysis matrices."""

    if field_name == "timeline":
        bucket = _build_docx_timeline_bucket(collection.get("creation_date"))
        return [bucket] if bucket else []

    return _extract_docx_names(collection.get(field_name))


def _extract_docx_names(value: Any) -> list[str]:
    """Extract readable values from preview fields for reporting."""

    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        names: list[str] = []
        for item in value:
            names.extend(_extract_docx_names(item))
        return _dedupe_names(names)
    if isinstance(value, dict):
        names: list[str] = []
        for key in ("name", "label", "title", "value", "id"):
            if key in value:
                names.extend(_extract_docx_names(value.get(key)))
                break
        for key, nested_value in value.items():
            if key in ("name", "label", "title", "value", "id"):
                continue
            names.extend(_extract_docx_names(nested_value))
        return _dedupe_names(names)

    return []


def _dedupe_names(values: list[str]) -> list[str]:
    """Dedupe extracted names while preserving order."""

    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.casefold()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(value)
    return deduped


def _normalize_matrix_value(value: str) -> str:
    """Normalize a matrix label for distinct-per-collection counting."""

    return " ".join(str(value).split()).casefold()


def _build_docx_timeline_bucket(value: Any) -> str | None:
    """Build a YYYY-MM bucket for cross-analysis timeline rows."""

    if value is None:
        return None
    text = str(value).strip()
    match = re.match(r"^(\d{4})-(\d{2})", text)
    if match:
        return f"{match.group(1)}-{match.group(2)}"
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        try:
            timestamp = float(text)
            if timestamp > 1_000_000_000_000:
                timestamp = timestamp / 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m")
        except (OSError, OverflowError, ValueError):
            return None
    return None


def _build_cross_analysis_interpretation(
    top_cells: list[dict[str, Any]],
    eligible_collections: int,
) -> str:
    """Generate a concise interpretation from top co-occurrence cells."""

    if not top_cells:
        return (
            "Not enough overlapping preview metadata was present to build this matrix."
        )

    strongest = top_cells[0]
    return (
        f"The strongest metadata co-occurrence is {strongest['row']} x "
        f"{strongest['column']} with {strongest['count']} GTI collection(s) "
        f"among {eligible_collections} eligible collection(s). These counts reflect "
        "GTI collection metadata, not confirmed incident counts."
    )


def _build_field_coverage_summary(
    fields_coverage: dict[str, Any],
    collections_analyzed: int,
) -> str:
    """Create a compact field coverage sentence for the executive summary."""

    if not fields_coverage:
        return "Field coverage was not available."

    labels = {
        "targeted_industries": "targeted industries",
        "targeted_regions": "targeted regions",
        "source_regions": "source regions",
        "tags": "tags / themes",
        "collection_type": "collection type",
        "timeline": "timeline",
        "targeted_organizations": "targeted organizations",
    }
    parts = [
        f"{label}: {_safe_int(fields_coverage.get(key))}/{collections_analyzed}"
        for key, label in labels.items()
    ]
    return "; ".join(parts)


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


def _append_cross_analysis(document: Document, context: dict[str, Any]) -> None:
    """Append cross-analysis matrices after basic rankings."""

    document.add_heading("Cross-analysis", level=1)
    document.add_paragraph(
        "These matrices count co-occurring GTI collection metadata values. Counts "
        "represent GTI collections, not confirmed incident counts."
    )
    matrices = context.get("cross_analysis", {})
    if not isinstance(matrices, dict) or not matrices:
        document.add_paragraph("Cross-analysis was not available for this export.")
        return

    for matrix_key, matrix in matrices.items():
        label = CROSS_ANALYSIS_LABELS.get(matrix_key, matrix_key)
        document.add_heading(label, level=2)
        eligible = _safe_int(matrix.get("eligible_collections") if isinstance(matrix, dict) else 0)
        document.add_paragraph(f"Eligible collections: {eligible}")
        document.add_paragraph(
            str(matrix.get("interpretation") or "No interpretation available.")
            if isinstance(matrix, dict)
            else "No interpretation available."
        )

        columns = matrix.get("columns", []) if isinstance(matrix, dict) else []
        rows = matrix.get("rows", []) if isinstance(matrix, dict) else []
        if not columns or not rows:
            document.add_paragraph("Not enough overlapping preview fields to build this matrix.")
            continue

        max_value = max(
            [max(row.get("cells", [0]) or [0]) for row in rows if isinstance(row, dict)]
            or [0]
        )
        table = document.add_table(rows=1, cols=len(columns) + 1)
        table.style = "Table Grid"
        header_cells = table.rows[0].cells
        header_cells[0].text = ""
        for index, column in enumerate(columns, start=1):
            header_cells[index].text = str(column)

        for row in rows:
            cells = table.add_row().cells
            cells[0].text = str(row.get("label", ""))
            for index, value in enumerate(row.get("cells", []), start=1):
                cells[index].text = str(value)
                _shade_cell(cells[index], _heatmap_shade(_safe_int(value), max_value))


def _heatmap_shade(value: int, max_value: int) -> str:
    """Return a light teal heatmap color for a matrix cell."""

    if value <= 0 or max_value <= 0:
        return "FFFFFF"
    intensity = min(1.0, value / max_value)
    # Blend white toward the product teal color.
    base = (13, 127, 122)
    blended = tuple(round(255 - (255 - channel) * intensity * 0.55) for channel in base)
    return "".join(f"{channel:02X}" for channel in blended)


def _shade_cell(cell: Any, fill: str) -> None:
    """Apply a background fill color to a Word table cell."""

    try:
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn

        tc_pr = cell._tc.get_or_add_tcPr()
        shading = OxmlElement("w:shd")
        shading.set(qn("w:fill"), fill)
        tc_pr.append(shading)
    except Exception:
        return


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


def _append_ttp_diagnostics(document: Document, context: dict[str, Any]) -> None:
    """Append hard TTP diagnostic fields used by the app."""

    ttp = context.get("ttp_analysis", {})
    if not isinstance(ttp, dict) or not ttp:
        return

    first_debug = ttp.get("ttp_first_successful_debug", {})
    if not isinstance(first_debug, dict):
        first_debug = {}

    document.add_heading("Appendix: TTP Diagnostics", level=1)
    if ttp.get("warning_message"):
        document.add_paragraph(str(ttp.get("warning_message")))

    rows = (
        ("ttp_lookups_attempted", ttp.get("ttp_lookups_attempted", 0)),
        ("ttp_lookups_succeeded", ttp.get("ttp_lookups_succeeded", 0)),
        ("ttp_eligible_collections", ttp.get("ttp_eligible_collections", 0)),
        (
            "ttp_first_successful_collection_id",
            ttp.get("ttp_first_successful_collection_id", ""),
        ),
        (
            "ttp_first_successful_debug.tactics_count",
            first_debug.get("tactics_count", 0),
        ),
        ("top_tactics count", len(context.get("top_tactics", []))),
        ("top_techniques count", len(context.get("top_techniques", []))),
        ("top_subtechniques count", len(context.get("top_subtechniques", []))),
    )

    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    header_cells = table.rows[0].cells
    header_cells[0].text = "Diagnostic"
    header_cells[1].text = "Value"
    for key, value in rows:
        cells = table.add_row().cells
        cells[0].text = str(key)
        cells[1].text = str(value)

    document.add_heading("ttp_lookup_attempt_samples", level=2)
    samples = ttp.get("ttp_lookup_attempt_samples", [])
    if isinstance(samples, list) and samples:
        document.add_paragraph(json.dumps(samples, indent=2, default=str))
    else:
        document.add_paragraph("No TTP lookup samples were recorded.")


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
