"""FastAPI entrypoint for the GTI report generator MVP."""

from __future__ import annotations

import time
import tempfile
import base64
import binascii
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from backend.routes.dtm_dashboard import router as dtm_dashboard_router

from backend.gti_client import (
    GTIClientError,
    build_ioc_stream_report,
    MAX_TOP_TARGETS_DETAIL_LOOKUPS,
    MockGTIClient,
    aggregate_top_targets,
    fetch_ioc_stream,
    lookup_domain,
    test_single_mitre_tree,
)
from backend.dtm_dashboard_docx import generate_dtm_dashboard_docx
from backend.ioc_stream_docx import generate_ioc_stream_docx
from backend.report_generator import (
    build_downloadable_filename,
    generate_ioc_enrichment_markdown_report,
    generate_markdown_report,
    normalize_output_format,
    normalize_requested_sections,
    normalize_threat_landscape,
)
from backend.top_ranking_docx import (
    build_cross_analysis_matrices,
    ensure_default_top_ranking_template,
    generate_top_ranking_docx,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

_CACHE_TTL = 300  # seconds
_api_cache: dict[str, tuple[float, Any]] = {}


def _cache_get(key: str) -> Any | None:
    entry = _api_cache.get(key)
    if entry and time.time() - entry[0] < _CACHE_TTL:
        return entry[1]
    _api_cache.pop(key, None)
    return None


def _cache_set(key: str, value: Any) -> None:
    _api_cache[key] = (time.time(), value)
INDEX_FILE = PROJECT_ROOT / "index.html"
APP_JS_FILE = PROJECT_ROOT / "app.js"
STYLE_CSS_FILE = PROJECT_ROOT / "style.css"
TOP_RANKING_TEMPLATE_FILE = PROJECT_ROOT / "templates" / "gti_top_ranking_template.docx"


app = FastAPI(
    title="GTI Report Generator MVP",
    description="Student internship MVP for generating Markdown reports from mock GTI data.",
    version="0.1.0",
)
app.include_router(dtm_dashboard_router)


class GenerateReportRequest(BaseModel):
    """Input payload for the report generation endpoint."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    report_type: str = Field(..., description="Type of report to generate.")
    year: int = Field(..., description="Year used to scope the report.")
    target: str | None = Field(
        default=None,
        description="Optional company, region, sector, or other report target.",
    )
    sections: list[str] = Field(
        default_factory=list,
        description="Selected report sections to include in the generated report.",
    )
    output_format: str = Field(
        default="markdown",
        description="Requested report output format.",
    )


class GenerateReportResponse(BaseModel):
    """Response payload returned by the report generation endpoint."""

    status: str
    report_markdown: str
    raw_data: dict[str, Any]
    downloadable_filename: str


class CollectionDetailsRequest(BaseModel):
    """Input payload for single-collection diagnostics."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    collection_id: str = Field(..., description="GTI collection identifier.")


class TopTargetsRequest(BaseModel):
    """Input payload for the Top Targets Ranking workflow."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    start_year: int = Field(default=2024, ge=2018, description="Start year of the analysis period.")
    end_year: int | None = Field(default=None, description="End year (inclusive). Defaults to start_year.")
    month: int | None = Field(default=None, ge=1, le=12, description="Optional month for a single-month ranking.")
    top_n: int = Field(default=10, ge=1, le=50, description="Number of top results to return.")
    max_collections: int = Field(default=1000, ge=1, description="Stop after this many collections.")
    selected_rankings: list[str] = Field(default_factory=lambda: ["targeted_industries", "targeted_organizations"], description="Ranking sections to compute from preview fields.")
    deep_organization_lookup: bool = Field(default=False, description="Enable bounded per-collection organization detail lookups.")
    max_detail_lookups: int = Field(default=0, ge=0, le=MAX_TOP_TARGETS_DETAIL_LOOKUPS, description="Maximum per-collection detail lookups when deep organization lookup is enabled.")
    ttp_source: str = Field(default="search_reports", description="TTP source mode: search_reports or ranking_collections.")
    max_ttp_candidates: int = Field(default=25, ge=1, le=100, description="Maximum report candidates for MITRE tree lookups.")
    ttp_query_filter: str | None = Field(default=None, description="Optional extra Intelligence Search filter for TTP report candidates.")
    include_ttp_analysis: bool = Field(default=False, description="Run MITRE ATT&CK TTP analysis.")
    include_debug: bool = Field(default=False, description="Return technical diagnostics.")


class TopTargetsResponse(BaseModel):
    """Response payload returned by the Top Targets Ranking workflow."""

    status: str
    period: str
    month: int | None = None
    selected_rankings: list[str] = Field(default_factory=list)
    collections_analyzed: int
    collections_seen: int = 0
    collections_with_targeted_industries: int = 0
    collections_without_targeted_industries: int = 0
    unique_industries_count: int = 0
    pages_fetched: int = 0
    max_collections: int = 1000
    deep_organization_lookup: bool = False
    max_detail_lookups: int = 0
    api_request_estimate: dict[str, Any] = Field(default_factory=dict)
    estimated_api_requests: int = 0
    actual_search_requests: int = 0
    fields_coverage: dict[str, int] = Field(default_factory=dict)
    debug_attribute_keys_frequency: dict[str, int] | None = None
    debug_sample_collection_fields: list[dict[str, Any]] | None = None
    technical_debug: dict[str, Any] | None = None
    company_detail_lookups_attempted: int
    company_detail_lookups_succeeded: int
    top_industries: list[dict[str, Any]]
    top_companies: list[dict[str, Any]]
    top_companies_status: str = "ok"
    ttp_analysis: dict[str, Any] = Field(default_factory=dict)
    top_tactics: list[dict[str, Any]] = Field(default_factory=list)
    top_techniques: list[dict[str, Any]] = Field(default_factory=list)
    top_subtechniques: list[dict[str, Any]] = Field(default_factory=list)
    rankings: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    cross_analysis: dict[str, Any] = Field(default_factory=dict)
    collection_preview_fields: list[dict[str, Any]] = Field(default_factory=list)
    query_used: str
    methodology: str


class TopRankingDocxExportRequest(BaseModel):
    """Input payload for DOCX export from an existing Top Rankings result."""

    ranking_result: dict[str, Any] = Field(..., description="Already computed Top Rankings result.")
    include_technical_debug: bool = Field(
        default=False,
        description="Include debug appendix with raw field diagnostics.",
    )
    custom_template_base64: str | None = Field(
        default=None,
        description="Optional base64-encoded DOCX template.",
    )
    custom_template_filename: str | None = Field(
        default=None,
        description="Original custom template filename.",
    )


class IocStreamDocxExportRequest(BaseModel):
    """Input payload for DOCX export from an existing Recent IoC Stream Sample report."""

    ioc_stream_report: dict[str, Any] = Field(..., description="Already computed Recent IoC Stream Sample report.")


class DtmDashboardDocxExportRequest(BaseModel):
    """Input payload for DOCX export from an existing DTM Dashboard result."""

    dashboard_result: dict[str, Any] = Field(..., description="Already computed DTM Dashboard result.")
    max_chart_items: int = Field(default=10, ge=1, le=100, description="Maximum number of items to show in bar charts (default 10).")


class MitreTreeTestResponse(BaseModel):
    """Response payload returned by the direct MITRE tree diagnostic."""

    status: str
    status_code: int
    error_message: str
    top_level_keys: list[str]
    data_keys: list[str]
    tactics_count: int
    first_tactic_sample: Any = None
    parsed_entries_count: int
    first_parsed_entries: list[dict[str, Any]]
    raw_data: Any


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    """Serve the single-page frontend from the FastAPI backend."""

    return FileResponse(INDEX_FILE, headers={"Cache-Control": "no-store"})


@app.get("/app.js", include_in_schema=False)
def serve_app_js() -> FileResponse:
    """Serve the frontend JavaScript bundle for the MVP page."""

    return FileResponse(
        APP_JS_FILE,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/style.css", include_in_schema=False)
def serve_style_css() -> FileResponse:
    """Serve the frontend stylesheet for the MVP page."""

    return FileResponse(
        STYLE_CSS_FILE,
        media_type="text/css",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/generate-report", response_model=GenerateReportResponse)
def generate_report(request: GenerateReportRequest) -> GenerateReportResponse:
    """Generate a Markdown report from GTI/VirusTotal or the mock fallback."""

    normalized_target = request.target.strip() if request.target else None

    try:
        retired_report_types = {
            "Industry Snapshot Explorer",
            "Company Exposure / DTM",
            "GTI Intelligence Search",
        }
        if request.report_type in retired_report_types:
            raise ValueError(f"The {request.report_type} feature has been retired.")

        normalized_sections = normalize_requested_sections(request.sections)
        normalized_output_format = normalize_output_format(request.output_format)

        if request.report_type == "IoC Enrichment" and normalized_target:
            raw_data = lookup_domain(
                api_key=request.api_key,
                domain=normalized_target,
            )
            report_markdown = generate_ioc_enrichment_markdown_report(
                raw_data,
                sections=normalized_sections,
            )
        else:
            # We keep the original mock flow as a fallback for non-IoC reports
            # and for any legacy requests that do not provide a target.
            client = MockGTIClient(api_key=request.api_key)
            raw_data = client.fetch_threat_landscape(
                report_type=request.report_type,
                year=request.year,
                target=normalized_target,
            )

            normalized_data = normalize_threat_landscape(raw_data)
            report_markdown = generate_markdown_report(
                normalized_data=normalized_data,
                report_type=request.report_type,
                year=request.year,
                sections=normalized_sections,
                raw_data=raw_data,
                target=normalized_target,
            )

        return GenerateReportResponse(
            status="success",
            report_markdown=report_markdown,
            raw_data=raw_data,
            downloadable_filename=build_downloadable_filename(
                report_type=request.report_type,
                year=request.year,
                target=normalized_target,
                output_format=normalized_output_format,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        # This broad exception is acceptable for an MVP because it keeps the
        # endpoint behavior simple while still surfacing useful debug details.
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {exc}",
        ) from exc


@app.post(
    "/explore/top-targets",
    response_model=TopTargetsResponse,
    response_model_exclude_none=True,
)
def explore_top_targets_workflow(request: TopTargetsRequest) -> TopTargetsResponse:
    """Aggregate top targeted industries and companies from GTI collections."""

    try:
        result = aggregate_top_targets(
            api_key=request.api_key,
            start_year=request.start_year,
            end_year=request.end_year,
            month=request.month,
            top_n=request.top_n,
            max_collections=request.max_collections,
            selected_rankings=request.selected_rankings,
            deep_organization_lookup=request.deep_organization_lookup,
            max_detail_lookups=request.max_detail_lookups,
            ttp_source=request.ttp_source,
            max_ttp_candidates=request.max_ttp_candidates,
            ttp_query_filter=request.ttp_query_filter,
            include_ttp_analysis=request.include_ttp_analysis,
            include_debug=request.include_debug,
        )
        cross_analysis = build_cross_analysis_matrices(
            result.get("collection_preview_fields", [])
        )
        return TopTargetsResponse(
            status="success",
            period=str(result["period"]),
            month=result.get("month"),
            selected_rankings=result.get("selected_rankings", []),
            collections_analyzed=int(result["collections_analyzed"]),
            collections_seen=int(result.get("collections_seen", 0)),
            collections_with_targeted_industries=int(result.get("collections_with_targeted_industries", 0)),
            collections_without_targeted_industries=int(result.get("collections_without_targeted_industries", 0)),
            unique_industries_count=int(result.get("unique_industries_count", 0)),
            pages_fetched=int(result.get("pages_fetched", 0)),
            max_collections=int(result.get("max_collections", 1000)),
            deep_organization_lookup=bool(result.get("deep_organization_lookup", False)),
            max_detail_lookups=int(result.get("max_detail_lookups", 0)),
            api_request_estimate=result.get("api_request_estimate", {}),
            estimated_api_requests=int(result.get("estimated_api_requests", 0)),
            actual_search_requests=int(result.get("actual_search_requests", 0)),
            fields_coverage=result.get("fields_coverage", {}),
            debug_attribute_keys_frequency=result.get("debug_attribute_keys_frequency"),
            debug_sample_collection_fields=result.get("debug_sample_collection_fields"),
            technical_debug=result.get("technical_debug"),
            company_detail_lookups_attempted=int(
                result["company_detail_lookups_attempted"]
            ),
            company_detail_lookups_succeeded=int(
                result["company_detail_lookups_succeeded"]
            ),
            top_industries=result["top_industries"],
            top_companies=result["top_companies"],
            top_companies_status=str(result.get("top_companies_status", "ok")),
            ttp_analysis=result.get("ttp_analysis", {}),
            top_tactics=result.get("top_tactics", []),
            top_techniques=result.get("top_techniques", []),
            top_subtechniques=result.get("top_subtechniques", []),
            rankings=result.get("rankings", {}),
            cross_analysis=cross_analysis,
            collection_preview_fields=result.get("collection_preview_fields", []),
            query_used=str(result["query_used"]),
            methodology=str(result["methodology"]),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Top targets ranking failed: {exc}",
        ) from exc


@app.post(
    "/explore/mitre-tree-test",
    response_model=MitreTreeTestResponse,
)
def test_mitre_tree_workflow(request: CollectionDetailsRequest) -> MitreTreeTestResponse:
    """Run a direct single-collection MITRE tree diagnostic."""

    try:
        result = test_single_mitre_tree(
            api_key=request.api_key,
            collection_id=request.collection_id,
        )
        status_code = int(result["status_code"])
        return MitreTreeTestResponse(
            status="success" if status_code == 200 else "upstream_error",
            status_code=status_code,
            error_message=str(result.get("error_message") or ""),
            top_level_keys=result.get("top_level_keys", []),
            data_keys=result.get("data_keys", []),
            tactics_count=int(result.get("tactics_count", 0)),
            first_tactic_sample=result.get("first_tactic_sample"),
            parsed_entries_count=int(result.get("parsed_entries_count", 0)),
            first_parsed_entries=result.get("first_parsed_entries", []),
            raw_data=result.get("raw_data"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/export/top-ranking-docx", include_in_schema=False)
def export_top_ranking_docx(request: TopRankingDocxExportRequest) -> FileResponse:
    """Generate a DOCX report from an already computed Top Rankings result."""

    try:
        ranking_result = dict(request.ranking_result or {})
        ranking_result.pop("api_key", None)
        ranking_result.pop("x_api_key", None)
        ranking_result["include_technical_debug"] = request.include_technical_debug

        template_path = ensure_default_top_ranking_template(TOP_RANKING_TEMPLATE_FILE)
        if request.custom_template_base64:
            try:
                template_bytes = base64.b64decode(
                    request.custom_template_base64,
                    validate=True,
                )
            except (binascii.Error, ValueError) as exc:
                raise ValueError("The uploaded template is not valid base64.") from exc
            if not template_bytes.startswith(b"PK"):
                raise ValueError("The uploaded template must be a .docx file.")
            custom_template_path = (
                Path(tempfile.gettempdir())
                / "gti_report_client"
                / "uploaded_top_ranking_template.docx"
            )
            custom_template_path.parent.mkdir(parents=True, exist_ok=True)
            custom_template_path.write_bytes(template_bytes)
            template_path = custom_template_path

        output_dir = Path(tempfile.gettempdir()) / "gti_report_client"
        output_dir.mkdir(parents=True, exist_ok=True)
        period_slug = str(ranking_result.get("period") or "top-rankings").lower()
        period_slug = "".join(
            character if character.isalnum() else "-"
            for character in period_slug
        ).strip("-") or "top-rankings"
        output_path = output_dir / f"gti-top-targets-ranking-{period_slug}.docx"

        generated_path = generate_top_ranking_docx(
            ranking_result=ranking_result,
            template_path=str(template_path),
            output_path=str(output_path),
        )
        return FileResponse(
            generated_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=Path(generated_path).name,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Top ranking DOCX export failed: {exc}",
        ) from exc


@app.post("/export/ioc-stream-docx", include_in_schema=False)
def export_ioc_stream_docx(request: IocStreamDocxExportRequest) -> FileResponse:
    """Generate a DOCX report from an already computed Recent IoC Stream Sample report."""

    try:
        report_data = dict(request.ioc_stream_report or {})
        report_data.pop("api_key", None)
        report_data.pop("x_api_key", None)

        output_dir = Path(tempfile.gettempdir()) / "gti_report_client"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "gti-ioc-stream-report.docx"
        generated_path = generate_ioc_stream_docx(
            report_data=report_data,
            output_path=str(output_path),
        )
        return FileResponse(
            generated_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=Path(generated_path).name,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Recent IoC Stream Sample DOCX export failed: {exc}",
        ) from exc


@app.post("/export/dtm-dashboard-docx", include_in_schema=False)
def export_dtm_dashboard_docx(request: DtmDashboardDocxExportRequest) -> FileResponse:
    """Generate a DOCX report from an already computed DTM Dashboard result."""

    try:
        dashboard_result = dict(request.dashboard_result or {})
        dashboard_result.pop("api_key", None)
        dashboard_result.pop("x_api_key", None)

        output_dir = Path(tempfile.gettempdir()) / "gti_report_client"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "gti-dtm-dashboard.docx"
        generated_path = generate_dtm_dashboard_docx(
            dashboard_result=dashboard_result,
            output_path=str(output_path),
            max_chart_items=request.max_chart_items,
        )
        return FileResponse(
            generated_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=Path(generated_path).name,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"DTM Dashboard DOCX export failed: {exc}",
        ) from exc


@app.get("/api/ioc-stream/report")
def api_ioc_stream_report(
    entity_type: str = Query(default="all"),
    origin: str = Query(default="all"),
    enrich: bool = Query(default=True),
    enrichment_limit: int | None = Query(default=None, ge=0, le=500),
    descriptors_only: bool = Query(default=False),
    cursor: str | None = Query(default=None),
    order: str = Query(default="date-"),
    collection_mode: str = Query(default="time_window"),
    time_window: str | None = Query(default=None),
    start_date: str | None = Query(default=None),
    end_date: str | None = Query(default=None),
    advanced_gti_filter_override: str | None = Query(default=None),
    pages_to_fetch: int = Query(default=5),
    max_pages: int | None = Query(default=None),
    x_api_key: str = Header(default=""),
) -> dict[str, Any]:
    """Return a read-only IoC Stream report from GTI IoC Stream."""

    api_key = (x_api_key or os.environ.get("GTI_API_KEY") or "").strip()
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="x-api-key header or GTI_API_KEY environment variable is required.",
        )

    try:
        stream_result = fetch_ioc_stream(
            api_key=api_key,
            entity_type=entity_type,
            origin=origin,
            descriptors_only=False,
            cursor=cursor,
            order=order,
            collection_mode=collection_mode,
            time_window=time_window,
            start_date=start_date,
            end_date=end_date,
            advanced_gti_filter_override=advanced_gti_filter_override,
            pages_to_fetch=pages_to_fetch,
            max_pages=max_pages,
        )
        status_code = int(stream_result.get("status_code", 0))
        if status_code in (401, 403):
            raise HTTPException(
                status_code=status_code,
                detail=(
                    "Unable to access IoC Stream. This may require a valid GTI "
                    "subscription and an API key with access to IoC Stream."
                ),
            )
        if status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="GTI rate limit reached. Try again later or reduce the limit.",
            )
        if status_code != 200:
            detail = _extract_upstream_error_detail(stream_result.get("raw_data"))
            raise HTTPException(
                status_code=502,
                detail=detail or f"GTI IoC Stream request failed with status {status_code}.",
            )

        report = build_ioc_stream_report(
            stream_result,
            api_key=api_key,
            enrich=enrich,
            enrichment_limit=enrichment_limit,
        )
        return {
            "status": "success",
            "message": (
                "No recent IoC Stream indicators were returned for the requested pages."
                if report["summary"]["total_iocs"] == 0
                else "IoC Stream report generated."
            ),
            **report,
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Recent IoC Stream Sample report failed: {exc}",
        ) from exc


def _extract_upstream_error_detail(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code") or "").strip()
    if error:
        return str(error).strip()
    return str(payload.get("message") or payload.get("detail") or "").strip()


@app.post("/explore/countries-industries")
def invalid_countries_industries_explorer() -> None:
    """Mark the old countries_industries explorer as invalid."""

    raise HTTPException(
        status_code=410,
        detail=(
            "The countries_industries explorer was removed and should no longer "
            "be used."
        ),
    )
