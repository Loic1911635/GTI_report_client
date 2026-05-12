"""FastAPI entrypoint for the GTI report generator MVP."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.gti_client import (
    GTIClientError,
    MAX_TOP_TARGETS_DETAIL_LOOKUPS,
    MockGTIClient,
    aggregate_top_targets,
    explore_industry_snapshots,
    get_collection_details,
    get_top_companies,
    get_top_industries,
    intelligence_search,
    list_dtm_alerts,
    list_dtm_monitors,
    lookup_domain,
)
from backend.report_generator import (
    build_downloadable_filename,
    generate_ioc_enrichment_markdown_report,
    generate_markdown_report,
    normalize_output_format,
    normalize_requested_sections,
    normalize_threat_landscape,
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


app = FastAPI(
    title="GTI Report Generator MVP",
    description="Student internship MVP for generating Markdown reports from mock GTI data.",
    version="0.1.0",
)


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


class ExplorerRequest(BaseModel):
    """Input payload for GTI exploration workflows."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    company_name: str | None = Field(default=None)
    primary_domain: str | None = Field(default=None)
    keywords: str | None = Field(default=None)
    monitor_id: str | None = Field(default=None)


class IntelligenceSearchRequest(BaseModel):
    """Input payload for the GTI Intelligence Search workflow."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    query: str = Field(..., description="GTI Intelligence Search query.")
    limit: int = Field(default=10, ge=1, description="Requested result page size.")
    descriptors_only: bool = Field(
        default=False,
        description="Request descriptors_only mode from the GTI API.",
    )
    cursor: str | None = Field(
        default=None,
        description="Optional pagination cursor for the next GTI page.",
    )


class CollectionDetailsRequest(BaseModel):
    """Input payload for the Industry Profile Analyzer workflow."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    collection_id: str = Field(..., description="GTI collection identifier.")


class TopTargetsRequest(BaseModel):
    """Input payload for the Top Targets Ranking workflow."""

    api_key: str = Field(..., description="GTI or VirusTotal API key.")
    start_year: int = Field(default=2024, ge=2018, description="Start year of the analysis period.")
    end_year: int | None = Field(default=None, description="End year (inclusive). Defaults to start_year.")
    top_n: int = Field(default=10, ge=1, le=50, description="Number of top results to return.")
    max_collections: int | None = Field(default=None, ge=1, description="Stop after this many collections. None = paginate until exhausted.")
    deep_organization_lookup: bool = Field(default=False, description="Enable bounded per-collection organization detail lookups.")
    max_detail_lookups: int | None = Field(default=None, ge=0, le=MAX_TOP_TARGETS_DETAIL_LOOKUPS, description="Maximum per-collection detail lookups when deep organization lookup is enabled.")


class TopTargetsResponse(BaseModel):
    """Response payload returned by the Top Targets Ranking workflow."""

    status: str
    period: str
    collections_analyzed: int
    collections_seen: int = 0
    collections_with_targeted_industries: int = 0
    collections_without_targeted_industries: int = 0
    unique_industries_count: int = 0
    pages_fetched: int = 0
    max_collections: int | None = None
    deep_organization_lookup: bool = False
    max_detail_lookups: int = 0
    api_request_estimate: dict[str, Any] = Field(default_factory=dict)
    company_detail_lookups_attempted: int
    company_detail_lookups_succeeded: int
    top_industries: list[dict[str, Any]]
    top_companies: list[dict[str, Any]]
    top_companies_status: str = "ok"
    collection_preview_fields: list[dict[str, Any]] = Field(default_factory=list)
    query_used: str
    methodology: str


class IndustrySnapshotExplorerResponse(BaseModel):
    """Response payload returned by the Industry Snapshot explorer."""

    status: str
    http_status: int
    snapshot_count: int
    snapshots: list[dict[str, Any]]
    endpoint_results: list[dict[str, Any]]
    raw_json: Any


class DTMMonitorExplorerResponse(BaseModel):
    """Response payload returned by the DTM Monitor explorer."""

    status: str
    http_status: int
    domain_filter: str
    requested_size: int
    page_count: int
    truncated: bool
    total_collected: int
    total_monitor_count: int
    monitor_count: int
    monitors: list[dict[str, Any]]
    endpoint_results: list[dict[str, Any]]
    raw_json: Any


class DTMAlertExplorerResponse(BaseModel):
    """Response payload returned by the DTM Alert explorer."""

    status: str
    http_status: int
    requested_size: int
    monitor_id: str
    page_count: int
    truncated: bool
    total_collected: int
    total_alert_count: int
    alert_count: int
    alerts: list[dict[str, Any]]
    simplified_preview: list[dict[str, Any]]
    endpoint_results: list[dict[str, Any]]
    raw_data: Any
    raw_json: Any


class IntelligenceSearchResponse(BaseModel):
    """Response payload returned by the GTI Intelligence Search workflow."""

    status: str
    status_code: int
    total_collected: int
    next_cursor: str | None = None
    simplified_preview: list[dict[str, Any]]
    raw_data: Any


class CollectionDetailsResponse(BaseModel):
    """Response payload returned by the Industry Profile Analyzer workflow."""

    status: str
    status_code: int
    collection_id: str
    experimental_exposure_score: int
    analysis: dict[str, Any]
    raw_data: Any


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    """Serve the single-page frontend from the FastAPI backend."""

    return FileResponse(INDEX_FILE)


@app.get("/app.js", include_in_schema=False)
def serve_app_js() -> FileResponse:
    """Serve the frontend JavaScript bundle for the MVP page."""

    return FileResponse(APP_JS_FILE, media_type="application/javascript")


@app.get("/style.css", include_in_schema=False)
def serve_style_css() -> FileResponse:
    """Serve the frontend stylesheet for the MVP page."""

    return FileResponse(STYLE_CSS_FILE, media_type="text/css")


@app.post("/generate-report", response_model=GenerateReportResponse)
def generate_report(request: GenerateReportRequest) -> GenerateReportResponse:
    """Generate a Markdown report from GTI/VirusTotal or the mock fallback."""

    normalized_target = request.target.strip() if request.target else None

    try:
        if request.report_type == "Industry Snapshot Explorer":
            raise ValueError("Use the explorer button for this report type.")
        if request.report_type == "Company Exposure / DTM":
            raise ValueError(
                "Use the Test DTM Monitors or Test DTM Alerts buttons for this report type."
            )
        if request.report_type == "GTI Intelligence Search":
            raise ValueError("Use the Search GTI button for this report type.")

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
    "/explore/industry-snapshots",
    response_model=IndustrySnapshotExplorerResponse,
)
def explore_industry_snapshot_workflow(
    request: ExplorerRequest,
) -> IndustrySnapshotExplorerResponse:
    """Explore Industry Snapshot objects from GTI-safe endpoints."""

    try:
        exploration_result = explore_industry_snapshots(
            api_key=request.api_key,
        )

        http_status = int(exploration_result["status_code"])
        status = "success" if http_status == 200 else "upstream_error"

        return IndustrySnapshotExplorerResponse(
            status=status,
            http_status=http_status,
            snapshot_count=int(exploration_result["snapshot_count"]),
            snapshots=exploration_result["snapshots"],
            endpoint_results=exploration_result["endpoint_results"],
            raw_json=exploration_result["raw_json"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/explore/dtm-monitors",
    response_model=DTMMonitorExplorerResponse,
)
def explore_dtm_monitor_workflow(
    request: ExplorerRequest,
) -> DTMMonitorExplorerResponse:
    """List DTM monitors from the GTI API."""

    try:
        exploration_result = list_dtm_monitors(
            api_key=request.api_key,
            primary_domain=request.primary_domain,
        )

        http_status = int(exploration_result["status_code"])
        status = "success" if http_status == 200 else "upstream_error"

        return DTMMonitorExplorerResponse(
            status=status,
            http_status=http_status,
            domain_filter=str(exploration_result["domain_filter"]),
            requested_size=int(exploration_result["requested_size"]),
            page_count=int(exploration_result["page_count"]),
            truncated=bool(exploration_result["truncated"]),
            total_collected=int(exploration_result["total_collected"]),
            total_monitor_count=int(exploration_result["total_monitor_count"]),
            monitor_count=int(exploration_result["monitor_count"]),
            monitors=exploration_result["monitors"],
            endpoint_results=exploration_result["endpoint_results"],
            raw_json=exploration_result["raw_json"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/explore/dtm-alerts",
    response_model=DTMAlertExplorerResponse,
)
def explore_dtm_alert_workflow(
    request: ExplorerRequest,
) -> DTMAlertExplorerResponse:
    """List DTM alerts from the GTI API."""

    try:
        exploration_result = list_dtm_alerts(
            api_key=request.api_key,
            monitor_id=request.monitor_id,
        )

        http_status = int(exploration_result["status_code"])
        status = "success" if http_status == 200 else "upstream_error"

        return DTMAlertExplorerResponse(
            status=status,
            http_status=http_status,
            requested_size=int(exploration_result["requested_size"]),
            monitor_id=str(exploration_result["monitor_id"]),
            page_count=int(exploration_result["page_count"]),
            truncated=bool(exploration_result["truncated"]),
            total_collected=int(exploration_result["total_collected"]),
            total_alert_count=int(exploration_result["total_alert_count"]),
            alert_count=int(exploration_result["alert_count"]),
            alerts=exploration_result["alerts"],
            simplified_preview=exploration_result["simplified_preview"],
            endpoint_results=exploration_result["endpoint_results"],
            raw_data=exploration_result["raw_data"],
            raw_json=exploration_result["raw_json"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/explore/intelligence-search",
    response_model=IntelligenceSearchResponse,
)
def explore_intelligence_search_workflow(
    request: IntelligenceSearchRequest,
) -> IntelligenceSearchResponse:
    """Run GTI Intelligence Search and return a simplified preview."""

    try:
        exploration_result = intelligence_search(
            api_key=request.api_key,
            query=request.query,
            limit=request.limit,
            descriptors_only=request.descriptors_only,
            cursor=request.cursor,
        )

        status_code = int(exploration_result["status_code"])
        status = "success" if status_code == 200 else "upstream_error"

        return IntelligenceSearchResponse(
            status=status,
            status_code=status_code,
            total_collected=int(exploration_result["total_collected"]),
            next_cursor=exploration_result["next_cursor"],
            simplified_preview=exploration_result["simplified_preview"],
            raw_data=exploration_result["raw_data"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/explore/collection-details",
    response_model=CollectionDetailsResponse,
)
def analyze_collection_workflow(
    request: CollectionDetailsRequest,
) -> CollectionDetailsResponse:
    """Fetch detailed GTI collection fields for the Industry Profile Analyzer."""

    try:
        analysis_result = get_collection_details(
            api_key=request.api_key,
            collection_id=request.collection_id,
        )

        status_code = int(analysis_result["status_code"])
        status = "success" if status_code == 200 else "upstream_error"

        return CollectionDetailsResponse(
            status=status,
            status_code=status_code,
            collection_id=str(analysis_result["collection_id"]),
            experimental_exposure_score=int(
                analysis_result["experimental_exposure_score"]
            ),
            analysis=analysis_result["analysis"],
            raw_data=analysis_result["raw_data"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/explore/top-targets", response_model=TopTargetsResponse)
def explore_top_targets_workflow(request: TopTargetsRequest) -> TopTargetsResponse:
    """Aggregate top targeted industries and companies from GTI collections."""

    try:
        result = aggregate_top_targets(
            api_key=request.api_key,
            start_year=request.start_year,
            end_year=request.end_year,
            top_n=request.top_n,
            max_collections=request.max_collections,
            deep_organization_lookup=request.deep_organization_lookup,
            max_detail_lookups=request.max_detail_lookups,
        )
        return TopTargetsResponse(
            status="success",
            period=str(result["period"]),
            collections_analyzed=int(result["collections_analyzed"]),
            collections_seen=int(result.get("collections_seen", 0)),
            collections_with_targeted_industries=int(result.get("collections_with_targeted_industries", 0)),
            collections_without_targeted_industries=int(result.get("collections_without_targeted_industries", 0)),
            unique_industries_count=int(result.get("unique_industries_count", 0)),
            pages_fetched=int(result.get("pages_fetched", 0)),
            max_collections=result.get("max_collections"),
            deep_organization_lookup=bool(result.get("deep_organization_lookup", False)),
            max_detail_lookups=int(result.get("max_detail_lookups", 0)),
            api_request_estimate=result.get("api_request_estimate", {}),
            company_detail_lookups_attempted=int(
                result["company_detail_lookups_attempted"]
            ),
            company_detail_lookups_succeeded=int(
                result["company_detail_lookups_succeeded"]
            ),
            top_industries=result["top_industries"],
            top_companies=result["top_companies"],
            top_companies_status=str(result.get("top_companies_status", "ok")),
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


@app.get("/api/industries")
def api_industries(
    year: int = Query(default=2024, ge=2018, le=2100),
    top: int = Query(default=10, ge=1, le=50),
    target: str | None = Query(default=None),
    x_api_key: str = Header(default=""),
) -> dict[str, Any]:
    """Return the top N most targeted industries for the given year."""

    if not x_api_key.strip():
        raise HTTPException(status_code=401, detail="x-api-key header is required.")

    cache_key = f"industries:{year}:{top}:{(target or '').strip().casefold()}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        result = get_top_industries(api_key=x_api_key, year=year, top_n=top, target=target)
        _cache_set(cache_key, result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Industry ranking failed: {exc}"
        ) from exc


@app.get("/api/companies")
def api_companies(
    year: int = Query(default=2024, ge=2018, le=2100),
    top: int = Query(default=10, ge=1, le=50),
    target: str | None = Query(default=None),
    x_api_key: str = Header(default=""),
) -> dict[str, Any]:
    """Return the top N most targeted companies/organizations for the given year."""

    if not x_api_key.strip():
        raise HTTPException(status_code=401, detail="x-api-key header is required.")

    cache_key = f"companies:{year}:{top}:{(target or '').strip().casefold()}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        result = get_top_companies(api_key=x_api_key, year=year, top_n=top, target=target)
        _cache_set(cache_key, result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GTIClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Company ranking failed: {exc}"
        ) from exc


@app.post("/explore/countries-industries")
def invalid_countries_industries_explorer() -> None:
    """Mark the old countries_industries explorer as invalid."""

    raise HTTPException(
        status_code=410,
        detail=(
            "The countries_industries explorer was removed and should no longer "
            "be used. Use the Industry Snapshot Explorer instead."
        ),
    )
