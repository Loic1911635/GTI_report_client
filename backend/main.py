"""FastAPI entrypoint for the GTI report generator MVP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.gti_client import MockGTIClient
from backend.report_generator import generate_markdown_report, normalize_threat_landscape


PROJECT_ROOT = Path(__file__).resolve().parent.parent
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

    api_key: str = Field(..., description="API key placeholder for the future GTI client.")
    report_type: str = Field(..., description="Type of report to generate.")
    year: int = Field(..., description="Year used to scope the report.")
    target: str | None = Field(
        default=None,
        description="Optional company, region, sector, or other report target.",
    )


class GenerateReportResponse(BaseModel):
    """Response payload returned by the report generation endpoint."""

    status: str
    report_markdown: str
    raw_data: dict[str, Any]


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
    """Generate a Markdown GTI report from mock threat landscape data."""

    try:
        # Step 1: Pull mock raw data from the fake GTI client.
        client = MockGTIClient(api_key=request.api_key)
        raw_data = client.fetch_threat_landscape(
            report_type=request.report_type,
            year=request.year,
            target=request.target,
        )

        # Step 2: Normalize the data so the report generator can rely on a
        # stable structure even if the future API changes slightly.
        normalized_data = normalize_threat_landscape(raw_data)

        # Step 3: Build the Markdown report that the frontend can display,
        # store, or export later.
        report_markdown = generate_markdown_report(
            normalized_data=normalized_data,
            report_type=request.report_type,
            year=request.year,
            target=request.target,
        )

        return GenerateReportResponse(
            status="success",
            report_markdown=report_markdown,
            raw_data=raw_data,
        )
    except Exception as exc:
        # This broad exception is acceptable for an MVP because it keeps the
        # endpoint behavior simple while still surfacing useful debug details.
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {exc}",
        ) from exc
