// Small frontend controller for the GTI report generator MVP.
// The goal is clarity over cleverness so the flow is easy to follow.

const reportForm = document.getElementById("report-form");
const apiKeyField = document.getElementById("api_key");
const generateButton = document.getElementById("generate-button");
const reportOutput = document.getElementById("report-output");
const rawJsonOutput = document.getElementById("raw-json-output");
const messageBanner = document.getElementById("message-banner");
const statusPill = document.getElementById("status-pill");
const reportTypeField = document.getElementById("report_type");
const intelligenceSearchFields = document.getElementById("intelligence-search-fields");
const intelligenceQueryField = document.getElementById("intelligence_query");
const intelligenceLimitField = document.getElementById("intelligence_limit");
const intelligenceDescriptorsOnlyField = document.getElementById("intelligence_descriptors_only");
const intelligencePresetButtons = document.querySelectorAll("[data-intelligence-query]");
const companyDtmFields = document.getElementById("company-dtm-fields");
const companyNameField = document.getElementById("company_name");
const primaryDomainField = document.getElementById("primary_domain");
const keywordsField = document.getElementById("keywords");
const monitorIdField = document.getElementById("monitor_id");
const targetField = document.getElementById("target");
const targetLabel = document.getElementById("target-label");
const downloadButton = document.getElementById("download-button");
const scopeFields = document.getElementById("report-scope-fields");
const reportSectionsGroup = document.getElementById("report-sections-group");
const outputFormatGroup = document.getElementById("output-format-group");
const reportActions = document.getElementById("report-actions");
const explorerActions = document.getElementById("explorer-actions");
const explorerButton = document.getElementById("explorer-button");
const companyDtmActions = document.getElementById("company-dtm-actions");
const dtmMonitorsButton = document.getElementById("dtm-monitors-button");
const dtmAlertsButton = document.getElementById("dtm-alerts-button");
const intelligenceSearchActions = document.getElementById("intelligence-search-actions");
const intelligenceSearchButton = document.getElementById("intelligence-search-button");
const topTargetsFields = document.getElementById("top-targets-fields");
const topTargetsActions = document.getElementById("top-targets-actions");
const topTargetsButton = document.getElementById("top-targets-button");
const topTargetsStartYearField = document.getElementById("top_targets_start_year");
const topTargetsEndYearField = document.getElementById("top_targets_end_year");
const topTargetsTopNField = document.getElementById("top_targets_top_n");
const topTargetsMaxPagesField = document.getElementById("top_targets_max_pages");
const statsYearField = document.getElementById("stats_year");
const statsTargetField = document.getElementById("stats_target");
const industriesChartEl = document.getElementById("industries-chart");
const companiesChartEl = document.getElementById("companies-chart");
const companiesSourceBadgeEl = document.getElementById("companies-source-badge");
const modeCard = document.getElementById("mode-card");
const modeCardLabel = document.getElementById("mode-card-label");
const modeCardText = document.getElementById("mode-card-text");
const emptyStateTitle = document.getElementById("empty-state-title");
const emptyStateText = document.getElementById("empty-state-text");

const IOC_ENRICHMENT = "IoC Enrichment";
const INDUSTRY_SNAPSHOT_EXPLORER = "Industry Snapshot Explorer";
const COMPANY_EXPOSURE_DTM = "Company Exposure / DTM";
const GTI_INTELLIGENCE_SEARCH = "GTI Intelligence Search";
const TOP_TARGETS_RANKING = "Top Targets Ranking";

const MODE_META = {
    [IOC_ENRICHMENT]: {
        label: "IoC Enrichment",
        description: "Generates a structured analyst report from GTI data on a target domain. Configure which sections to include and the output format below.",
        emptyTitle: "Ready to generate a report",
        emptyText: "Enter a target domain, select the sections to include, and click Generate Report.",
    },
    [INDUSTRY_SNAPSHOT_EXPLORER]: {
        label: "Industry Snapshot Explorer",
        description: "Scans GTI collections for Industry Snapshot reports and returns their metadata: publication dates, targeted sectors, regions, and summaries.",
        emptyTitle: "Ready to explore",
        emptyText: "Click Explore Industry Snapshots to browse GTI collections matching the snapshot filter.",
    },
    [COMPANY_EXPOSURE_DTM]: {
        label: "Company Exposure / DTM",
        description: "Queries your Digital Threat Monitoring watchlists and their recent alerts. Use this to verify API connectivity and review active monitors before generating a report.",
        emptyTitle: "Ready to test DTM",
        emptyText: "Fill in your company details, then click Test DTM Monitors or Test DTM Alerts.",
    },
    [GTI_INTELLIGENCE_SEARCH]: {
        label: "GTI Intelligence Search",
        description: "Free-text search across GTI objects — collections, files, and threat actors. Use preset queries or write your own to explore available intelligence.",
        emptyTitle: "Ready to search",
        emptyText: "Enter a search query or choose a preset, then click Search GTI.",
    },
    [TOP_TARGETS_RANKING]: {
        label: "Top Targets Ranking",
        description: "Scans GTI collections from a selected period and ranks the most frequently targeted industries and companies. Each entity is counted at most once per collection.",
        emptyTitle: "Ready to rank",
        emptyText: "Set the time range and search parameters, then click Run Ranking.",
    },
};

let lastGeneratedReport = "";
let lastDownloadFilename = "";
let lastDownloadFormat = "markdown";
let lastIntelligenceSearchResponse = null;
let lastCollectionAnalysisResponse = null;
let activeCollectionAnalysisId = "";
let collectionAnalysisInProgressId = "";

function escapeHtml(text) {
    return text
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatInlineMarkdown(text) {
    // Escape first so any returned content is safe to inject into the page.
    let formattedText = escapeHtml(text);

    formattedText = formattedText.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    formattedText = formattedText.replace(/`(.+?)`/g, "<code>$1</code>");

    return formattedText;
}

function markdownToHtml(markdown) {
    // This light parser supports the Markdown structures generated by the MVP
    // backend: headings, paragraphs, bold text, inline code, bullet lists,
    // and fenced code blocks.
    const lines = markdown.split(/\r?\n/);
    const htmlParts = [];
    let inList = false;
    let inCodeBlock = false;
    let codeBlockLines = [];

    function closeListIfNeeded() {
        if (inList) {
            htmlParts.push("</ul>");
            inList = false;
        }
    }

    function closeCodeBlockIfNeeded() {
        if (inCodeBlock) {
            htmlParts.push(
                `<pre><code>${escapeHtml(codeBlockLines.join("\n"))}</code></pre>`,
            );
            inCodeBlock = false;
            codeBlockLines = [];
        }
    }

    for (const line of lines) {
        const trimmedLine = line.trim();

        if (trimmedLine.startsWith("```")) {
            closeListIfNeeded();

            if (inCodeBlock) {
                closeCodeBlockIfNeeded();
            } else {
                inCodeBlock = true;
                codeBlockLines = [];
            }

            continue;
        }

        if (inCodeBlock) {
            codeBlockLines.push(line);
            continue;
        }

        if (!trimmedLine) {
            closeListIfNeeded();
            continue;
        }

        if (trimmedLine.startsWith("# ")) {
            closeListIfNeeded();
            htmlParts.push(`<h1>${formatInlineMarkdown(trimmedLine.slice(2))}</h1>`);
            continue;
        }

        if (trimmedLine.startsWith("## ")) {
            closeListIfNeeded();
            htmlParts.push(`<h2>${formatInlineMarkdown(trimmedLine.slice(3))}</h2>`);
            continue;
        }

        if (trimmedLine.startsWith("- ")) {
            if (!inList) {
                htmlParts.push("<ul>");
                inList = true;
            }

            htmlParts.push(`<li>${formatInlineMarkdown(trimmedLine.slice(2))}</li>`);
            continue;
        }

        closeListIfNeeded();
        htmlParts.push(`<p>${formatInlineMarkdown(trimmedLine)}</p>`);
    }

    closeListIfNeeded();
    closeCodeBlockIfNeeded();
    return htmlParts.join("");
}

function showMessage(message, type) {
    messageBanner.hidden = false;
    messageBanner.textContent = message;
    messageBanner.className = `message-banner ${type}`;
}

function clearMessage() {
    messageBanner.hidden = true;
    messageBanner.textContent = "";
    messageBanner.className = "message-banner";
}

function updateStatus(label, stateClass) {
    statusPill.textContent = label;
    statusPill.className = `status-pill ${stateClass}`;
}

function setLoadingState(isLoading) {
    generateButton.disabled = isLoading;
    generateButton.textContent = isLoading ? "Generating..." : "Generate Report";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function getExplorerButtonLabel() {
    if (reportTypeField.value === INDUSTRY_SNAPSHOT_EXPLORER) {
        return "Explore Industry Snapshots";
    }

    return "Run Explorer";
}

function setExplorerLoadingState(isLoading) {
    explorerButton.disabled = isLoading;
    explorerButton.textContent = isLoading
        ? "Loading..."
        : getExplorerButtonLabel();
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setCompanyDtmLoadingState(isLoading, action) {
    dtmMonitorsButton.disabled = isLoading;
    dtmAlertsButton.disabled = isLoading;

    if (!isLoading) {
        dtmMonitorsButton.textContent = "Test DTM Monitors";
        dtmAlertsButton.textContent = "Test DTM Alerts";
    } else if (action === "monitors") {
        dtmMonitorsButton.textContent = "Testing Monitors...";
        dtmAlertsButton.textContent = "Test DTM Alerts";
    } else {
        dtmMonitorsButton.textContent = "Test DTM Monitors";
        dtmAlertsButton.textContent = "Testing Alerts...";
    }

    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setIntelligenceSearchLoadingState(isLoading) {
    intelligenceSearchButton.disabled = isLoading;
    intelligenceSearchButton.textContent = isLoading ? "Searching..." : "Search GTI";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setTopTargetsLoadingState(isLoading) {
    topTargetsButton.disabled = isLoading;
    topTargetsButton.textContent = isLoading ? "Analyzing GTI collections..." : "Run Ranking";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function getSelectedSections() {
    return Array.from(
        document.querySelectorAll('input[name="sections"]:checked'),
        (input) => input.value,
    );
}

function getSelectedOutputFormat() {
    const selectedFormat = document.querySelector('input[name="output_format"]:checked');
    return selectedFormat ? selectedFormat.value : "markdown";
}

function setDownloadState(isReady, filename = "", outputFormat = "markdown") {
    lastDownloadFilename = filename;
    lastDownloadFormat = outputFormat;
    downloadButton.hidden = !isReady;
    downloadButton.disabled = !isReady;
    downloadButton.textContent = outputFormat === "html"
        ? "Download Report (.html)"
        : "Download Report (.md)";
}

function updateModeCard(type) {
    const meta = MODE_META[type];
    if (!meta) return;
    modeCardLabel.textContent = meta.label;
    modeCardText.textContent = meta.description;
    modeCard.style.animation = "none";
    void modeCard.offsetWidth; // force reflow to restart animation
    modeCard.style.animation = "modeCardUpdate 0.2s ease";
}

function updateEmptyState(type) {
    if (!reportOutput.classList.contains("empty-state")) return;
    const meta = MODE_META[type];
    if (!meta) return;
    emptyStateTitle.textContent = meta.emptyTitle;
    emptyStateText.textContent = meta.emptyText;
}

function syncTargetRequirement() {
    const isExplorerMode = (
        reportTypeField.value === INDUSTRY_SNAPSHOT_EXPLORER
    );
    const isCompanyExposureDtm = reportTypeField.value === COMPANY_EXPOSURE_DTM;
    const isIocEnrichment = reportTypeField.value === IOC_ENRICHMENT;
    const isIntelligenceSearch = reportTypeField.value === GTI_INTELLIGENCE_SEARCH;
    const isTopTargets = reportTypeField.value === TOP_TARGETS_RANKING;
    const isSpecialMode = isExplorerMode || isCompanyExposureDtm || isIntelligenceSearch || isTopTargets;

    scopeFields.hidden = isSpecialMode;
    reportSectionsGroup.hidden = isSpecialMode;
    outputFormatGroup.hidden = isSpecialMode;
    reportActions.hidden = isSpecialMode;
    explorerActions.hidden = !isExplorerMode;
    intelligenceSearchFields.hidden = !isIntelligenceSearch;
    intelligenceSearchActions.hidden = !isIntelligenceSearch;
    companyDtmFields.hidden = !isCompanyExposureDtm;
    companyDtmActions.hidden = !isCompanyExposureDtm;
    topTargetsFields.hidden = !isTopTargets;
    topTargetsActions.hidden = !isTopTargets;

    targetField.required = (
        isIocEnrichment
        && !isExplorerMode
        && !isCompanyExposureDtm
        && !isIntelligenceSearch
        && !isTopTargets
    );
    intelligenceQueryField.required = isIntelligenceSearch;
    targetField.placeholder = isIocEnrichment ? "example.com" : "Company, region, or industry";
    targetLabel.textContent = isIocEnrichment ? "Target Domain" : "Target (Optional)";
    explorerButton.textContent = getExplorerButtonLabel();

    if (isSpecialMode) {
        lastGeneratedReport = "";
        setDownloadState(false);
    }

    updateModeCard(reportTypeField.value);
    updateEmptyState(reportTypeField.value);
}

function buildHtmlDownloadDocument(filename, markdown) {
    const documentTitle = escapeHtml(filename.replace(/\.[^.]+$/, ""));
    const renderedReport = markdownToHtml(markdown);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${documentTitle}</title>
    <style>
        body {
            margin: 0;
            padding: 32px 20px;
            font-family: "Bahnschrift", "Trebuchet MS", "Segoe UI", sans-serif;
            color: #10232d;
            background: linear-gradient(180deg, #edf6f7, #dce9ea);
        }

        main {
            width: min(920px, 100%);
            margin: 0 auto;
            padding: 28px;
            border-radius: 24px;
            background: rgba(255, 255, 255, 0.96);
            box-shadow: 0 22px 48px rgba(17, 45, 56, 0.12);
        }

        h1, h2, h3 {
            font-family: "Franklin Gothic Medium", "Arial Narrow", sans-serif;
        }

        h2 {
            color: #095f63;
            margin-top: 28px;
        }

        p, li {
            line-height: 1.7;
        }

        code {
            font-family: "Consolas", "Courier New", monospace;
            padding: 2px 6px;
            border-radius: 999px;
            background: rgba(13, 127, 122, 0.1);
            color: #095f63;
        }

        pre {
            overflow-x: auto;
            padding: 16px;
            border-radius: 16px;
            background: #10232d;
            color: #f4fffd;
        }

        pre code {
            padding: 0;
            border-radius: 0;
            background: transparent;
            color: inherit;
        }
    </style>
</head>
<body>
    <main>${renderedReport}</main>
</body>
</html>`;
}

function downloadCurrentReport() {
    if (!lastGeneratedReport || !lastDownloadFilename) {
        return;
    }

    const fileContents = lastDownloadFormat === "html"
        ? buildHtmlDownloadDocument(lastDownloadFilename, lastGeneratedReport)
        : lastGeneratedReport;
    const mimeType = lastDownloadFormat === "html"
        ? "text/html;charset=utf-8"
        : "text/markdown;charset=utf-8";
    const downloadUrl = URL.createObjectURL(new Blob([fileContents], { type: mimeType }));
    const downloadLink = document.createElement("a");

    downloadLink.href = downloadUrl;
    downloadLink.download = lastDownloadFilename;
    document.body.append(downloadLink);
    downloadLink.click();
    downloadLink.remove();
    URL.revokeObjectURL(downloadUrl);
}

function formatApiValue(value) {
    if (value === null || value === undefined || value === "") {
        return "<em>not returned by API</em>";
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return "<em>not returned by API</em>";
        }

        return escapeHtml(value.map((item) => (
            typeof item === "object" ? JSON.stringify(item) : String(item)
        )).join(", "));
    }

    if (typeof value === "object") {
        return escapeHtml(JSON.stringify(value));
    }

    return escapeHtml(String(value));
}

function renderRawJsonDetails(rawJson) {
    return `
        <details class="inline-raw-json">
            <summary>Raw JSON</summary>
            <pre>${escapeHtml(JSON.stringify(rawJson, null, 2))}</pre>
        </details>
    `;
}

function renderEndpointResults(endpointResults) {
    if (!Array.isArray(endpointResults) || endpointResults.length === 0) {
        return "<p><strong>Endpoint Checks:</strong> <em>not returned by API</em></p>";
    }

    return `
        <ul>${endpointResults.map((result) => `
            <li>
                <strong>${escapeHtml(String(result.endpoint_name || "endpoint"))}:</strong>
                HTTP ${escapeHtml(String(result.http_status ?? "not returned by API"))}
                | page ${escapeHtml(String(result.page_number ?? "not returned by API"))}
                | params ${formatApiValue(result.request_params)}
                | requested cursor ${formatApiValue(result.requested_cursor)}
                | next link ${formatApiValue(result.next_link_url)}
                | next cursor ${formatApiValue(result.next_cursor)}
            </li>
        `).join("")}</ul>
    `;
}

function renderCompanyDtmContext() {
    return `
        <p><strong>Company Name:</strong> ${formatApiValue(companyNameField.value.trim())}</p>
        <p><strong>Primary Domain:</strong> ${formatApiValue(primaryDomainField.value.trim())}</p>
        <p><strong>Keywords:</strong> ${formatApiValue(keywordsField.value.trim())}</p>
        <p><strong>Monitor ID:</strong> ${formatApiValue(monitorIdField.value.trim())}</p>
    `;
}

function renderPreviewField(label, value) {
    return `
        <div class="preview-row">
            <span class="preview-label">${escapeHtml(label)}</span>
            <div class="preview-value">${formatApiValue(value)}</div>
        </div>
    `;
}

function getCollectionDisplayLabel(item) {
    if (item.title && item.name && item.title !== item.name) {
        return `${String(item.title)} | ${String(item.name)}`;
    }

    return item.title || item.name;
}

function renderCollectionAnalyzeAction(item) {
    const normalizedType = String(item.type || "").toLowerCase();
    const collectionId = item.id ? String(item.id) : "";

    if (normalizedType !== "collection" || !collectionId) {
        return "";
    }

    const isAnalyzing = collectionAnalysisInProgressId === collectionId;
    const buttonStateClass = activeCollectionAnalysisId === collectionId
        ? "selected-action-button"
        : "";

    return `
        <div class="preview-card-actions">
            <button
                type="button"
                class="generate-button secondary-button inline-action-button ${buttonStateClass}"
                data-analyze-collection-id="${escapeHtml(collectionId)}"
                ${isAnalyzing ? "disabled" : ""}
            >
                ${isAnalyzing ? "Analyzing selected collection..." : "Analyze selected collection"}
            </button>
        </div>
    `;
}

function renderIntelligenceSearchCard(item) {
    const normalizedType = String(item.type || "").toLowerCase();

    if (normalizedType === "file") {
        return `
            <article class="preview-card">
                ${renderPreviewField("ID", item.id)}
                ${renderPreviewField("Type", item.type)}
                ${renderPreviewField("Meaningful Name", item.meaningful_name)}
                ${renderPreviewField("Reputation", item.reputation)}
                ${renderPreviewField("Last Analysis Stats", item.last_analysis_stats)}
            </article>
        `;
    }

    if (normalizedType !== "collection") {
        return `
            <article class="preview-card">
                ${renderPreviewField("ID", item.id)}
                ${renderPreviewField("Type", item.type)}
                ${renderPreviewField("Title", item.title)}
                ${renderPreviewField("Name", item.name)}
                ${renderPreviewField("Meaningful Name", item.meaningful_name)}
                ${renderPreviewField("Attributes Keys", item.attributes_keys)}
            </article>
        `;
    }

    return `
        <article class="preview-card">
            ${renderPreviewField("ID", item.id)}
            ${renderPreviewField("Type", item.type)}
            ${renderPreviewField("Title / Name", getCollectionDisplayLabel(item))}
            ${renderPreviewField("Collection Type", item.collection_type)}
            ${renderPreviewField("Creation Date", item.creation_date)}
            ${renderPreviewField("Targeted Industries", item.targeted_industries)}
            ${renderPreviewField("Targeted Regions", item.targeted_regions)}
            ${renderPreviewField("Source Regions", item.source_regions)}
            ${renderPreviewField("Tags", item.tags)}
            ${renderPreviewField("Attributes Keys", item.attributes_keys)}
            ${renderCollectionAnalyzeAction(item)}
        </article>
    `;
}

function renderCollectionAnalysisPanel(responseData) {
    const analysis = responseData && typeof responseData.analysis === "object"
        ? responseData.analysis
        : {};

    return `
        <section class="analysis-panel">
            <h2>Industry Profile Analyzer</h2>
            <p><strong>Selected Collection ID:</strong> ${formatApiValue(responseData.collection_id)}</p>
            <p><strong>Status Code:</strong> ${escapeHtml(String(responseData.status_code))}</p>
            <div class="score-callout">
                <p><strong>GTI Exposure Score:</strong> ${escapeHtml(String(responseData.experimental_exposure_score ?? 0))}</p>
                <p>Experimental score based on GTI object counters, not a confirmed attack count.</p>
            </div>
            <div class="analysis-grid">
                ${renderPreviewField("Name", analysis.name)}
                ${renderPreviewField("Collection Type", analysis.collection_type)}
                ${renderPreviewField("OSINT Summary", analysis.osint_summary)}
                ${renderPreviewField("Recent Activity Summary", analysis.recent_activity_summary)}
                ${renderPreviewField("Counters", analysis.counters)}
                ${renderPreviewField("Aggregations", analysis.aggregations)}
                ${renderPreviewField("Profile Stats", analysis.profile_stats)}
                ${renderPreviewField("Targeted Industries", analysis.targeted_industries)}
                ${renderPreviewField("Targeted Regions", analysis.targeted_regions)}
                ${renderPreviewField("Source Region", analysis.source_region)}
                ${renderPreviewField("Source Regions Hierarchy", analysis.source_regions_hierarchy)}
                ${renderPreviewField("Malware Roles", analysis.malware_roles)}
                ${renderPreviewField("Motivations", analysis.motivations)}
                ${renderPreviewField("Merged Actors", analysis.merged_actors)}
                ${renderPreviewField("Threat Activity Drivers", analysis.threat_activity_drivers)}
                ${renderPreviewField("Collection Links", analysis.collection_links)}
            </div>
            ${renderRawJsonDetails(responseData.raw_data)}
        </section>
    `;
}

function renderIntelligenceSearchResult(
    responseData,
    collectionAnalysisResponse = lastCollectionAnalysisResponse,
) {
    const previewItems = Array.isArray(responseData.simplified_preview)
        ? responseData.simplified_preview
        : [];
    const previewCardsHtml = previewItems.length > 0
        ? `
            <div class="preview-grid">
                ${previewItems.map((item) => renderIntelligenceSearchCard(item)).join("")}
            </div>
        `
        : "<p>No GTI objects were returned for the current page.</p>";
    const analysisHtml = collectionAnalysisResponse
        ? renderCollectionAnalysisPanel(collectionAnalysisResponse)
        : "";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>GTI Intelligence Search</h1>
        <p><strong>Search Query:</strong> ${formatApiValue(intelligenceQueryField.value.trim())}</p>
        <p><strong>Requested Limit:</strong> ${formatApiValue(Number(intelligenceLimitField.value || 10))}</p>
        <p><strong>Descriptors Only:</strong> ${formatApiValue(intelligenceDescriptorsOnlyField.checked)}</p>
        <p><strong>Status Code:</strong> ${escapeHtml(String(responseData.status_code))}</p>
        <p><strong>Total Collected:</strong> ${escapeHtml(String(responseData.total_collected || 0))}</p>
        <p><strong>Next Cursor:</strong> ${formatApiValue(responseData.next_cursor)}</p>
        <h2>Simplified Preview</h2>
        ${previewCardsHtml}
        ${analysisHtml}
        ${renderRawJsonDetails(responseData.raw_data)}
    `;
}

function renderIndustrySnapshotResult(responseData) {
    const snapshots = Array.isArray(responseData.snapshots) ? responseData.snapshots : [];
    const snapshotItemsHtml = snapshots.length > 0
        ? `<ul>${snapshots.map((item) => {
            const titleAndName = item.title && item.name && item.title !== item.name
                ? `${escapeHtml(String(item.title))} | ${escapeHtml(String(item.name))}`
                : formatApiValue(item.title || item.name);

            return `<li>
                <strong>Title/Name:</strong> ${titleAndName}<br>
                <strong>Published Date:</strong> ${formatApiValue(item.published_date)}<br>
                <strong>Targeted Industries:</strong> ${formatApiValue(item.targeted_industries)}<br>
                <strong>Targeted Regions:</strong> ${formatApiValue(item.targeted_regions)}<br>
                <strong>Source Regions:</strong> ${formatApiValue(item.source_regions)}<br>
                <strong>Summary/Description:</strong> ${formatApiValue(item.summary_or_description)}<br>
                ${renderRawJsonDetails(item.raw_json)}
            </li>`;
        }).join("")}</ul>`
        : "<p>No object with a title/name containing <code>Industry Snapshot</code> was returned.</p>";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Industry Snapshot Explorer</h1>
        <p><strong>HTTP Status:</strong> ${escapeHtml(String(responseData.http_status))}</p>
        <p><strong>Endpoint Checks:</strong></p>
        ${renderEndpointResults(responseData.endpoint_results)}
        <p><strong>Summary:</strong> ${escapeHtml(String(responseData.snapshot_count || 0))} matching object(s) found.</p>
        <h2>Returned Industry Snapshot Objects</h2>
        ${snapshotItemsHtml}
    `;
}

function renderCompanyDtmMonitorsResult(responseData) {
    const monitors = Array.isArray(responseData.monitors) ? responseData.monitors : [];
    const domainFilter = responseData.domain_filter || "";
    const paginationNote = responseData.truncated
        ? " Retrieval stopped at the safe page limit."
        : "";
    const monitorItemsHtml = monitors.length > 0
        ? `<ul>${monitors.map((item) => `
            <li>
                <strong>Monitor ID:</strong> ${formatApiValue(item.monitor_id)}<br>
                <strong>Monitor Name:</strong> ${formatApiValue(item.monitor_name)}<br>
                <strong>Monitor Type:</strong> ${formatApiValue(item.monitor_type)}<br>
                <strong>Monitor Template:</strong> ${formatApiValue(item.monitor_template)}<br>
                <strong>Created Date:</strong> ${formatApiValue(item.created_date)}<br>
                ${renderRawJsonDetails(item.raw_json)}
            </li>
        `).join("")}</ul>`
        : "<p>No monitor item could be extracted from the current response schema.</p>";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Company Exposure / DTM</h1>
        ${renderCompanyDtmContext()}
        <p><strong>HTTP Status:</strong> ${escapeHtml(String(responseData.http_status))}</p>
        <p><strong>Primary Domain Filter:</strong> ${domainFilter ? `<code>${escapeHtml(String(domainFilter))}</code>` : "<em>none</em>"}</p>
        <p><strong>Requested Page Size:</strong> ${escapeHtml(String(responseData.requested_size || 0))}</p>
        <p><strong>Pagination:</strong> ${escapeHtml(String(responseData.page_count || 0))} page(s) loaded.${escapeHtml(paginationNote)}</p>
        <p><strong>Endpoint Checks:</strong></p>
        ${renderEndpointResults(responseData.endpoint_results)}
        <p><strong>Summary:</strong> ${escapeHtml(String(responseData.monitor_count || 0))} monitor(s) matched out of ${escapeHtml(String(responseData.total_collected || responseData.total_monitor_count || 0))} collected from the API.</p>
        <h2>DTM Monitors Preview</h2>
        ${monitorItemsHtml}
    `;
}

function renderCompanyDtmAlertsResult(responseData) {
    const alerts = Array.isArray(responseData.simplified_preview)
        ? responseData.simplified_preview
        : (Array.isArray(responseData.alerts) ? responseData.alerts : []);
    const paginationNote = responseData.truncated
        ? " Retrieval stopped at the safe page limit."
        : "";
    const alertItemsHtml = alerts.length > 0
        ? `<ul>${alerts.map((item) => `
            <li>
                <strong>Alert ID:</strong> ${formatApiValue(item.id || item.alert_id)}<br>
                <strong>Type:</strong> ${formatApiValue(item.type)}<br>
                <strong>Title/Name:</strong> ${formatApiValue(item.title_or_name)}<br>
                <strong>Severity:</strong> ${formatApiValue(item.severity)}<br>
                <strong>Status:</strong> ${formatApiValue(item.status)}<br>
                <strong>Monitor ID:</strong> ${formatApiValue(item.monitor_id)}<br>
                <strong>Created At:</strong> ${formatApiValue(item.created_at)}<br>
                <strong>Updated At:</strong> ${formatApiValue(item.updated_at)}<br>
                <strong>Alert Type/Category:</strong> ${formatApiValue(item.alert_type_or_category)}<br>
                <strong>Matched Domain/URL/Email/Keyword:</strong> ${formatApiValue(item.matched_indicator)}<br>
                <strong>Raw Attributes Keys:</strong> ${formatApiValue(item.raw_attribute_keys)}<br>
                ${renderRawJsonDetails(item.raw_json)}
            </li>
        `).join("")}</ul>`
        : "<p>No alert item could be extracted from the current response schema.</p>";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Company Exposure / DTM</h1>
        ${renderCompanyDtmContext()}
        <p><strong>HTTP Status:</strong> ${escapeHtml(String(responseData.http_status))}</p>
        <p><strong>Requested Page Size:</strong> ${escapeHtml(String(responseData.requested_size || 0))}</p>
        <p><strong>Monitor ID Filter:</strong> ${responseData.monitor_id ? `<code>${escapeHtml(String(responseData.monitor_id))}</code>` : "<em>none</em>"}</p>
        <p><strong>Pagination:</strong> ${escapeHtml(String(responseData.page_count || 0))} page(s) loaded.${escapeHtml(paginationNote)}</p>
        <p><strong>Endpoint Checks:</strong></p>
        ${renderEndpointResults(responseData.endpoint_results)}
        <p><strong>Summary:</strong> ${escapeHtml(String(responseData.alert_count || 0))} alert(s) normalized out of ${escapeHtml(String(responseData.total_collected || responseData.total_alert_count || 0))} collected from the API.</p>
        <h2>DTM Alerts Preview</h2>
        ${alertItemsHtml}
    `;
}

async function runSelectedExplorer() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setExplorerLoadingState(true);
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        if (reportTypeField.value !== INDUSTRY_SNAPSHOT_EXPLORER) {
            throw new Error("No explorer workflow is selected.");
        }

        const response = await fetch("/explore/industry-snapshots", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                api_key: apiKeyField.value.trim(),
            }),
        });

        const responseData = await response.json();

        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        renderIndustrySnapshotResult(responseData);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(responseData.raw_json, null, 2);

        if (responseData.http_status === 200) {
            updateStatus("HTTP 200", "success");
            showMessage(
                `Industry Snapshot exploration completed. ${responseData.snapshot_count} matching object(s) found.`,
                "success",
            );
        } else {
            updateStatus(`HTTP ${responseData.http_status}`, "error");
            showMessage(
                `The endpoint responded with HTTP ${responseData.http_status}. Review the raw JSON below.`,
                "error",
            );
        }
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>Explorer request failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "Explorer request failed.", "error");
    } finally {
        setExplorerLoadingState(false);

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

function buildIntelligenceSearchPayload() {
    return {
        api_key: apiKeyField.value.trim(),
        query: intelligenceQueryField.value.trim(),
        limit: Number(intelligenceLimitField.value || 10),
        descriptors_only: intelligenceDescriptorsOnlyField.checked,
    };
}

function applyIntelligenceQueryPreset(event) {
    const presetQuery = event.currentTarget.dataset.intelligenceQuery || "";
    intelligenceQueryField.value = presetQuery;
    intelligenceQueryField.focus();
    intelligenceQueryField.setSelectionRange(
        intelligenceQueryField.value.length,
        intelligenceQueryField.value.length,
    );
}

function refreshIntelligenceSearchView() {
    if (!lastIntelligenceSearchResponse) {
        return;
    }

    renderIntelligenceSearchResult(
        lastIntelligenceSearchResponse,
        lastCollectionAnalysisResponse,
    );
}

async function analyzeSelectedCollection(collectionId) {
    if (!collectionId) {
        return;
    }

    clearMessage();
    collectionAnalysisInProgressId = collectionId;
    refreshIntelligenceSearchView();
    updateStatus("Running", "running");

    try {
        const response = await fetch("/explore/collection-details", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                api_key: apiKeyField.value.trim(),
                collection_id: collectionId,
            }),
        });

        const responseData = await response.json();
        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        lastCollectionAnalysisResponse = responseData;
        activeCollectionAnalysisId = collectionId;
        refreshIntelligenceSearchView();
        rawJsonOutput.textContent = JSON.stringify(responseData.raw_data, null, 2);

        if (responseData.status_code === 200) {
            updateStatus("HTTP 200", "success");
            showMessage(
                `Collection analysis completed for ${collectionId}. Experimental exposure score: ${responseData.experimental_exposure_score}.`,
                "success",
            );
        } else {
            updateStatus(`HTTP ${responseData.status_code}`, "error");
            showMessage(
                `The collection details endpoint responded with HTTP ${responseData.status_code}. Review the raw JSON below.`,
                "error",
            );
        }
    } catch (error) {
        updateStatus("Error", "error");
        showMessage(error.message || "Collection analysis failed.", "error");
    } finally {
        collectionAnalysisInProgressId = "";
        refreshIntelligenceSearchView();

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

async function searchGtiIntelligence() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setIntelligenceSearchLoadingState(true);
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        const response = await fetch("/explore/intelligence-search", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(buildIntelligenceSearchPayload()),
        });

        const responseData = await response.json();
        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        lastIntelligenceSearchResponse = responseData;
        lastCollectionAnalysisResponse = null;
        activeCollectionAnalysisId = "";
        collectionAnalysisInProgressId = "";
        renderIntelligenceSearchResult(responseData);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(responseData.raw_data, null, 2);

        if (responseData.status_code === 200) {
            updateStatus("HTTP 200", "success");
            showMessage(
                `GTI Intelligence Search completed. ${responseData.total_collected} object(s) returned in the current page.`,
                "success",
            );
        } else {
            updateStatus(`HTTP ${responseData.status_code}`, "error");
            showMessage(
                `The endpoint responded with HTTP ${responseData.status_code}. Review the raw JSON below.`,
                "error",
            );
        }
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>GTI Intelligence Search failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        lastIntelligenceSearchResponse = null;
        lastCollectionAnalysisResponse = null;
        activeCollectionAnalysisId = "";
        collectionAnalysisInProgressId = "";
        showMessage(error.message || "GTI Intelligence Search failed.", "error");
    } finally {
        setIntelligenceSearchLoadingState(false);

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

function buildCompanyDtmPayload() {
    return {
        api_key: apiKeyField.value.trim(),
        company_name: companyNameField.value.trim() || null,
        primary_domain: primaryDomainField.value.trim() || null,
        keywords: keywordsField.value.trim() || null,
        monitor_id: monitorIdField.value.trim() || null,
    };
}

async function testDtmMonitors() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setCompanyDtmLoadingState(true, "monitors");
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        const response = await fetch("/explore/dtm-monitors", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(buildCompanyDtmPayload()),
        });

        const responseData = await response.json();
        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        renderCompanyDtmMonitorsResult(responseData);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(
            responseData.raw_data || responseData.raw_json,
            null,
            2,
        );

        if (responseData.http_status === 200) {
            updateStatus("HTTP 200", "success");
            showMessage(
                `DTM monitors test completed. ${responseData.monitor_count} monitor(s) matched out of ${responseData.total_collected || responseData.total_monitor_count} collected across ${responseData.page_count} page(s).`,
                "success",
            );
        } else {
            updateStatus(`HTTP ${responseData.http_status}`, "error");
            showMessage(
                `The endpoint responded with HTTP ${responseData.http_status}. Review the raw JSON below.`,
                "error",
            );
        }
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>DTM monitors test failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "DTM monitors test failed.", "error");
    } finally {
        setCompanyDtmLoadingState(false, "monitors");

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

async function testDtmAlerts() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setCompanyDtmLoadingState(true, "alerts");
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        const response = await fetch("/explore/dtm-alerts", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(buildCompanyDtmPayload()),
        });

        const responseData = await response.json();
        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        renderCompanyDtmAlertsResult(responseData);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(responseData.raw_json, null, 2);

        if (responseData.http_status === 200) {
            updateStatus("HTTP 200", "success");
            showMessage(
                `DTM alerts test completed. ${responseData.alert_count} alert(s) normalized out of ${responseData.total_collected || responseData.total_alert_count} collected across ${responseData.page_count} page(s).`,
                "success",
            );
        } else {
            updateStatus(`HTTP ${responseData.http_status}`, "error");
            showMessage(
                `The endpoint responded with HTTP ${responseData.http_status}. Review the raw JSON below.`,
                "error",
            );
        }
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>DTM alerts test failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "DTM alerts test failed.", "error");
    } finally {
        setCompanyDtmLoadingState(false, "alerts");

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

function renderRankingTable(items, countLabel) {
    if (!Array.isArray(items) || items.length === 0) {
        return "<p><em>No data returned — the API may not have returned targeted information for this period.</em></p>";
    }

    const maxCount = Math.max(
        ...items.map((item) => item.collection_count ?? item.report_count ?? 0),
        1,
    );

    const rows = items.map((item) => {
        const count = item.collection_count ?? item.report_count ?? 0;
        const pct = Math.round((count / maxCount) * 100);
        return `
            <tr class="ranking-row">
                <td class="rank-cell">${escapeHtml(String(item.rank))}</td>
                <td class="name-cell">${escapeHtml(String(item.name || "Unknown"))}</td>
                <td class="bar-cell">
                    <div class="ranking-bar-wrap">
                        <div class="ranking-bar" style="width:${pct}%"></div>
                    </div>
                </td>
                <td class="count-cell">${escapeHtml(String(count))} ${escapeHtml(countLabel)}</td>
            </tr>
        `;
    }).join("");

    return `
        <table class="ranking-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Name</th>
                    <th>Frequency</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

function renderTopTargetsResult(responseData) {
    const industriesHtml = renderRankingTable(responseData.top_industries, "collections");
    const companiesHtml = renderRankingTable(responseData.top_companies, "collections");
    const detailLookupsAttempted = Number(responseData.company_detail_lookups_attempted || 0);
    const detailLookupsSucceeded = Number(responseData.company_detail_lookups_succeeded || 0);
    const detailLookupHtml = detailLookupsAttempted > 0
        ? `
        <p>
            <strong>Company detail lookups:</strong>
            ${escapeHtml(String(detailLookupsSucceeded))}/${escapeHtml(String(detailLookupsAttempted))} succeeded
        </p>
        `
        : "";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Top Targets Ranking — ${escapeHtml(String(responseData.period || ""))}</h1>
        <p>
            <strong>Collections analyzed:</strong> ${escapeHtml(String(responseData.collections_analyzed || 0))} |
            <strong>GTI query:</strong> <code>${escapeHtml(String(responseData.query_used || ""))}</code>
        </p>
        <p><strong>Counting model:</strong> each industry or company is counted at most once per GTI collection.</p>
        ${detailLookupHtml}

        <h2>Top ${escapeHtml(String(responseData.top_industries?.length || 0))} Most Targeted Industries</h2>
        ${industriesHtml}

        <h2>Top ${escapeHtml(String(responseData.top_companies?.length || 0))} Most Targeted Companies / Organizations <small style="font-size:0.7em;opacity:0.6">(counted by distinct collections)</small></h2>
        ${companiesHtml}

        <div class="methodology-note">
            <strong>Methodology:</strong> ${escapeHtml(String(responseData.methodology || ""))}
        </div>
        ${renderRawJsonDetails(responseData)}
    `;
}

async function runTopTargetsRanking() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setTopTargetsLoadingState(true);
    setDownloadState(false);
    lastGeneratedReport = "";

    const startYear = Number(topTargetsStartYearField.value || 2024);
    const endYearRaw = topTargetsEndYearField.value.trim();
    const endYear = endYearRaw ? Number(endYearRaw) : null;
    const topN = Number(topTargetsTopNField.value || 10);
    const maxPages = Number(topTargetsMaxPagesField.value || 3);

    try {
        const response = await fetch("/explore/top-targets", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                api_key: apiKeyField.value.trim(),
                start_year: startYear,
                end_year: endYear,
                top_n: topN,
                max_pages: maxPages,
            }),
        });

        const responseData = await response.json();
        if (!response.ok) {
            throw new Error(responseData.detail || "The backend returned an error.");
        }

        renderTopTargetsResult(responseData);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(responseData, null, 2);

        const industryCount = responseData.top_industries?.length || 0;
        const companyCount = responseData.top_companies?.length || 0;
        updateStatus("Success", "success");
        showMessage(
            `Ranking complete: ${industryCount} industries and ${companyCount} companies ranked from ${responseData.collections_analyzed} distinct GTI collections (${responseData.period}).`,
            "success",
        );
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>Top Targets Ranking failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "Top Targets Ranking failed.", "error");
    } finally {
        setTopTargetsLoadingState(false);

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

async function generateReport(event) {
    event.preventDefault();

    if (
        reportTypeField.value === INDUSTRY_SNAPSHOT_EXPLORER
    ) {
        await runSelectedExplorer();
        return;
    }

    if (reportTypeField.value === COMPANY_EXPOSURE_DTM) {
        await testDtmMonitors();
        return;
    }

    if (reportTypeField.value === GTI_INTELLIGENCE_SEARCH) {
        await searchGtiIntelligence();
        return;
    }

    if (reportTypeField.value === TOP_TARGETS_RANKING) {
        await runTopTargetsRanking();
        return;
    }

    if (!reportForm.reportValidity()) {
        return;
    }

    const selectedSections = getSelectedSections();
    if (selectedSections.length === 0) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>No report generated yet</h3>
            <p>Select at least one report section before generating.</p>
        `;
        rawJsonOutput.textContent = "No response yet.";
        updateStatus("Error", "error");
        showMessage("Select at least one report section.", "error");
        setDownloadState(false);
        return;
    }

    clearMessage();
    setLoadingState(true);
    setDownloadState(false);

    const formData = new FormData(reportForm);
    const payload = {
        api_key: String(formData.get("api_key") || "").trim(),
        report_type: String(formData.get("report_type") || "").trim(),
        year: Number(formData.get("year")),
        target: String(formData.get("target") || "").trim() || null,
        sections: selectedSections,
        output_format: getSelectedOutputFormat(),
    };

    try {
        const response = await fetch("/generate-report", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        const responseData = await response.json();

        if (!response.ok) {
            const errorMessage = responseData.detail || "The backend returned an error.";
            throw new Error(errorMessage);
        }

        reportOutput.classList.remove("empty-state");
        reportOutput.innerHTML = markdownToHtml(responseData.report_markdown);
        switchToTab("report");
        rawJsonOutput.textContent = JSON.stringify(responseData.raw_data, null, 2);
        updateStatus(responseData.status || "Success", "success");
        lastGeneratedReport = responseData.report_markdown;
        setDownloadState(
            true,
            responseData.downloadable_filename || "gti-report.md",
            payload.output_format,
        );
        showMessage("Report generated successfully.", "success");
    } catch (error) {
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = `
            <h3>Report generation failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        lastGeneratedReport = "";
        setDownloadState(false);
        showMessage(error.message || "Report generation failed.", "error");
    } finally {
        generateButton.disabled = false;
        generateButton.textContent = "Generate Report";

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

function handleReportOutputClick(event) {
    const analyzeButton = event.target.closest("[data-analyze-collection-id]");
    if (!analyzeButton) {
        return;
    }

    event.preventDefault();
    analyzeSelectedCollection(analyzeButton.dataset.analyzeCollectionId || "");
}

reportTypeField.addEventListener("change", syncTargetRequirement);
downloadButton.addEventListener("click", downloadCurrentReport);
explorerButton.addEventListener("click", runSelectedExplorer);
dtmMonitorsButton.addEventListener("click", testDtmMonitors);
dtmAlertsButton.addEventListener("click", testDtmAlerts);
intelligenceSearchButton.addEventListener("click", searchGtiIntelligence);
topTargetsButton.addEventListener("click", runTopTargetsRanking);
intelligencePresetButtons.forEach((button) => {
    button.addEventListener("click", applyIntelligenceQueryPreset);
});
reportOutput.addEventListener("click", handleReportOutputClick);
reportForm.addEventListener("submit", generateReport);
setDownloadState(false);
syncTargetRequirement();
reportForm.dataset.initialized = "true"; // enable field animations after initial render

let statsDebounceTimer = null;

async function fetchIndustries(year, target = "") {
    const apiKey = apiKeyField.value.trim();
    if (!apiKey) {
        industriesChartEl.innerHTML = "<p><em>Enter your API key above to load data.</em></p>";
        return;
    }
    industriesChartEl.innerHTML = "<p><em>Loading…</em></p>";

    const params = new URLSearchParams({ year, top: 10 });
    if (target) params.set("target", target);

    try {
        const response = await fetch(`/api/industries?${params}`, {
            headers: { "x-api-key": apiKey },
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to load industries.");
        industriesChartEl.innerHTML = renderRankingTable(data.data || [], "collections");
    } catch (err) {
        industriesChartEl.innerHTML = `<p class="stats-error">${escapeHtml(err.message)}</p>`;
    }
}

async function fetchCompanies(year, target = "") {
    const apiKey = apiKeyField.value.trim();
    if (!apiKey) {
        companiesChartEl.innerHTML = "<p><em>Enter your API key above to load data.</em></p>";
        companiesSourceBadgeEl.innerHTML = "";
        return;
    }
    companiesChartEl.innerHTML = "<p><em>Loading…</em></p>";
    companiesSourceBadgeEl.innerHTML = "";

    const params = new URLSearchParams({ year, top: 10 });
    if (target) params.set("target", target);

    try {
        const response = await fetch(`/api/companies?${params}`, {
            headers: { "x-api-key": apiKey },
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Failed to load companies.");
        companiesChartEl.innerHTML = renderRankingTable(data.data || [], "collections");
        const sourceLabels = { dtm: "via DTM", search: "via Search", actors: "via Actors" };
        const sourceLabel = sourceLabels[data.source] || data.source || "";
        if (sourceLabel) {
            companiesSourceBadgeEl.innerHTML = `<span class="badge source-badge">${escapeHtml(sourceLabel)}</span>`;
        }
    } catch (err) {
        companiesChartEl.innerHTML = `<p class="stats-error">${escapeHtml(err.message)}</p>`;
    }
}

function refreshStats() {
    const year = Number(statsYearField.value || 2024);
    const target = statsTargetField.value.trim();
    fetchIndustries(year, target);
    fetchCompanies(year, target);
}

function onStatsInputChange() {
    clearTimeout(statsDebounceTimer);
    statsDebounceTimer = setTimeout(refreshStats, 400);
}

statsYearField.addEventListener("change", onStatsInputChange);
statsTargetField.addEventListener("input", onStatsInputChange);
apiKeyField.addEventListener("change", refreshStats);
refreshStats();

// ── Tab switching ──────────────────────────────────────────────────────────

const tabBtns = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");

function switchToTab(tabId) {
    tabBtns.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tabId));
    tabPanels.forEach((panel) => { panel.hidden = panel.id !== `tab-${tabId}`; });
}

tabBtns.forEach((btn) => btn.addEventListener("click", () => switchToTab(btn.dataset.tab)));

