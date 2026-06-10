// Small frontend controller for the GTI report generator MVP.
// The goal is clarity over cleverness so the flow is easy to follow.

const reportForm = document.getElementById("report-form");
const apiKeyField = document.getElementById("api_key");
const apiKeyBlock = apiKeyField?.closest(".form-block");
const generateButton = document.getElementById("generate-button");
const reportOutput = document.getElementById("report-output");
const dtmDashboardOutput = document.getElementById("dtm-dashboard-output");
const iocStreamOutput = document.getElementById("ioc-stream-output");
const rawJsonOutput = document.getElementById("raw-json-output");
const crossAnalysisOutput = document.getElementById("cross-analysis-output");
const diagnosticsOutput = document.getElementById("diagnostics-output");
const copyJsonButton = document.getElementById("copy-json-button");
const messageBanner = document.getElementById("message-banner");
const statusPill = document.getElementById("status-pill");
const reportTypeField = document.getElementById("report_type");
const targetField = document.getElementById("target");
const targetLabel = document.getElementById("target-label");
const downloadButton = document.getElementById("download-button");
const scopeFields = document.getElementById("report-scope-fields");
const reportSectionsGroup = document.getElementById("report-sections-group");
const outputFormatGroup = document.getElementById("output-format-group");
const reportActions = document.getElementById("report-actions");
const topTargetsFields = document.getElementById("top-targets-fields");
const topTargetsActions = document.getElementById("top-targets-actions");
const topTargetsButton = document.getElementById("top-targets-button");
const dtmDashboardFields = document.getElementById("dtm-dashboard-fields");
const dtmDashboardActions = document.getElementById("dtm-dashboard-actions");
const dtmDashboardButton = document.getElementById("dtm-dashboard-button");
const iocStreamFields = document.getElementById("ioc-stream-fields");
const iocStreamActions = document.getElementById("ioc-stream-actions");
const iocStreamButton = document.getElementById("ioc-stream-button");
const iocStreamCollectionModeField = document.getElementById("ioc_stream_collection_mode");
const iocStreamPagesToFetchField = document.getElementById("ioc_stream_pages_to_fetch");
const iocStreamCustomPagesField = document.getElementById("ioc_stream_custom_pages");
const iocStreamCustomPagesWrapper = document.getElementById("ioc_stream_custom_pages_field");
const iocStreamTimeWindowField = document.getElementById("ioc_stream_time_window");
const iocStreamTimeWindowWrapper = document.getElementById("ioc_stream_time_window_field");
const iocStreamStartDateField = document.getElementById("ioc_stream_start_date");
const iocStreamEndDateField = document.getElementById("ioc_stream_end_date");
const iocStreamCustomDatesWrapper = document.getElementById("ioc_stream_custom_dates_fields");
const iocStreamAdvancedFilterField = document.getElementById("ioc_stream_advanced_filter");
const iocStreamAdvancedFilterWrapper = document.getElementById("ioc_stream_advanced_filter_field");
const iocStreamEntityTypeField = document.getElementById("ioc_stream_entity_type");
const iocStreamOriginField = document.getElementById("ioc_stream_origin");
const iocStreamDocxButton = document.getElementById("ioc-stream-docx-button");
const dtmDashboardDocxButton = document.getElementById("dtm-dashboard-docx-button");
const dtmDashboardSinceField = document.getElementById("dtm_dashboard_since");
const dtmDashboardUntilField = document.getElementById("dtm_dashboard_until");
const dtmDashboardMaxPagesField = document.getElementById("dtm_dashboard_max_pages");
const dtmDashboardIncludeRawField = document.getElementById("dtm_dashboard_include_raw");
const topTargetsStartYearField = document.getElementById("top_targets_start_year");
const topTargetsMonthField = document.getElementById("top_targets_month");
const topTargetsTopNField = document.getElementById("top_targets_top_n");
const topTargetsMaxCollectionsField = document.getElementById("top_targets_max_collections");
const topTargetsDeepLookupField = document.getElementById("top_targets_deep_lookup");
const topTargetsMaxDetailLookupsField = document.getElementById("top_targets_max_detail_lookups");
const topTargetsIncludeTtpField = document.getElementById("top_targets_include_ttp");
const topTargetsTtpSourceField = document.getElementById("top_targets_ttp_source");
const topTargetsMaxTtpCandidatesField = document.getElementById("top_targets_max_ttp_candidates");
const topTargetsTtpQueryFilterField = document.getElementById("top_targets_ttp_query_filter");
const topTargetsTtpWarning = document.getElementById("top-targets-ttp-warning");
const topTargetsIncludeDebugField = document.getElementById("top_targets_include_debug");
const topTargetsShowRawJsonField = document.getElementById("top_targets_show_raw_json");
const topTargetsEstimatePanel = document.getElementById("top-targets-estimate");
const topTargetsIncludeDebugDocxField = document.getElementById("top_targets_include_debug_docx");
const topTargetsDocxTemplateField = document.getElementById("top_targets_docx_template");
const topTargetsDocxButton = document.getElementById("top-targets-docx-button");
const modeCard = document.getElementById("mode-card");
const modeCardLabel = document.getElementById("mode-card-label");
const modeCardText = document.getElementById("mode-card-text");
const emptyStateTitle = document.getElementById("empty-state-title");
const emptyStateText = document.getElementById("empty-state-text");

const IOC_ENRICHMENT = "IoC Enrichment";
const DTM_DASHBOARD = "DTM Monitor & Alert Dashboard";
const IOC_STREAM_REPORT = "Recent IoC Stream Sample Report";
const TOP_TARGETS_RANKING = "Top Targets Ranking";
const TOP_TARGETS_SEARCH_PAGE_SIZE = 40;
const TOP_TARGETS_DEFAULT_MAX_COLLECTIONS = 1000;
const TOP_TARGETS_DEFAULT_DEEP_LOOKUPS = 0;
const TOP_TARGETS_MAX_DETAIL_LOOKUPS = 50;
const TOP_TARGETS_DEFAULT_TTP_CANDIDATES = 25;
const TOP_TARGETS_MAX_TTP_CANDIDATES = 100;

const TOP_TARGETS_MONTH_NAMES = [
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const TOP_TARGETS_RANKING_LABELS = {
    targeted_industries: "Top Targeted Industries",
    targeted_regions: "Top Targeted Regions",
    source_regions: "Top Source Regions",
    tags: "Top Tags / Themes",
    collection_type: "Collection Type Distribution",
    timeline: "Timeline",
    targeted_organizations: "Top Targeted Organizations",
};

const TOP_TARGETS_CROSS_ANALYSIS_LABELS = {
    industries_by_tags: "Industries by Tags / Themes",
    industries_by_collection_type: "Industries by Collection Type",
    industries_by_targeted_region: "Industries by Targeted Region",
    timeline_by_collection_type: "Timeline by Collection Type",
    source_region_by_targeted_region: "Source Region by Targeted Region",
};

const MODE_META = {
    [IOC_ENRICHMENT]: {
        label: "IoC Enrichment",
        description: "Generates a structured analyst report from GTI data on a target domain. Configure which sections to include and the output format below.",
        emptyTitle: "Ready to generate a report",
        emptyText: "Enter a target domain, select the sections to include, and click Generate Report.",
    },
    [DTM_DASHBOARD]: {
        label: "DTM Monitor & Alert Dashboard",
        description: "Builds a read-only dashboard from existing DTM monitors and alerts. Enter your GTI API key or configure GTI_API_KEY in the backend.",
        emptyTitle: "Ready to load the DTM dashboard",
        emptyText: "Choose a date range and page limit, then click Run Dashboard.",
    },
    [IOC_STREAM_REPORT]: {
        label: "Recent IoC Stream Sample Report",
        description: "Builds a recent-page sample from GTI IoC Stream notifications with enrichment, risk analytics, charts, and recommended actions.",
        emptyTitle: "Ready to build a Recent IoC Stream Sample report",
        emptyText: "Choose how many recent pages to fetch, then click Generate Recent IoC Stream Sample Report.",
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
let lastTopTargetsResponse = null;
let lastDtmDashboardResponse = null;
let lastIocStreamResponse = null;
let dtmMonitorSortKey = "risk_score";
let dtmMonitorSortDirection = "desc";

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

function setTopTargetsLoadingState(isLoading) {
    topTargetsButton.disabled = isLoading;
    if (topTargetsDocxButton) {
        topTargetsDocxButton.disabled = isLoading || !lastTopTargetsResponse;
    }
    topTargetsButton.textContent = isLoading ? "Analyzing GTI collections..." : "Run Ranking";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setDtmDashboardLoadingState(isLoading) {
    dtmDashboardButton.disabled = isLoading;
    dtmDashboardButton.textContent = isLoading ? "Loading Dashboard..." : "Run Dashboard";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setIocStreamLoadingState(isLoading) {
    iocStreamButton.disabled = isLoading;
    if (iocStreamDocxButton) {
        iocStreamDocxButton.disabled = isLoading || !lastIocStreamResponse;
    }
    iocStreamButton.textContent = isLoading ? "Generating Recent IoC Stream Sample Report..." : "Generate Recent IoC Stream Sample Report";
    updateStatus(isLoading ? "Running" : "Idle", isLoading ? "running" : "idle");
}

function setTopTargetsDocxState(isReady, isExporting = false) {
    if (!topTargetsDocxButton) {
        return;
    }
    topTargetsDocxButton.hidden = !isReady;
    topTargetsDocxButton.disabled = !isReady || isExporting;
    topTargetsDocxButton.textContent = isExporting
        ? "Exporting Word report..."
        : "Export Word Report";
}

function setIocStreamDocxState(isReady, isExporting = false) {
    if (!iocStreamDocxButton) {
        return;
    }
    iocStreamDocxButton.hidden = !isReady;
    iocStreamDocxButton.disabled = !isReady || isExporting;
    iocStreamDocxButton.textContent = isExporting
        ? "Exporting Word report..."
        : "Export Word Report";
}

function setDtmDashboardDocxState(isReady, isExporting = false) {
    if (!dtmDashboardDocxButton) {
        return;
    }
    dtmDashboardDocxButton.hidden = !isReady;
    dtmDashboardDocxButton.disabled = !isReady || isExporting;
    dtmDashboardDocxButton.textContent = isExporting
        ? "Exporting Word report..."
        : "Export Word Report";
}

function syncTopTargetsDeepLookupControls() {
    if (!topTargetsDeepLookupField || !topTargetsMaxDetailLookupsField) {
        return;
    }
    topTargetsMaxDetailLookupsField.disabled = !topTargetsDeepLookupField.checked;
    if (topTargetsDeepLookupField.checked && !topTargetsMaxDetailLookupsField.value.trim()) {
        topTargetsMaxDetailLookupsField.value = String(TOP_TARGETS_DEFAULT_DEEP_LOOKUPS);
    }
    if (!topTargetsDeepLookupField.checked) {
        topTargetsMaxDetailLookupsField.value = "0";
    }
    updateTopTargetsEstimatePanel();
}

function buildTopTargetsRequestEstimate(
    maxCollections,
    deepLookup,
    maxDetailLookups,
    maxTtpCandidates = TOP_TARGETS_DEFAULT_TTP_CANDIDATES,
    ttpSource = "search_reports",
    includeTtp = false,
) {
    const collectionLimit = Math.max(
        Number(maxCollections) || TOP_TARGETS_DEFAULT_MAX_COLLECTIONS,
        1,
    );
    const detailLookups = deepLookup
        ? Math.min(
            Math.max(Number(maxDetailLookups) || TOP_TARGETS_DEFAULT_DEEP_LOOKUPS, 0),
            TOP_TARGETS_MAX_DETAIL_LOOKUPS,
        )
        : 0;
    const searchRequests = collectionLimit === null
        ? null
        : Math.ceil(collectionLimit / TOP_TARGETS_SEARCH_PAGE_SIZE);
    const ttpCandidates = Math.min(
        Math.max(Number(maxTtpCandidates) || TOP_TARGETS_DEFAULT_TTP_CANDIDATES, 1),
        TOP_TARGETS_MAX_TTP_CANDIDATES,
    );
    const ttpSearchRequests = includeTtp && ttpSource === "search_reports"
        ? Math.ceil(ttpCandidates / TOP_TARGETS_SEARCH_PAGE_SIZE)
        : 0;
    const ttpLookupRequests = includeTtp ? ttpCandidates : 0;
    const ttpRequests = ttpLookupRequests + ttpSearchRequests;

    return {
        maxCollections: collectionLimit,
        searchRequests,
        detailLookups,
        ttpCandidates: ttpLookupRequests,
        ttpSearchRequests,
        ttpRequests,
        totalRequests: searchRequests === null ? null : searchRequests + detailLookups + ttpRequests,
    };
}

function getTopTargetsPeriodLabel() {
    const year = Number(topTargetsStartYearField?.value || 2024);
    const month = Number(topTargetsMonthField?.value || 0);
    return month ? `${TOP_TARGETS_MONTH_NAMES[month]} ${year}` : String(year);
}

function getSelectedTopTargetRankings() {
    return Array.from(
        document.querySelectorAll('input[name="top_targets_rankings"]:checked'),
        (input) => input.value,
    );
}

function updateTopTargetsEstimatePanel() {
    if (
        !topTargetsEstimatePanel
        || !topTargetsMaxCollectionsField
        || !topTargetsDeepLookupField
        || !topTargetsMaxDetailLookupsField
        || !topTargetsMaxTtpCandidatesField
        || !topTargetsTtpSourceField
    ) {
        return;
    }

    const maxCollections = Number(topTargetsMaxCollectionsField.value || TOP_TARGETS_DEFAULT_MAX_COLLECTIONS);
    const deepLookup = topTargetsDeepLookupField.checked;
    const maxDetailLookups = deepLookup
        ? Number(topTargetsMaxDetailLookupsField.value || 0)
        : 0;
    const maxTtpCandidates = Number(topTargetsMaxTtpCandidatesField.value || TOP_TARGETS_DEFAULT_TTP_CANDIDATES);
    const ttpSource = topTargetsTtpSourceField.value || "search_reports";
    const includeTtp = Boolean(topTargetsIncludeTtpField?.checked);
    const estimate = buildTopTargetsRequestEstimate(
        maxCollections,
        deepLookup,
        maxDetailLookups,
        maxTtpCandidates,
        ttpSource,
        includeTtp,
    );
    if (topTargetsTtpWarning) {
        topTargetsTtpWarning.textContent = `Adds up to ${includeTtp ? estimate.ttpRequests : 0} extra GTI API requests.`;
    }
    const warningHtml = estimate.totalRequests > 100
        ? `<p class="estimate-warning">Warning: this may consume a significant number of GTI API requests.</p>`
        : "";

    topTargetsEstimatePanel.innerHTML = `
        <strong>Execution estimate:</strong>
        <ul>
            <li>Period: ${escapeHtml(getTopTargetsPeriodLabel())}</li>
            <li>Max collections: ${escapeHtml(String(estimate.maxCollections))}</li>
            <li>Search page size: ${escapeHtml(String(TOP_TARGETS_SEARCH_PAGE_SIZE))}</li>
            <li>Estimated search pages: ${escapeHtml(String(estimate.searchRequests))}</li>
            <li>Deep collection lookups: ${deepLookup ? escapeHtml(String(estimate.detailLookups)) : "disabled"}</li>
            <li>MITRE ATT&CK analysis: ${includeTtp ? "enabled" : "disabled"}</li>
            <li>TTP source: ${includeTtp ? escapeHtml(ttpSource === "ranking_collections" ? "ranking result collections" : "report search") : "disabled"}</li>
            <li>TTP MITRE tree lookups: ${escapeHtml(String(estimate.ttpCandidates))}</li>
            <li>Estimated API requests: ~${escapeHtml(String(estimate.totalRequests))}</li>
        </ul>
        ${warningHtml}
    `;
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
    const isIocEnrichment = reportTypeField.value === IOC_ENRICHMENT;
    const isTopTargets = reportTypeField.value === TOP_TARGETS_RANKING;
    const isDtmDashboard = reportTypeField.value === DTM_DASHBOARD;
    const isIocStream = reportTypeField.value === IOC_STREAM_REPORT;
    const isSpecialMode = isTopTargets || isDtmDashboard || isIocStream;

    if (apiKeyBlock) {
        apiKeyBlock.hidden = false;
    }
    apiKeyField.required = !isDtmDashboard;
    apiKeyField.disabled = false;
    scopeFields.hidden = isSpecialMode;
    reportSectionsGroup.hidden = isSpecialMode;
    outputFormatGroup.hidden = isSpecialMode;
    reportActions.hidden = isSpecialMode;
    topTargetsFields.hidden = !isTopTargets;
    topTargetsActions.hidden = !isTopTargets;
    dtmDashboardFields.hidden = !isDtmDashboard;
    dtmDashboardActions.hidden = !isDtmDashboard;
    iocStreamFields.hidden = !isIocStream;
    iocStreamActions.hidden = !isIocStream;

    targetField.required = (
        isIocEnrichment
        && !isTopTargets
        && !isDtmDashboard
        && !isIocStream
    );
    targetField.placeholder = isIocEnrichment ? "example.com" : "Company, region, or industry";
    targetLabel.textContent = isIocEnrichment ? "Target Domain" : "Target (Optional)";

    if (isSpecialMode) {
        lastGeneratedReport = "";
        setDownloadState(false);
    }
    setTopTargetsDocxState(isTopTargets && Boolean(lastTopTargetsResponse));
    setIocStreamDocxState(isIocStream && Boolean(lastIocStreamResponse));

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

function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const result = String(reader.result || "");
            resolve(result.includes(",") ? result.split(",", 2)[1] : result);
        };
        reader.onerror = () => reject(reader.error || new Error("Failed to read template file."));
        reader.readAsDataURL(file);
    });
}

function escapeXml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function createRankingChartPng(rows, title) {
    if (!Array.isArray(rows) || rows.length === 0) {
        return Promise.resolve(null);
    }

    const chartRows = rows.slice(0, 10);
    const width = 900;
    const rowHeight = 42;
    const height = 92 + chartRows.length * rowHeight;
    const maxCount = Math.max(
        ...chartRows.map((row) => Number(row.collection_count ?? row.report_count ?? 0)),
        1,
    );
    const bars = chartRows.map((row, index) => {
        const count = Number(row.collection_count ?? row.report_count ?? 0);
        const barWidth = Math.max(4, Math.round((count / maxCount) * 430));
        const y = 72 + index * rowHeight;
        const label = escapeXml(String(row.name || "Unknown").slice(0, 48));
        return `
            <text x="24" y="${y + 17}" font-family="Arial" font-size="15" fill="#10232d">${label}</text>
            <rect x="340" y="${y}" width="${barWidth}" height="22" rx="4" fill="#0d7f7a"></rect>
            <text x="${350 + barWidth}" y="${y + 17}" font-family="Arial" font-size="14" fill="#10232d">${count}</text>
        `;
    }).join("");
    const svg = `
        <svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
            <rect width="100%" height="100%" fill="#ffffff"/>
            <text x="24" y="36" font-family="Arial" font-weight="700" font-size="24" fill="#095f63">${escapeXml(title)}</text>
            <text x="24" y="58" font-family="Arial" font-size="13" fill="#52656f">Counts represent distinct GTI collections</text>
            ${bars}
        </svg>
    `;

    return new Promise((resolve) => {
        const image = new Image();
        const svgUrl = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
        image.onload = () => {
            const canvas = document.createElement("canvas");
            canvas.width = width;
            canvas.height = height;
            const context = canvas.getContext("2d");
            if (!context) {
                URL.revokeObjectURL(svgUrl);
                resolve(null);
                return;
            }
            context.drawImage(image, 0, 0);
            URL.revokeObjectURL(svgUrl);
            resolve(canvas.toDataURL("image/png"));
        };
        image.onerror = () => {
            URL.revokeObjectURL(svgUrl);
            resolve(null);
        };
        image.src = svgUrl;
    });
}

async function buildTopRankingChartPayload(rankingResult) {
    const chartMapping = {
        industry_chart: ["targeted_industries", "Top Targeted Industries"],
        targeted_regions_chart: ["targeted_regions", "Top Targeted Regions"],
        source_regions_chart: ["source_regions", "Top Source Regions"],
        tags_chart: ["tags", "Top Tags / Themes"],
        collection_type_chart: ["collection_type", "Collection Type Distribution"],
        timeline_chart: ["timeline", "Timeline"],
    };
    const charts = {};
    const rankings = rankingResult.rankings || {};

    await Promise.all(Object.entries(chartMapping).map(async ([chartKey, [rankingKey, title]]) => {
        const png = await createRankingChartPng(rankings[rankingKey] || [], title);
        if (png) {
            charts[chartKey] = png;
        }
    }));

    return charts;
}

async function buildTopRankingDocxPayload() {
    const includeTechnicalDebug = Boolean(topTargetsIncludeDebugDocxField?.checked);
    const rankingResult = { ...(lastTopTargetsResponse || {}) };

    delete rankingResult.api_key;
    delete rankingResult.x_api_key;
    delete rankingResult.raw_data;
    delete rankingResult.raw_json;

    if (!includeTechnicalDebug) {
        delete rankingResult.debug_attribute_keys_frequency;
        delete rankingResult.debug_sample_collection_fields;
    }

    const charts = await buildTopRankingChartPayload(lastTopTargetsResponse || {});
    if (Object.keys(charts).length > 0) {
        rankingResult.charts = charts;
    }

    const payload = {
        ranking_result: rankingResult,
        include_technical_debug: includeTechnicalDebug,
    };

    const templateFile = topTargetsDocxTemplateField?.files?.[0];
    if (templateFile) {
        payload.custom_template_base64 = await readFileAsBase64(templateFile);
        payload.custom_template_filename = templateFile.name;
    }

    return payload;
}

async function exportTopRankingDocx() {
    if (!lastTopTargetsResponse) {
        showMessage("Run Top Rankings before exporting a Word report.", "error");
        return;
    }

    setTopTargetsDocxState(true, true);
    updateStatus("Exporting", "running");
    clearMessage();

    try {
        const response = await fetch("/export/top-ranking-docx", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(await buildTopRankingDocxPayload()),
        });

        if (!response.ok) {
            let detail = "Word export failed.";
            try {
                const errorPayload = await response.json();
                detail = errorPayload.detail || detail;
            } catch (_) {
                // Keep the generic message when the backend returned a non-JSON error.
            }
            throw new Error(detail);
        }

        const reportBlob = await response.blob();
        const contentDisposition = response.headers.get("content-disposition") || "";
        const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
        const filename = filenameMatch?.[1] || "gti-top-targets-ranking.docx";
        const downloadUrl = URL.createObjectURL(reportBlob);
        const downloadLink = document.createElement("a");
        downloadLink.href = downloadUrl;
        downloadLink.download = filename;
        document.body.append(downloadLink);
        downloadLink.click();
        downloadLink.remove();
        URL.revokeObjectURL(downloadUrl);

        updateStatus("Success", "success");
        showMessage("Word report exported.", "success");
    } catch (error) {
        updateStatus("Error", "error");
        showMessage(error.message || "Word export failed.", "error");
    } finally {
        setTopTargetsDocxState(Boolean(lastTopTargetsResponse), false);
    }
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

function renderPreviewField(label, value) {
    return `
        <div class="preview-row">
            <span class="preview-label">${escapeHtml(label)}</span>
            <div class="preview-value">${formatApiValue(value)}</div>
        </div>
    `;
}

function renderRankingTable(
    items,
    countLabel,
    emptyMessage = "Field not present in the GTI collection preview for this sample",
) {
    if (!Array.isArray(items) || items.length === 0) {
        return `<p><em>${escapeHtml(emptyMessage)}</em></p>`;
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

const CHART_PALETTE = ["#0D7F7A","#1A9E98","#0A5F5B","#15B0A8","#086560","#20C4BB","#053E3B","#25D4CA"];

function renderDonutChartSvg(items, maxItems = 8) {
    const rows = items.slice(0, maxItems);
    if (!rows.length) return "";
    const total = rows.reduce((s, r) => s + Number(r.collection_count || 0), 0);
    if (!total) return "";
    const CX = 85, CY = 85, R = 70, RI = 42, VW = 360, VH = 170, LEG_X = CX * 2 + 20;
    let angle = -Math.PI / 2;
    const slices = rows.map((row, i) => {
        const count = Number(row.collection_count || 0);
        const frac = count / total;
        const sweep = frac * 2 * Math.PI;
        const a1 = angle, a2 = angle + sweep;
        angle = a2;
        const color = CHART_PALETTE[i % CHART_PALETTE.length];
        const pct = Math.round(frac * 100);
        let path;
        if (rows.length === 1 || sweep >= 2 * Math.PI - 0.001) {
            path = `M ${CX - R} ${CY} A ${R} ${R} 0 1 1 ${CX + R} ${CY} A ${R} ${R} 0 1 1 ${CX - R} ${CY} ` +
                `M ${CX - RI} ${CY} A ${RI} ${RI} 0 1 0 ${CX + RI} ${CY} A ${RI} ${RI} 0 1 0 ${CX - RI} ${CY} Z`;
        } else {
            const large = sweep > Math.PI ? 1 : 0;
            const x1o = CX + R * Math.cos(a1), y1o = CY + R * Math.sin(a1);
            const x2o = CX + R * Math.cos(a2), y2o = CY + R * Math.sin(a2);
            const x1i = CX + RI * Math.cos(a1), y1i = CY + RI * Math.sin(a1);
            const x2i = CX + RI * Math.cos(a2), y2i = CY + RI * Math.sin(a2);
            path = `M ${x1i} ${y1i} L ${x1o} ${y1o} A ${R} ${R} 0 ${large} 1 ${x2o} ${y2o} L ${x2i} ${y2i} A ${RI} ${RI} 0 ${large} 0 ${x1i} ${y1i} Z`;
        }
        return { path, color, name: String(row.name || ""), pct };
    });
    const paths = slices.map((s) => `<path d="${s.path}" fill="${s.color}"/>`).join("");
    const legend = slices.map((s, i) => {
        const ly = 14 + i * 19;
        const lbl = s.name.length > 18 ? s.name.slice(0, 17) + "…" : s.name;
        return `<rect x="${LEG_X}" y="${ly - 9}" width="10" height="10" rx="2" fill="${s.color}"/>` +
            `<text x="${LEG_X + 14}" y="${ly}" class="rcd-leg">${escapeHtml(lbl)} (${s.pct}%)</text>`;
    }).join("");
    return `<svg viewBox="0 0 ${VW} ${VH}" class="ranking-chart-svg ranking-chart-donut" role="img" aria-label="Donut chart">` +
        `<defs><style>.rcd-leg{font:11px/1 system-ui,sans-serif;fill:#444}</style></defs>` +
        `${paths}` +
        `<circle cx="${CX}" cy="${CY}" r="${RI}" fill="white"/>` +
        `<text x="${CX}" y="${CY - 5}" text-anchor="middle" style="font:bold 13px system-ui;fill:#333">${total}</text>` +
        `<text x="${CX}" y="${CY + 11}" text-anchor="middle" style="font:10px system-ui;fill:#888">total</text>` +
        `${legend}</svg>`;
}

function renderRankingSectionContent(rankingKey, items, countLabel, emptyMessage) {
    if (!Array.isArray(items) || !items.length) {
        const msg = emptyMessage
            || (rankingKey === "targeted_organizations"
                ? "Not enough organization data in preview fields."
                : "Field not present in the GTI collection preview for this sample");
        return `<p><em>${escapeHtml(msg)}</em></p>`;
    }
    const chartHtml = rankingKey !== "timeline" ? renderDonutChartSvg(items, 8) : "";
    return (chartHtml ? `<div class="ranking-viz">${chartHtml}</div>` : "") + renderRankingTable(items, countLabel);
}

function normalizeTopTargetsResponse(responseData, requestedRankings = []) {
    const normalized = { ...responseData };
    const rankings = (
        responseData.rankings
        && typeof responseData.rankings === "object"
        && !Array.isArray(responseData.rankings)
    )
        ? { ...responseData.rankings }
        : {};

    if (!rankings.targeted_industries && Array.isArray(responseData.top_industries)) {
        rankings.targeted_industries = responseData.top_industries;
    }
    if (!rankings.targeted_organizations && Array.isArray(responseData.top_companies)) {
        rankings.targeted_organizations = responseData.top_companies;
    }

    const selectedRankings = Array.isArray(responseData.selected_rankings)
        && responseData.selected_rankings.length > 0
            ? responseData.selected_rankings
            : requestedRankings.length > 0
                ? requestedRankings
                : Object.keys(rankings);

    selectedRankings.forEach((rankingKey) => {
        if (!Array.isArray(rankings[rankingKey])) {
            rankings[rankingKey] = [];
        }
    });

    normalized.rankings = rankings;
    normalized.selected_rankings = selectedRankings;
    normalized.top_industries = Array.isArray(responseData.top_industries)
        ? responseData.top_industries
        : rankings.targeted_industries || [];
    normalized.top_companies = Array.isArray(responseData.top_companies)
        ? responseData.top_companies
        : rankings.targeted_organizations || [];
    normalized.top_tactics = Array.isArray(responseData.top_tactics)
        ? responseData.top_tactics
        : [];
    normalized.top_techniques = Array.isArray(responseData.top_techniques)
        ? responseData.top_techniques
        : [];
    normalized.top_subtechniques = Array.isArray(responseData.top_subtechniques)
        ? responseData.top_subtechniques
        : [];
    normalized.ttp_analysis = (
        responseData.ttp_analysis
        && typeof responseData.ttp_analysis === "object"
        && !Array.isArray(responseData.ttp_analysis)
    )
        ? responseData.ttp_analysis
        : {};
    normalized.technical_debug = (
        responseData.technical_debug
        && typeof responseData.technical_debug === "object"
        && !Array.isArray(responseData.technical_debug)
    )
        ? responseData.technical_debug
        : null;

    return normalized;
}

function renderMetricChips(responseData) {
    const estimate = responseData.api_request_estimate || {};
    const ttp = responseData.ttp_analysis || {};
    const selectedRankings = Array.isArray(responseData.selected_rankings)
        ? responseData.selected_rankings.length
        : 0;
    const chips = [
        `${Number(responseData.collections_analyzed || 0)} collections`,
        `${Number(responseData.actual_search_requests ?? responseData.pages_fetched ?? 0)} search requests`,
        `${Number(ttp.ttp_lookups_attempted || estimate.ttp_lookup_requests || 0)} TTP lookups`,
        `${selectedRankings} ranking sections`,
        "Word export ready",
    ];

    return `<div class="metric-chip-row">${chips.map((chip) => `<span class="metric-chip">${escapeHtml(chip)}</span>`).join("")}</div>`;
}

function renderSectionCard(title, bodyHtml, extraClass = "") {
    return `
        <section class="report-section-card ${extraClass}">
            <h2>${escapeHtml(title)}</h2>
            ${bodyHtml}
        </section>
    `;
}

function renderSelectedRankingSections(responseData) {
    const rankings = responseData.rankings || {};
    const selectedRankings = Array.isArray(responseData.selected_rankings)
        ? responseData.selected_rankings
        : Object.keys(rankings);

    return selectedRankings.map((rankingKey) => {
        const label = TOP_TARGETS_RANKING_LABELS[rankingKey] || rankingKey;
        const items = rankings[rankingKey] || [];
        const bodyHtml = rankingKey === "targeted_organizations" && responseData.top_companies_status === "not enough data"
            ? "<p><em>Not enough organization data in preview fields.</em></p>"
            : renderRankingSectionContent(rankingKey, items, "collections");
        return renderSectionCard(label, bodyHtml);
    }).join("");
}

function renderCrossAnalysisSections(responseData) {
    const matrices = responseData.cross_analysis || {};
    const matrixKeys = Object.keys(TOP_TARGETS_CROSS_ANALYSIS_LABELS)
        .filter((key) => matrices[key]);

    if (matrixKeys.length === 0) {
        return "";
    }

    const matrixHtml = matrixKeys.map((matrixKey) => {
        const matrix = matrices[matrixKey] || {};
        const columns = Array.isArray(matrix.columns) ? matrix.columns : [];
        const rows = Array.isArray(matrix.rows) ? matrix.rows : [];
        const maxValue = Math.max(
            ...rows.flatMap((row) => Array.isArray(row.cells) ? row.cells.map(Number) : []),
            0,
        );
        const tableHtml = columns.length && rows.length
            ? `
                <div class="cross-analysis-table-wrap">
                    <table class="cross-analysis-table">
                        <thead>
                            <tr>
                                <th></th>
                                ${columns.map((column) => `<th>${escapeHtml(String(column))}</th>`).join("")}
                            </tr>
                        </thead>
                        <tbody>
                            ${rows.map((row) => `
                                <tr>
                                    <th>${escapeHtml(String(row.label || ""))}</th>
                                    ${(Array.isArray(row.cells) ? row.cells : []).map((value) => {
                                        const count = Number(value || 0);
                                        const intensity = maxValue > 0 ? count / maxValue : 0;
                                        return `<td style="--heat:${intensity.toFixed(3)}">${escapeHtml(String(count))}</td>`;
                                    }).join("")}
                                </tr>
                            `).join("")}
                        </tbody>
                    </table>
                </div>
            `
            : "<p><em>Not enough overlapping preview fields to build this matrix.</em></p>";

        return `
            <section class="report-section-card cross-analysis-section">
                <h2>${escapeHtml(TOP_TARGETS_CROSS_ANALYSIS_LABELS[matrixKey])}</h2>
                <p><strong>Eligible collections:</strong> ${escapeHtml(String(matrix.eligible_collections || 0))}</p>
                <p>${escapeHtml(String(matrix.interpretation || "No interpretation available."))}</p>
                ${tableHtml}
            </section>
        `;
    }).join("");

    return `
        <div class="report-document">
            <h1>Cross-analysis</h1>
            <p>These matrices count co-occurring GTI collection metadata values. Counts represent GTI collections, not confirmed incident counts.</p>
            ${matrixHtml}
        </div>
    `;
}

function renderCrossAnalysisTab(responseData) {
    const html = renderCrossAnalysisSections(responseData);
    if (!html) {
        crossAnalysisOutput.classList.add("empty-state");
        crossAnalysisOutput.innerHTML = `
        <h3>Cross-analysis is empty</h3>
        <p>Not enough overlapping preview fields were available for this run.</p>
        `;
        return;
    }
    crossAnalysisOutput.classList.remove("empty-state");
    crossAnalysisOutput.innerHTML = html;
}

function renderCrossAnalysisSummary(responseData) {
    const matrices = responseData.cross_analysis || {};
    const matrixKeys = Object.keys(TOP_TARGETS_CROSS_ANALYSIS_LABELS)
        .filter((key) => matrices[key]);
    if (matrixKeys.length === 0) {
        return renderSectionCard(
            "Cross-analysis summary",
            "<p><em>No cross-analysis matrix is available for this run.</em></p>",
        );
    }

    const items = matrixKeys.map((matrixKey) => {
        const matrix = matrices[matrixKey] || {};
        return `<li><strong>${escapeHtml(TOP_TARGETS_CROSS_ANALYSIS_LABELS[matrixKey])}:</strong> ${escapeHtml(String(matrix.eligible_collections || 0))} eligible collections</li>`;
    }).join("");
    return renderSectionCard(
        "Cross-analysis summary",
        `<ul>${items}</ul><button type="button" class="link-button" data-switch-tab="cross-analysis">Open Cross-analysis tab</button>`,
    );
}

function renderTtpStatusCard(responseData) {
    const ttp = responseData.ttp_analysis || {};
    const enabled = Boolean(ttp.enabled);
    const attempted = Number(ttp.ttp_lookups_attempted || 0);
    const succeeded = Number(ttp.ttp_lookups_succeeded || 0);
    const status = !enabled
        ? "Disabled"
        : attempted > 0 && succeeded === attempted
            ? "Complete"
            : "Partial";
    const sourceLabel = ttp.ttp_source === "ranking_collections"
        ? "Ranking collections"
        : "Search reports";
    const warningMessage = ttp.warning_message
        ? `<p class="diagnostic-warning compact">${escapeHtml(String(ttp.warning_message))}</p>`
        : "";

    return `
        <section class="status-card">
            <div>
                <h2>MITRE ATT&CK analysis</h2>
                ${warningMessage}
            </div>
            <div class="status-grid">
                ${renderPreviewField("Status", status)}
                ${renderPreviewField("Lookups", `${succeeded} / ${attempted} succeeded`)}
                ${renderPreviewField("Candidate source", enabled ? sourceLabel : "Disabled")}
                ${renderPreviewField("Tactics found", responseData.top_tactics.length)}
                ${renderPreviewField("Techniques found", responseData.top_techniques.length)}
                ${renderPreviewField("Subtechniques found", responseData.top_subtechniques.length)}
            </div>
            <button type="button" class="link-button" data-switch-tab="diagnostics">View technical diagnostics</button>
        </section>
    `;
}

function renderDiagnosticsTab(responseData, includeDebug) {
    if (!includeDebug || !responseData.technical_debug) {
        diagnosticsOutput.classList.add("empty-state");
        diagnosticsOutput.innerHTML = `
            <h3>Technical diagnostics are disabled</h3>
            <p>Enable 'Include technical debug' in the sidebar to inspect API/parser details.</p>
        `;
        return;
    }

    const technicalDebug = responseData.technical_debug || {};
    diagnosticsOutput.classList.remove("empty-state");
    diagnosticsOutput.innerHTML = `
        <div class="report-document">
            <h1>Diagnostics</h1>
            <section class="report-section-card">
                <h2>Ranking debug</h2>
                <pre>${escapeHtml(JSON.stringify(technicalDebug.ranking_debug || {}, null, 2))}</pre>
            </section>
            <section class="report-section-card">
                <h2>TTP debug</h2>
                <pre>${escapeHtml(JSON.stringify(technicalDebug.ttp_debug || {}, null, 2))}</pre>
            </section>
            <section class="report-section-card">
                <h2>Raw samples</h2>
                <pre>${escapeHtml(JSON.stringify(technicalDebug.raw_samples || {}, null, 2))}</pre>
            </section>
        </div>
    `;
}

function renderTtpDiagnosticsPanel(responseData) {
    const ttp = responseData.ttp_analysis || {};
    const warningMessage = ttp.warning_message
        ? `<p class="diagnostic-warning compact">${escapeHtml(String(ttp.warning_message))}</p>`
        : "";
    return `
        <section class="report-section-card">
            <h2>TTP diagnostics summary</h2>
            ${warningMessage}
            <ul>
                <li><strong>ttp_lookups_attempted:</strong> ${escapeHtml(String(ttp.ttp_lookups_attempted ?? 0))}</li>
                <li><strong>ttp_lookups_succeeded:</strong> ${escapeHtml(String(ttp.ttp_lookups_succeeded ?? 0))}</li>
                <li><strong>ttp_eligible_collections:</strong> ${escapeHtml(String(ttp.ttp_eligible_collections ?? 0))}</li>
                <li><strong>top_tactics count:</strong> ${escapeHtml(String(responseData.top_tactics.length))}</li>
                <li><strong>top_techniques count:</strong> ${escapeHtml(String(responseData.top_techniques.length))}</li>
                <li><strong>top_subtechniques count:</strong> ${escapeHtml(String(responseData.top_subtechniques.length))}</li>
            </ul>
        </section>
    `;
}

function renderTtpSections(responseData) {
    const ttp = responseData.ttp_analysis || {};
    if (!ttp.enabled) {
        return "";
    }
    const subtechniquesHtml = Array.isArray(responseData.top_subtechniques)
        && responseData.top_subtechniques.length > 0
            ? renderSectionCard(
                "Top MITRE Subtechniques",
                renderRankingSectionContent("top_subtechniques", responseData.top_subtechniques, "collections"),
            )
            : "";
    return `
        ${renderSectionCard("Top MITRE Tactics", renderRankingSectionContent("top_tactics", responseData.top_tactics || [], "collections", "No MITRE tactics were extracted."))}
        ${renderSectionCard("Top MITRE Techniques", renderRankingSectionContent("top_techniques", responseData.top_techniques || [], "collections", "No MITRE techniques were extracted."))}
        ${subtechniquesHtml}
    `;
}

function renderTopTargetsResult(responseData) {
    const detailLookupsAttempted = Number(responseData.company_detail_lookups_attempted || 0);
    const detailLookupsSucceeded = Number(responseData.company_detail_lookups_succeeded || 0);
    const estimate = responseData.api_request_estimate || {};
    const fieldsCoverage = responseData.fields_coverage || {};
    const collectionsAnalyzed = Number(responseData.collections_analyzed || 0);
    const rankingSectionsHtml = renderSelectedRankingSections(responseData);
    const ttpStatusHtml = renderTtpStatusCard(responseData);
    const ttpSectionsHtml = renderTtpSections(responseData);
    const crossAnalysisSummaryHtml = renderCrossAnalysisSummary(responseData);
    const detailLookupHtml = detailLookupsAttempted > 0
        ? `
        <p class="compact-note">
            <strong>Company detail lookups:</strong>
            ${escapeHtml(String(detailLookupsSucceeded))}/${escapeHtml(String(detailLookupsAttempted))} succeeded
        </p>
        `
        : "";

    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Top Targets Ranking — ${escapeHtml(String(responseData.period || ""))}</h1>
        ${renderMetricChips(responseData)}
        <p>
            <strong>Collections analyzed:</strong> ${escapeHtml(String(responseData.collections_analyzed || 0))} |
            <strong>GTI query:</strong> <code>${escapeHtml(String(responseData.query_used || ""))}</code>
        </p>
        <p><strong>Counting model:</strong> each industry or company is counted at most once per GTI collection.</p>
        <details class="diagnostics-block">
            <summary>Diagnostics</summary>
            <ul>
                <li><strong>Pages fetched:</strong> ${escapeHtml(String(responseData.pages_fetched ?? 0))}</li>
                <li><strong>Actual search requests:</strong> ${escapeHtml(String(responseData.actual_search_requests ?? responseData.pages_fetched ?? 0))}</li>
                <li><strong>Collections seen:</strong> ${escapeHtml(String(responseData.collections_seen ?? 0))}</li>
                <li><strong>Max collections:</strong> ${escapeHtml(String(responseData.max_collections ?? 0))}</li>
                <li><strong>Deep organization lookup:</strong> ${escapeHtml(String(Boolean(responseData.deep_organization_lookup)))}</li>
                <li><strong>Estimated API requests:</strong> ${escapeHtml(String(responseData.estimated_api_requests ?? estimate.estimated_total_requests ?? 0))}</li>
                <li><strong>Targeted industries:</strong> ${escapeHtml(String(fieldsCoverage.targeted_industries ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Targeted regions:</strong> ${escapeHtml(String(fieldsCoverage.targeted_regions ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Source regions:</strong> ${escapeHtml(String(fieldsCoverage.source_regions ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Tags/themes:</strong> ${escapeHtml(String(fieldsCoverage.tags ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Collection type:</strong> ${escapeHtml(String(fieldsCoverage.collection_type ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Timeline:</strong> ${escapeHtml(String(fieldsCoverage.timeline ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
                <li><strong>Targeted organizations:</strong> ${escapeHtml(String(fieldsCoverage.targeted_organizations ?? 0))} / ${escapeHtml(String(collectionsAnalyzed))} collections</li>
            </ul>
        </details>
        ${ttpStatusHtml}
        ${detailLookupHtml}

        ${rankingSectionsHtml}

        ${ttpSectionsHtml}

        ${crossAnalysisSummaryHtml}

        <div class="methodology-note">
            <strong>Methodology:</strong> ${escapeHtml(String(responseData.methodology || ""))}
        </div>
    `;
}

function formatInteger(value) {
    return Number(value || 0).toLocaleString();
}

function localDateTimeToRfc3339(value) {
    if (!value) {
        return "";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return "";
    }
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function renderDtmMetricCards(responseData) {
    const summary = responseData.summary || {};
    const quota = responseData.quota || {};
    const cards = [
        ["Monitors", summary.total_monitors, `${formatInteger(quota.remaining_estimate)} remaining estimate`],
        ["Alerts", summary.total_alerts, "selected period"],
        ["High", summary.high_alerts, "severity"],
        ["Medium", summary.medium_alerts, "severity"],
        ["Low", summary.low_alerts, "severity"],
        ["Quota Used", `${Number(quota.used_percent || 0).toFixed(1)}%`, `${formatInteger(quota.monitor_count)} / ${formatInteger(quota.default_monitor_quota)}`],
    ];

    return `
        <div class="kpi-grid">
            ${cards.map(([label, value, hint]) => `
                <div class="kpi-card">
                    <span>${escapeHtml(String(label))}</span>
                    <strong>${escapeHtml(String(value ?? 0))}</strong>
                    <small>${escapeHtml(String(hint || ""))}</small>
                </div>
            `).join("")}
        </div>
    `;
}

function renderDtmBarTable(items, options) {
    const rows = Array.isArray(items) ? items : [];
    if (rows.length === 0) {
        return `<p><em>${escapeHtml(options.emptyMessage || "No data for this chart.")}</em></p>`;
    }

    const valueKey = options.valueKey;
    const labelKey = options.labelKey;
    const maxValue = Math.max(...rows.map((item) => Number(item[valueKey] || 0)), 1);

    return `
        <table class="ranking-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>${escapeHtml(options.labelTitle || "Name")}</th>
                    <th>Volume</th>
                    <th>${escapeHtml(options.valueTitle || "Count")}</th>
                </tr>
            </thead>
            <tbody>
                ${rows.map((item, index) => {
                    const value = Number(item[valueKey] || 0);
                    const pct = Math.round((value / maxValue) * 100);
                    return `
                        <tr class="ranking-row">
                            <td class="rank-cell">${escapeHtml(String(index + 1))}</td>
                            <td class="name-cell">${escapeHtml(String(item[labelKey] || "Unknown"))}</td>
                            <td class="bar-cell">
                                <div class="ranking-bar-wrap">
                                    <div class="ranking-bar" style="width:${pct}%"></div>
                                </div>
                            </td>
                            <td class="count-cell">${escapeHtml(formatInteger(value))}</td>
                        </tr>
                    `;
                }).join("")}
            </tbody>
        </table>
    `;
}

function renderDtmCountTable(items, keyName, label) {
    const rows = Array.isArray(items) ? items : [];
    if (rows.length === 0) {
        return "<p><em>No alerts in this category.</em></p>";
    }
    return `
        <table class="ranking-table compact-table">
            <thead>
                <tr>
                    <th>${escapeHtml(label)}</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                ${rows.map((item) => `
                    <tr class="ranking-row">
                        <td class="name-cell">${escapeHtml(String(item[keyName] || "Unknown"))}</td>
                        <td class="count-cell">${escapeHtml(formatInteger(item.count))}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

function renderDtmMonitorTable(responseData) {
    const monitors = Array.isArray(responseData.monitors) ? [...responseData.monitors] : [];
    const sortableKeys = new Set(["alert_count", "risk_score", "noise_score", "high"]);
    const sortKey = sortableKeys.has(dtmMonitorSortKey) ? dtmMonitorSortKey : "risk_score";
    const direction = dtmMonitorSortDirection === "asc" ? 1 : -1;
    monitors.sort((a, b) => {
        const aValue = Number(a[sortKey] || 0);
        const bValue = Number(b[sortKey] || 0);
        if (aValue !== bValue) {
            return (aValue - bValue) * direction;
        }
        return String(a.name || "").localeCompare(String(b.name || ""));
    });

    const headerButton = (key, label) => `
        <button type="button" class="table-sort-button" data-dtm-sort="${escapeHtml(key)}">
            ${escapeHtml(label)}${sortKey === key ? (dtmMonitorSortDirection === "asc" ? " ↑" : " ↓") : ""}
        </button>
    `;

    if (monitors.length === 0) {
        return "<p><em>No monitor rows are available.</em></p>";
    }

    return `
        <div class="table-scroll">
            <table class="ranking-table monitor-table">
                <thead>
                    <tr>
                        <th>Monitor</th>
                        <th>${headerButton("alert_count", "Alerts")}</th>
                        <th>${headerButton("risk_score", "Risk")}</th>
                        <th>${headerButton("noise_score", "Noise")}</th>
                        <th>${headerButton("high", "High")}</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Last Alert</th>
                    </tr>
                </thead>
                <tbody>
                    ${monitors.map((item) => `
                        <tr class="ranking-row">
                            <td class="name-cell">
                                <strong>${escapeHtml(String(item.name || "Unknown monitor"))}</strong>
                                <small>${escapeHtml(String(item.monitor_id || ""))}</small>
                            </td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.alert_count))}</td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.risk_score))}</td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.noise_score))}</td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.high))}</td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.medium))}</td>
                            <td class="count-cell">${escapeHtml(formatInteger(item.low))}</td>
                            <td class="count-cell">${escapeHtml(String(item.last_alert_date || "none"))}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function renderDtmInactiveTable(items) {
    const rows = Array.isArray(items) ? items : [];
    if (rows.length === 0) {
        return "<p><em>No inactive monitors for this period.</em></p>";
    }
    return `
        <table class="ranking-table compact-table">
            <thead>
                <tr>
                    <th>Monitor</th>
                    <th>Last Alert</th>
                </tr>
            </thead>
            <tbody>
                ${rows.slice(0, 20).map((item) => `
                    <tr class="ranking-row">
                        <td class="name-cell">${escapeHtml(String(item.monitor_name || "Unknown monitor"))}</td>
                        <td class="count-cell">${escapeHtml(String(item.last_alert_date || "none"))}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

// ── DTM Dashboard SVG charts ─────────────────────────────────────────────────

/** Traffic-light colours for alert severity levels. */
const DTM_SEVERITY_COLORS = { high: "#dc3545", medium: "#fd7e14", low: "#28a745" };

/**
 * Renders an SVG donut chart for the alerts-by-severity section.
 * Expects rows like [{severity: "high"|"medium"|"low", count: N}, ...].
 */
function renderDtmSeverityDonut(items) {
    const rows = Array.isArray(items) ? items.filter((r) => Number(r.count || 0) > 0) : [];
    const total = rows.reduce((s, r) => s + Number(r.count || 0), 0);
    if (!rows.length || total === 0) {
        return `<p><em>No severity data for this period.</em></p>`;
    }

    const cx = 72, cy = 72, outerR = 58, innerR = 35;
    let angle = -Math.PI / 2;
    const slices = rows.map((row) => {
        const fraction = Number(row.count) / total;
        const sweep = fraction * Math.PI * 2;
        const color = DTM_SEVERITY_COLORS[(row.severity || "").toLowerCase()] || "#888";
        const startAngle = angle;
        const endAngle = angle + sweep;
        angle = endAngle;
        const largeArc = sweep > Math.PI ? 1 : 0;

        if (rows.length === 1) {
            return `<circle cx="${cx}" cy="${cy}" r="${outerR}" fill="${color}"></circle>`;
        }
        const x1o = cx + outerR * Math.cos(startAngle);
        const y1o = cy + outerR * Math.sin(startAngle);
        const x2o = cx + outerR * Math.cos(endAngle);
        const y2o = cy + outerR * Math.sin(endAngle);
        const x1i = cx + innerR * Math.cos(startAngle);
        const y1i = cy + innerR * Math.sin(startAngle);
        const x2i = cx + innerR * Math.cos(endAngle);
        const y2i = cy + innerR * Math.sin(endAngle);
        return `<path d="M ${x1i} ${y1i} L ${x1o} ${y1o} A ${outerR} ${outerR} 0 ${largeArc} 1 ${x2o} ${y2o} L ${x2i} ${y2i} A ${innerR} ${innerR} 0 ${largeArc} 0 ${x1i} ${y1i} Z" fill="${color}"><title>${escapeHtml(row.severity)}: ${escapeHtml(String(row.count))}</title></path>`;
    }).join("");

    const legend = rows.map((row) => {
        const color = DTM_SEVERITY_COLORS[(row.severity || "").toLowerCase()] || "#888";
        const sev = String(row.severity || "");
        const label = sev.charAt(0).toUpperCase() + sev.slice(1);
        const percent = Math.round((Number(row.count) / total) * 100);
        return `<li>
            <span class="ioc-chart-swatch" style="background:${color}"></span>
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(String(row.count))} (${percent}%)</strong>
        </li>`;
    }).join("");

    return `
        <div class="ioc-donut-chart" role="img" aria-label="Alerts by severity">
            <svg viewBox="0 0 144 144" aria-hidden="true">
                ${slices}
                <circle cx="${cx}" cy="${cy}" r="${innerR}" fill="white"></circle>
                <text x="${cx}" y="${cy - 3}" text-anchor="middle" class="ioc-donut-total">${escapeHtml(String(total))}</text>
                <text x="${cx}" y="${cy + 13}" text-anchor="middle" class="ioc-donut-label">Alerts</text>
            </svg>
            <ul class="ioc-chart-legend">${legend}</ul>
        </div>`;
}

/**
 * Renders a horizontal bar chart for a list of DTM data rows.
 * @param {Array} rows - Array of data objects.
 * @param {string} labelKey - Property name for the bar label.
 * @param {string} valueKey - Property name for the numeric value.
 * @param {{ emptyMessage?: string, colorFn?: (row, index) => string }} options
 */
function renderDtmHorizontalBars(rows, labelKey, valueKey, options) {
    const data = Array.isArray(rows) ? rows : [];
    const opts = options || {};
    if (!data.length) {
        return `<p><em>${escapeHtml(opts.emptyMessage || "No data for this period.")}</em></p>`;
    }
    const maxValue = Math.max(...data.map((r) => Number(r[valueKey] || 0)), 1);
    const colorFn = opts.colorFn || ((_, i) => CHART_PALETTE[i % CHART_PALETTE.length]);

    return `<div class="dtm-bar-chart">
        ${data.map((row, i) => {
            const value = Number(row[valueKey] || 0);
            const pct = Math.max(4, Math.round((value / maxValue) * 100));
            return `
            <div class="dtm-bar-row">
                <span class="dtm-bar-label" title="${escapeHtml(String(row[labelKey] || "Unknown"))}">${escapeHtml(String(row[labelKey] || "Unknown"))}</span>
                <div class="dtm-bar-track"><div class="dtm-bar-fill" style="width:${pct}%;background:${colorFn(row, i)}"></div></div>
                <strong class="dtm-bar-value">${escapeHtml(formatInteger(value))}</strong>
            </div>`;
        }).join("")}
    </div>`;
}

/**
 * Renders a vertical bar chart for the alerts-timeline section.
 * Expects rows like [{date: "YYYY-MM-DD", count: N}, ...].
 */
function renderDtmTimelineChart(items) {
    const rows = Array.isArray(items) ? items : [];
    if (!rows.length) {
        return `<p><em>No dated alerts were returned.</em></p>`;
    }

    const maxCount = Math.max(...rows.map((r) => Number(r.count || 0)), 1);
    const chartH = 90;
    const barW = Math.max(8, Math.min(30, Math.floor(460 / rows.length)));
    const gap = Math.max(2, Math.ceil(barW * 0.25));
    const totalW = rows.length * (barW + gap) - gap;
    const labelStep = Math.max(1, Math.ceil(rows.length / 10));

    const bars = rows.map((row, i) => {
        const count = Number(row.count || 0);
        const barH = Math.max(2, Math.round((count / maxCount) * chartH));
        const x = i * (barW + gap);
        const y = chartH - barH;
        const dateShort = String(row.date || "").slice(5); // "MM-DD"
        return `<g>
            <rect x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${CHART_PALETTE[0]}" rx="2" opacity="0.9">
                <title>${escapeHtml(String(row.date))}: ${escapeHtml(String(count))}</title>
            </rect>
            ${i % labelStep === 0 ? `<text x="${x + barW / 2}" y="${chartH + 14}" text-anchor="middle" class="dtm-timeline-label">${escapeHtml(dateShort)}</text>` : ""}
        </g>`;
    }).join("");

    return `
        <div class="dtm-timeline-wrap">
            <svg viewBox="0 0 ${totalW} ${chartH + 20}" class="dtm-timeline-svg" role="img" aria-label="Alerts timeline">
                ${bars}
            </svg>
        </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────

function renderDtmDashboard(responseData) {
    const charts = responseData.charts || {};
    const summary = responseData.summary || {};
    const period = responseData.period || {};
    const limits = responseData.limits || {};
    const maxAlerts = Number(limits.max_alerts || 500);
    const warnings = Array.isArray(responseData.warnings) ? responseData.warnings : [];
    const warningsHtml = warnings.length > 0
        ? `<div class="diagnostic-warning compact">${warnings.map((warning) => escapeHtml(String(warning))).join("<br>")}</div>`
        : "";

    const dashboardHtml = `
        <div class="report-document dashboard-document">
            <h1>DTM Monitor & Alert Dashboard</h1>
            <p>
                <strong>Period:</strong> ${escapeHtml(String(period.since || ""))} to ${escapeHtml(String(period.until || ""))}
            </p>
            <p class="compact-note">Showing up to ${escapeHtml(formatInteger(maxAlerts))} alerts. Increase max_pages to fetch more.</p>
            ${warningsHtml}
            ${renderDtmMetricCards(responseData)}
            <section class="status-card">
                <div>
                    <h2>Monitor posture</h2>
                    <p><strong>Monitors with alerts:</strong> ${escapeHtml(formatInteger(summary.monitors_with_alerts))} | <strong>Inactive:</strong> ${escapeHtml(formatInteger(summary.monitors_without_alerts))}</p>
                    <p><strong>Top risky monitor:</strong> ${escapeHtml(String(summary.top_risky_monitor || "none"))}</p>
                    <p><strong>Top noisy monitor:</strong> ${escapeHtml(String(summary.top_noisy_monitor || "none"))}</p>
                </div>
            </section>
            <div class="stats-charts-grid dtm-charts-grid">
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Top Monitors by Alert Count</h2>
                    ${renderDtmHorizontalBars(
                        charts.top_monitors_by_alert_count,
                        "monitor_name", "alert_count",
                        { emptyMessage: "No alerts returned for this period." },
                    )}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Top Monitors by Risk Score</h2>
                    ${renderDtmHorizontalBars(
                        charts.top_monitors_by_risk_score,
                        "monitor_name", "risk_score",
                        {
                            emptyMessage: "No risk score was computed for this period.",
                            colorFn: (row) => {
                                const r = Number(row.risk_score || 0);
                                return r >= 20 ? "#dc3545" : r >= 8 ? "#fd7e14" : "#28a745";
                            },
                        },
                    )}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Severity</h2>
                    ${renderDtmSeverityDonut(charts.alerts_by_severity)}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Type</h2>
                    ${renderDtmHorizontalBars(
                        charts.alerts_by_type,
                        "type", "count",
                        { emptyMessage: "No alert type data for this period." },
                    )}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Status</h2>
                    ${renderDtmHorizontalBars(
                        charts.alerts_by_status,
                        "status", "count",
                        { emptyMessage: "No alert status data for this period." },
                    )}
                </section>
                <section class="stats-chart-panel dtm-timeline-panel">
                    <h2 class="stats-chart-title">Alerts Timeline</h2>
                    ${renderDtmTimelineChart(charts.alerts_timeline)}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Noisy Monitors</h2>
                    ${renderDtmHorizontalBars(
                        charts.noisy_monitors,
                        "monitor_name", "noise_score",
                        { emptyMessage: "No noisy monitor pattern was detected." },
                    )}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Inactive Monitors</h2>
                    ${renderDtmInactiveTable(charts.inactive_monitors)}
                </section>
            </div>
            <section class="report-section-card">
                <h2>Monitor Table</h2>
                ${renderDtmMonitorTable(responseData)}
            </section>
        </div>
    `;

    dtmDashboardOutput.classList.remove("empty-state");
    dtmDashboardOutput.innerHTML = dashboardHtml;
    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>DTM Monitor & Alert Dashboard</h1>
        ${renderDtmMetricCards(responseData)}
        <p><strong>Period:</strong> ${escapeHtml(String(period.since || ""))} to ${escapeHtml(String(period.until || ""))}</p>
        <p class="compact-note">Showing up to ${escapeHtml(formatInteger(maxAlerts))} alerts. Increase max_pages to fetch more.</p>
        <button type="button" class="link-button" data-switch-tab="dtm-dashboard">Open DTM Dashboard tab</button>
    `;
}

function buildIocStreamParams() {
    const params = new URLSearchParams();
    const collectionMode = iocStreamCollectionModeField?.value || "time_window";
    const pagesChoice = iocStreamPagesToFetchField?.value || "5";
    const maxPages = pagesChoice === "custom"
        ? Number(iocStreamCustomPagesField?.value || 10)
        : Number(pagesChoice || 5);
    params.set("collection_mode", collectionMode);
    params.set("max_pages", String(maxPages));
    params.set("entity_type", iocStreamEntityTypeField?.value || "all");
    params.set("origin", iocStreamOriginField?.value || "all");
    params.set("enrich", "true");
    params.set("descriptors_only", "false");
    if (collectionMode === "time_window") {
        const timeWindow = iocStreamTimeWindowField?.value || "last_24h";
        params.set("time_window", timeWindow);
        const advancedFilter = iocStreamAdvancedFilterField?.value?.trim() || "";
        if (advancedFilter) {
            params.set("advanced_gti_filter_override", advancedFilter);
        }
        const startDate = iocStreamStartDateField?.value || "";
        const endDate = iocStreamEndDateField?.value || "";
        if (timeWindow === "custom") {
            if (startDate) params.set("start_date", startDate);
            if (endDate) params.set("end_date", endDate);
        }
    }
    return params;
}

function syncIocStreamCollectionControls() {
    const collectionMode = iocStreamCollectionModeField?.value || "time_window";
    const pagesChoice = iocStreamPagesToFetchField?.value || "5";
    const isCustomPages = pagesChoice === "custom";
    const isTimeWindow = collectionMode === "time_window";
    const isCustomWindow = (iocStreamTimeWindowField?.value || "last_24h") === "custom";

    if (iocStreamCustomPagesWrapper) {
        iocStreamCustomPagesWrapper.hidden = !isCustomPages;
    }
    if (iocStreamCustomPagesField) {
        iocStreamCustomPagesField.disabled = !isCustomPages;
    }
    if (iocStreamTimeWindowWrapper) {
        iocStreamTimeWindowWrapper.hidden = !isTimeWindow;
    }
    if (iocStreamTimeWindowField) {
        iocStreamTimeWindowField.disabled = !isTimeWindow;
    }
    if (iocStreamAdvancedFilterWrapper) {
        iocStreamAdvancedFilterWrapper.hidden = !isTimeWindow;
    }
    if (iocStreamAdvancedFilterField) {
        iocStreamAdvancedFilterField.disabled = !isTimeWindow;
    }
    if (iocStreamCustomDatesWrapper) {
        iocStreamCustomDatesWrapper.hidden = !isTimeWindow || !isCustomWindow;
    }
    [iocStreamStartDateField, iocStreamEndDateField].filter(Boolean).forEach((field) => {
        field.disabled = !isTimeWindow || !isCustomWindow;
        field.required = isTimeWindow && isCustomWindow;
    });
}

function normalizeChartRows(rows) {
    return Array.isArray(rows)
        ? rows.map((row) => ({
            label: String(row.label || "Unknown"),
            value: Number(row.value || 0),
        })).filter((row) => row.value > 0)
        : [];
}

function renderIocStreamDonutChart(rows, title) {
    const data = normalizeChartRows(rows);
    const total = data.reduce((sum, row) => sum + row.value, 0);
    if (!data.length || total <= 0) {
        return `<div class="ioc-chart-empty">No chart data.</div>`;
    }

    const cx = 72;
    const cy = 72;
    const outerRadius = 58;
    const innerRadius = 35;
    let angle = -Math.PI / 2;
    const slices = data.map((row, index) => {
        const fraction = row.value / total;
        const sweep = fraction * Math.PI * 2;
        const startAngle = angle;
        const endAngle = angle + sweep;
        angle = endAngle;
        const color = CHART_PALETTE[index % CHART_PALETTE.length];
        const largeArc = sweep > Math.PI ? 1 : 0;

        if (data.length === 1) {
            return `<circle cx="${cx}" cy="${cy}" r="${outerRadius}" fill="${color}"></circle>`;
        }

        const x1o = cx + outerRadius * Math.cos(startAngle);
        const y1o = cy + outerRadius * Math.sin(startAngle);
        const x2o = cx + outerRadius * Math.cos(endAngle);
        const y2o = cy + outerRadius * Math.sin(endAngle);
        const x1i = cx + innerRadius * Math.cos(startAngle);
        const y1i = cy + innerRadius * Math.sin(startAngle);
        const x2i = cx + innerRadius * Math.cos(endAngle);
        const y2i = cy + innerRadius * Math.sin(endAngle);
        return `
            <path
                d="M ${x1i} ${y1i} L ${x1o} ${y1o} A ${outerRadius} ${outerRadius} 0 ${largeArc} 1 ${x2o} ${y2o} L ${x2i} ${y2i} A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${x1i} ${y1i} Z"
                fill="${color}"
            ></path>
        `;
    }).join("");

    const legend = data.map((row, index) => {
        const percent = Math.round((row.value / total) * 100);
        return `
            <li>
                <span class="ioc-chart-swatch" style="background:${CHART_PALETTE[index % CHART_PALETTE.length]}"></span>
                <span>${escapeHtml(row.label)}</span>
                <strong>${escapeHtml(String(row.value))} (${percent}%)</strong>
            </li>
        `;
    }).join("");

    return `
        <div class="ioc-donut-chart" role="img" aria-label="${escapeHtml(title)}">
            <svg viewBox="0 0 144 144" aria-hidden="true">
                ${slices}
                <circle cx="${cx}" cy="${cy}" r="${innerRadius}" fill="white"></circle>
                <text x="${cx}" y="${cy - 3}" text-anchor="middle" class="ioc-donut-total">${escapeHtml(String(total))}</text>
                <text x="${cx}" y="${cy + 13}" text-anchor="middle" class="ioc-donut-label">IoCs</text>
            </svg>
            <ul class="ioc-chart-legend">${legend}</ul>
        </div>
    `;
}

function renderIocStreamBarChart(rows) {
    const data = normalizeChartRows(rows);
    if (!data.length) {
        return `<div class="ioc-chart-empty">No chart data.</div>`;
    }
    const maxValue = Math.max(...data.map((row) => row.value), 1);
    return `
        <div class="ioc-bar-chart">
            ${data.map((row) => {
                const width = Math.max(4, Math.round((row.value / maxValue) * 100));
                return `
                    <div class="ioc-bar-row">
                        <span>${escapeHtml(row.label)}</span>
                        <div class="ioc-bar-track"><div class="ioc-bar-fill" style="width:${width}%"></div></div>
                        <strong>${escapeHtml(String(row.value))}</strong>
                    </div>
                `;
            }).join("")}
        </div>
    `;
}

function SummaryCards(summary) {
    const cards = [
        ["Total IoCs", summary.total_iocs ?? 0, "returned"],
        ["High Risk", summary.high_risk ?? 0, "urgent"],
        ["Medium Risk", summary.medium_risk ?? 0, "review"],
        ["Main IoC Type", summary.main_entity_type || "Unknown", "dominant"],
        ["Main Source Type", summary.main_source_type || "Unknown", "dominant"],
    ];
    return `
        <div class="kpi-grid ioc-summary-grid">
            ${cards.map(([label, value, hint]) => `
                <div class="kpi-card">
                    <span>${escapeHtml(String(label))}</span>
                    <strong>${escapeHtml(String(value))}</strong>
                    <small>${escapeHtml(String(hint))}</small>
                </div>
            `).join("")}
        </div>
    `;
}

function formatTimestampForReport(value) {
    if (!value) {
        return "n/a";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }
    return date.toLocaleString();
}

function RecentExposureCollectionSummary(responseData) {
    const collection = responseData.collection || responseData.technical_details?.collection || {};
    const warnings = Array.isArray(responseData.technical_details?.warnings)
        ? responseData.technical_details.warnings
        : [];
    const diagnostics = responseData.technical_details?.diagnostics || {};
    const pageDiagnostics = Array.isArray(diagnostics.page_diagnostics)
        ? diagnostics.page_diagnostics
        : (Array.isArray(collection.page_diagnostics) ? collection.page_diagnostics : []);
    const collectionMode = collection.collection_mode || responseData.technical_details?.request_params?.collection_mode || "time_window";
    const modeLabel = collectionMode === "time_window" ? "GTI matched-on date filter" : "Unfiltered IoC Stream sample (diagnostic)";
    const stoppedReason = String(collection.stopped_reason || "unknown").replaceAll("_", " ");
    const gtiOrderSent = collection.gti_order_sent || responseData.technical_details?.request_params?.gti_order_sent || responseData.technical_details?.request_params?.order || "n/a";
    const gtiOrderEffective = collection.gti_order_effective || responseData.technical_details?.request_params?.gti_order_effective || gtiOrderSent;
    const gtiFilterSent = collection.gti_filter_sent || collection.server_side_date_filter_string || responseData.technical_details?.request_params?.gti_filter_sent || "n/a";
    const earliestMatchedOnTimestamp = collection.earliest_fetched_timestamp || responseData.summary?.earliest_fetched_timestamp || collection.oldest_stream_event_timestamp || diagnostics.oldest_stream_event_timestamp;
    const latestMatchedOnTimestamp = collection.latest_fetched_timestamp || responseData.summary?.latest_fetched_timestamp;
    const recommendation = collection.recommendation || diagnostics.recommendation || "";
    const returnedByDateFilter = collection.raw_iocs_returned ?? collection.server_side_date_filter_returned_count ?? collection.raw_ioc_count ?? responseData.summary?.raw_ioc_count ?? 0;
    const insideWindowValue = collectionMode === "time_window" ? returnedByDateFilter : (collection.iocs_inside_window ?? responseData.summary?.iocs_inside_window ?? collection.raw_ioc_count ?? 0);
    const insideWindowHint = collectionMode === "time_window" ? "GTI filter" : "kept";
    const serverDateDiagnosticsLine = collectionMode === "time_window" && collection.server_side_date_filter_attempted ? `<p class="compact-note">GTI filter sent: ${escapeHtml(String(gtiFilterSent))}. Raw IoCs returned: ${escapeHtml(String(returnedByDateFilter))}.</p>` : "";
    const streamTimestampFields = diagnostics.stream_timestamp_fields_seen || collection.stream_timestamp_fields_seen || [];
    const cards = [
        ["Collection Mode", modeLabel, "mode"],
        ["Requested Pages", collection.requested_pages ?? responseData.technical_details?.request_params?.pages_to_fetch ?? "n/a", "input"],
        ["Pages Fetched", collection.pages_fetched ?? responseData.summary?.pages_fetched ?? 0, "GTI pages"],
        ["Max Pages", collection.max_pages ?? collection.requested_pages ?? "n/a", "safety cap"],
        ["Page Size", collection.page_size ?? responseData.summary?.page_size ?? "n/a", "API limit"],
        ["GTI Order Sent", gtiOrderSent, collection.gti_order_fallback_used ? `fallback ${gtiOrderEffective}` : "order"],
        ["Raw IoCs Fetched", collection.raw_ioc_count ?? responseData.summary?.raw_ioc_count ?? 0, "before filtering"],
        [collectionMode === "time_window" ? "GTI Filter Returned" : "Fetched IoCs", insideWindowValue, insideWindowHint],
        ["Unique IoCs", collection.unique_ioc_count ?? responseData.summary?.unique_ioc_count ?? 0, "deduped"],
        ["Duplicates Removed", collection.duplicates_removed ?? responseData.summary?.duplicates_removed ?? 0, "duplicates"],
        ["Enriched", collection.total_enriched ?? responseData.summary?.total_enriched ?? 0, "IoCs"],
        ["Stopped", stoppedReason, "reason"],
        ["Coverage", collection.coverage_status || "n/a", "sample"],
        ...(collectionMode === "time_window" ? [
            ["GTI Filter Sent", gtiFilterSent, "filter"],
            ["Earliest matched on", formatTimestampForReport(earliestMatchedOnTimestamp), "timestamp"],
            ["Latest matched on", formatTimestampForReport(latestMatchedOnTimestamp), "timestamp"],
        ] : []),
    ];
    const diagnosticsTable = pageDiagnostics.length ? `
        <details class="diagnostics-block">
            <summary>IoC Stream pagination diagnostics</summary>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Page</th>
                            <th>Raw items</th>
                            <th>Next cursor</th>
                            <th>Next link</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${pageDiagnostics.map((page) => `
                            <tr>
                                <td>${escapeHtml(String(page.page_number ?? "n/a"))}</td>
                                <td>${escapeHtml(String(page.raw_page_item_count ?? 0))}</td>
                                <td>${escapeHtml(String(Boolean(page.next_cursor_found)))}</td>
                                <td>${escapeHtml(String(Boolean(page.next_link_found)))}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            </div>
            <p class="compact-note">Stopped reason: ${escapeHtml(String(diagnostics.stopped_reason || collection.stopped_reason || "unknown"))}. Unique IoCs: ${escapeHtml(String(diagnostics.unique_ioc_count ?? collection.unique_ioc_count ?? 0))}. Duplicates removed: ${escapeHtml(String(diagnostics.duplicates_removed ?? collection.duplicates_removed ?? 0))}.</p>
            <p class="compact-note">Raw IoCs: ${escapeHtml(String(diagnostics.raw_ioc_count ?? collection.raw_ioc_count ?? 0))}. Items with stream timestamp: ${escapeHtml(String(diagnostics.items_with_stream_timestamp ?? collection.items_with_stream_timestamp ?? 0))}. Items without stream timestamp: ${escapeHtml(String(diagnostics.items_without_stream_timestamp ?? collection.items_without_stream_timestamp ?? collection.items_without_stream_timestamp_count ?? 0))}.</p>
            <p class="compact-note">GTI order sent: ${escapeHtml(String(gtiOrderSent))}. Effective order: ${escapeHtml(String(gtiOrderEffective))}.</p>
            ${serverDateDiagnosticsLine}
            <p class="compact-note">Matched on fields seen: ${escapeHtml(String(streamTimestampFields.join?.(", ") || "none"))}.</p>
            <p class="compact-note">Notification dates: ${escapeHtml(String(diagnostics.notification_date_count ?? collection.notification_date_count ?? 0))}. Matched_on fallbacks: ${escapeHtml(String(diagnostics.matched_on_fallback_count ?? collection.matched_on_fallback_count ?? 0))}. Missing notification dates: ${escapeHtml(String(diagnostics.missing_notification_date_count ?? collection.missing_notification_date_count ?? 0))}. Notification IDs: ${escapeHtml(String(diagnostics.notification_id_count ?? collection.notification_id_count ?? 0))}.</p>
            <p class="compact-note">Timestamp fields seen: ${escapeHtml(String((diagnostics.timestamp_fields_seen || collection.timestamp_fields_seen || []).join?.(", ") || "none"))}. Stop timestamp field: ${escapeHtml(String(diagnostics.stop_timestamp_field || collection.stop_timestamp_field || "none"))}.</p>
            <p class="compact-note">Oldest matched on timestamp: ${escapeHtml(String(formatTimestampForReport(diagnostics.oldest_stream_event_timestamp || collection.oldest_stream_event_timestamp)))}.</p>
            <p class="compact-note">Items without matched on: ${escapeHtml(String(diagnostics.items_without_stream_timestamp_count ?? collection.items_without_stream_timestamp_count ?? 0))}.</p>
        </details>
    ` : "";
    return `
        <section class="report-section-card">
            <h2>IoC Stream Collection</h2>
            <p><strong>Mode:</strong> ${escapeHtml(String(modeLabel))}</p>
            <p><strong>Requested pages:</strong> ${escapeHtml(String(collection.requested_pages ?? responseData.technical_details?.request_params?.pages_to_fetch ?? "n/a"))}</p>
            <p><strong>Pages fetched:</strong> ${escapeHtml(String(collection.pages_fetched ?? responseData.summary?.pages_fetched ?? 0))}</p>
            <p><strong>Max pages:</strong> ${escapeHtml(String(collection.max_pages ?? collection.requested_pages ?? "n/a"))}</p>
            <p><strong>Page size:</strong> ${escapeHtml(String(collection.page_size ?? responseData.summary?.page_size ?? "n/a"))}</p>
            <p><strong>GTI order sent:</strong> ${escapeHtml(String(gtiOrderSent))}</p>
            <p><strong>Raw IoCs fetched:</strong> ${escapeHtml(String(collection.raw_ioc_count ?? responseData.summary?.raw_ioc_count ?? 0))}</p>
            <p><strong>${collectionMode === "time_window" ? "IoCs returned by GTI filter" : "Fetched IoCs"}:</strong> ${escapeHtml(String(insideWindowValue))}</p>
            <p><strong>Unique IoCs after deduplication:</strong> ${escapeHtml(String(collection.unique_ioc_count ?? responseData.summary?.unique_ioc_count ?? 0))}</p>
            <p><strong>Duplicates removed:</strong> ${escapeHtml(String(collection.duplicates_removed ?? responseData.summary?.duplicates_removed ?? 0))}</p>
            <p><strong>Stopped reason:</strong> ${escapeHtml(String(stoppedReason))}</p>
            ${collectionMode === "time_window" ? `<p><strong>Earliest matched on:</strong> ${escapeHtml(String(formatTimestampForReport(earliestMatchedOnTimestamp)))}</p>` : ""}
            ${collectionMode === "time_window" ? `<p><strong>Latest matched on:</strong> ${escapeHtml(String(formatTimestampForReport(latestMatchedOnTimestamp)))}</p>` : ""}
            ${collectionMode === "time_window" ? `<p><strong>Coverage status:</strong> ${escapeHtml(String(collection.coverage_status || "unknown"))}</p>` : ""}
            ${collectionMode === "time_window" ? `<p><strong>GTI filter sent:</strong> ${escapeHtml(String(gtiFilterSent))}</p>` : ""}
            ${recommendation ? `<p><strong>Recommendation:</strong> ${escapeHtml(String(recommendation))}</p>` : ""}
            <div class="kpi-grid ioc-summary-grid">
                ${cards.map(([label, value, hint]) => `
                    <div class="kpi-card">
                        <span>${escapeHtml(String(label))}</span>
                        <strong>${escapeHtml(String(value))}</strong>
                        <small>${escapeHtml(String(hint))}</small>
                    </div>
                `).join("")}
            </div>
            <p class="compact-note">${collectionMode === "time_window" ? "IoC Stream was fetched with the GTI matched-on date filter. Results are a GTI-filtered sample, not a complete coverage claim." : "Diagnostic mode only: this endpoint may not reflect the newest Matched on dates without a GTI date filter."}</p>
            ${warnings.length ? `<div class="diagnostic-warning compact">${warnings.map((warning) => `<p>${escapeHtml(String(warning))}</p>`).join("")}</div>` : ""}
            ${diagnosticsTable}
        </section>
    `;
}

function IocStreamCharts(charts) {
    const chartData = charts || {};
    return `
        <div class="stats-charts-grid ioc-chart-grid">
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">IoCs by Entity Type</h2>
                ${renderIocStreamDonutChart(chartData.by_entity_type, "IoCs by entity type")}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">IoCs by Risk</h2>
                ${renderIocStreamBarChart(chartData.by_risk)}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Recommended Actions</h2>
                ${renderIocStreamDonutChart(chartData.by_recommended_action, "Recommended actions")}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Intelligence Source Distribution</h2>
                ${renderIocStreamBarChart(chartData.by_source_type)}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Origin Distribution</h2>
                ${renderIocStreamDonutChart(chartData.by_origin, "Origin distribution")}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Trend Over Time</h2>
                ${renderIocStreamBarChart(chartData.trend_over_time)}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Most Active Threat Categories</h2>
                ${renderIocStreamBarChart(chartData.by_threat_category)}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Most Targeted Industries</h2>
                ${renderIocStreamBarChart(chartData.by_targeted_industry)}
            </section>
        </div>
    `;
}

function IocStreamEnrichmentStatus(technicalDetails) {
    const enrichment = technicalDetails?.enrichment || {};
    const enabled = Boolean(enrichment.enabled);
    const cards = [
        ["Enrichment", enabled ? "Enabled" : "Disabled"],
        ["Attempted", enrichment.attempted ?? 0],
        ["Succeeded", enrichment.succeeded ?? 0],
        ["Skipped", enrichment.skipped ?? 0],
        ["Errors", enrichment.errors ?? 0],
        ["Too Long URLs", enrichment.skipped_too_long_url ?? 0],
        ["Requested", enrichment.requested_limit ?? 0],
        ["Actual Scope", enrichment.actual_limit ?? 0],
    ];
    return `
        <section class="report-section-card">
            <h2>Enrichment Status</h2>
            <div class="mini-metric-grid">
                ${cards.map(([label, value]) => `
                    <div class="mini-metric">
                        <span>${escapeHtml(String(label))}</span>
                        <strong>${escapeHtml(String(value))}</strong>
                    </div>
                `).join("")}
            </div>
            <p class="compact-note">Risk scoring requires enrichment. This may generate one API lookup per IoC. Unknown means enrichment failed or GTI returned no risk context.</p>
        </section>
    `;
}

function formatAnalyticsPercent(value) {
    const number = Number(value || 0);
    return `${number.toFixed(number % 1 === 0 ? 0 : 1)}%`;
}

function IocStreamAnalystCards(analytics) {
    const riskRows = Array.isArray(analytics.risk_distribution) ? analytics.risk_distribution : [];
    const actionRows = Array.isArray(analytics.recommended_action_distribution)
        ? analytics.recommended_action_distribution
        : [];
    const dangerousSummary = analytics.dangerous_indicator_summary || {};
    const highRisk = riskRows.find((row) => row.label === "High")?.count || 0;
    const manualReview = actionRows.find((row) => row.label === "Manual Review")?.count || 0;
    const cards = [
        ["Enriched IoCs", analytics.enriched_indicator_count || 0, "scored"],
        ["High Risk", highRisk, "enriched"],
        ["Manual Review", manualReview, "enriched"],
        [
            "Malicious Detections",
            dangerousSummary.malicious_indicator_count || 0,
            "enriched IoCs",
        ],
    ];
    return `
        <div class="kpi-grid ioc-summary-grid">
            ${cards.map(([label, value, hint]) => `
                <div class="kpi-card">
                    <span>${escapeHtml(String(label))}</span>
                    <strong>${escapeHtml(String(value))}</strong>
                    <small>${escapeHtml(String(hint))}</small>
                </div>
            `).join("")}
        </div>
    `;
}

function IocStreamAnalystCharts(analytics) {
    const riskRows = Array.isArray(analytics.risk_distribution) ? analytics.risk_distribution : [];
    const typeRows = Array.isArray(analytics.ioc_type_distribution) ? analytics.ioc_type_distribution : [];
    const actionRows = Array.isArray(analytics.recommended_action_distribution)
        ? analytics.recommended_action_distribution
        : [];
    const typeRiskRows = Array.isArray(analytics.highest_risk_by_ioc_type)
        ? analytics.highest_risk_by_ioc_type
            .filter((row) => row.average_risk_score !== null && row.average_risk_score !== undefined)
            .map((row) => ({
                label: row.ioc_type,
                value: Number(row.average_risk_score || 0),
            }))
        : [];
    return `
        <div class="stats-charts-grid ioc-chart-grid">
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Enriched Risk Distribution</h2>
                ${renderIocStreamBarChart(riskRows)}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Enriched IoC Type Distribution</h2>
                ${renderIocStreamDonutChart(typeRows, "Enriched IoC type distribution")}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Recommended Action Distribution</h2>
                ${renderIocStreamDonutChart(actionRows, "Recommended action distribution")}
            </section>
            <section class="stats-chart-panel report-section-card">
                <h2 class="stats-chart-title">Average GTI Score by Type</h2>
                ${renderIocStreamBarChart(typeRiskRows)}
            </section>
        </div>
    `;
}

function HighestRiskByTypeTable(rows) {
    const data = Array.isArray(rows) ? rows : [];
    if (!data.length) {
        return `<p><em>No successfully enriched IoCs are available for this analysis.</em></p>`;
    }
    return `
        <div class="table-scroll">
            <table class="ranking-table monitor-table">
                <thead>
                    <tr>
                        <th>IoC Type</th>
                        <th>Total</th>
                        <th>Avg GTI score</th>
                        <th>Malicious IoCs</th>
                        <th>Suspicious IoCs</th>
                        <th>Malicious %</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.map((row) => `
                        <tr class="ranking-row">
                            <td class="name-cell"><strong>${escapeHtml(String(row.ioc_type || "others"))}</strong></td>
                            <td class="count-cell">${escapeHtml(String(row.total_count ?? 0))}</td>
                            <td class="count-cell">${escapeHtml(row.average_risk_score === null || row.average_risk_score === undefined ? "n/a" : String(row.average_risk_score))}</td>
                            <td class="count-cell">${escapeHtml(String(row.malicious_indicator_count ?? 0))}</td>
                            <td class="count-cell">${escapeHtml(String(row.suspicious_indicator_count ?? 0))}</td>
                            <td class="count-cell">${escapeHtml(formatAnalyticsPercent(row.malicious_percentage))}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function DistributionTable(rows) {
    const data = Array.isArray(rows) ? rows : [];
    if (!data.length) {
        return `<p><em>No distribution data.</em></p>`;
    }
    return `
        <div class="table-scroll">
            <table class="ranking-table monitor-table compact-table">
                <thead>
                    <tr>
                        <th>Bucket</th>
                        <th>Count</th>
                        <th>Percent</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.map((row) => `
                        <tr class="ranking-row">
                            <td class="name-cell">${escapeHtml(String(row.label || "Unknown"))}</td>
                            <td class="count-cell">${escapeHtml(String(row.count ?? row.value ?? 0))}</td>
                            <td class="count-cell">${escapeHtml(formatAnalyticsPercent(row.percentage))}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function KeyValueTable(rows) {
    return `
        <div class="table-scroll">
            <table class="ranking-table compact-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows.map(([label, value]) => `
                        <tr class="ranking-row">
                            <td class="name-cell">${escapeHtml(String(label))}</td>
                            <td class="count-cell">${escapeHtml(value === null || value === undefined ? "n/a" : String(value))}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        </div>
    `;
}

function DangerousIndicatorSummary(summary) {
    const data = summary || {};
    return KeyValueTable([
        ["Enriched indicators analyzed", data.enriched_indicator_count ?? 0],
        ["High-risk indicators", data.high_risk_count ?? 0],
        ["Indicators with malicious detections", data.malicious_indicator_count ?? 0],
        ["Indicators with suspicious detections", data.suspicious_indicator_count ?? 0],
        ["Indicators with negative reputation", data.negative_reputation_count ?? 0],
        ["Highest malicious detections on one indicator", data.highest_malicious_detections ?? 0],
        ["Highest suspicious detections on one indicator", data.highest_suspicious_detections ?? 0],
        ["Lowest reputation observed", data.lowest_reputation ?? "n/a"],
        ["Dominant high-risk IoC type", data.dominant_high_risk_type || "Unknown"],
    ]);
}

function RiskMetricsSummary(metrics) {
    const data = metrics || {};
    return KeyValueTable([
        ["High-risk percentage", formatAnalyticsPercent(data.high_risk_percentage)],
        ["Medium-or-high risk percentage", formatAnalyticsPercent(data.medium_or_high_risk_percentage)],
        ["Average GTI score", data.average_gti_score ?? "n/a"],
        ["Maximum GTI score", data.max_gti_score ?? "n/a"],
        ["Indicators with vendor detections", data.indicators_with_vendor_detections ?? 0],
    ]);
}

function IocStreamAnalystAnalysis(analytics) {
    const analystData = analytics || {};
    const insights = Array.isArray(analystData.business_insights)
        ? analystData.business_insights
        : [];
    return `
        <section class="analyst-cross-analysis">
            <h2>Analyst Cross-Analysis</h2>
            <p class="compact-note">Computed only from successfully enriched indicators. Missing fields are left as n/a.</p>
            ${IocStreamAnalystCards(analystData)}
            ${IocStreamAnalystCharts(analystData)}
            <h3>Business Insights</h3>
            <ul>${insights.map((sentence) => `<li>${escapeHtml(String(sentence))}</li>`).join("")}</ul>
            <h3>Highest Risk by IoC Type</h3>
            ${HighestRiskByTypeTable(analystData.highest_risk_by_ioc_type)}
            <h3>Dangerous Indicator Aggregate Summary</h3>
            ${DangerousIndicatorSummary(analystData.dangerous_indicator_summary)}
            <h3>Risk Metrics</h3>
            ${RiskMetricsSummary(analystData.risk_metrics)}
            <div class="stats-charts-grid ioc-chart-grid">
                <section class="stats-chart-panel report-section-card">
                    <h3>Risk Distribution</h3>
                    ${DistributionTable(analystData.risk_distribution)}
                </section>
                <section class="stats-chart-panel report-section-card">
                    <h3>IoC Type Distribution</h3>
                    ${DistributionTable(analystData.ioc_type_distribution)}
                </section>
                <section class="stats-chart-panel report-section-card">
                    <h3>Recommended Action Distribution</h3>
                    ${DistributionTable(analystData.recommended_action_distribution)}
                </section>
            </div>
        </section>
    `;
}

function DefinitionsPanel(definitions) {
    const rows = Array.isArray(definitions) ? definitions : [];
    return `
        <details class="definitions-panel">
            <summary>Definitions</summary>
            <div class="definition-list">
                ${rows.map((item) => `
                    <div>
                        <strong>${escapeHtml(String(item.term || ""))}</strong>
                        <p>${escapeHtml(String(item.definition || ""))}</p>
                    </div>
                `).join("")}
            </div>
        </details>
    `;
}

function IocStreamReportPage(responseData) {
    const summary = responseData.summary || {};
    const businessSummary = Array.isArray(responseData.business_summary)
        ? responseData.business_summary
        : [];
    const noDataMessage = Number(summary.total_iocs || 0) === 0
        ? `<p class="diagnostic-warning compact">No IoC Stream notifications were returned for the selected filters.</p>`
        : "";
    const enrichment = responseData.technical_details?.enrichment || {};
    const enrichmentNote = enrichment.enabled
        ? `Enrichment enabled: ${Number(enrichment.succeeded || 0)} / ${Number(enrichment.attempted || 0)} indicator lookup(s) succeeded.`
        : "Enrichment disabled. Risk scoring requires enrichment.";

    return `
        <div class="report-document ioc-stream-document">
            <h1>Recent IoC Stream Sample Report</h1>
            <p class="compact-note">Generated from recent GTI IoC Stream notifications. This module is read-only. ${escapeHtml(enrichmentNote)}</p>
            <p class="diagnostic-warning compact">Risk scoring requires enrichment. This may generate one API lookup per IoC. Unknown indicators are not treated as safe.</p>
            ${noDataMessage}
            ${RecentExposureCollectionSummary(responseData)}
            ${SummaryCards(summary)}
            ${IocStreamEnrichmentStatus(responseData.technical_details || {})}
            ${IocStreamAnalystAnalysis(responseData.analytics || {})}
            ${IocStreamCharts(responseData.charts || {})}
            <section class="report-section-card">
                <h2>Business Interpretation</h2>
                <ul>${businessSummary.map((sentence) => `<li>${escapeHtml(String(sentence))}</li>`).join("")}</ul>
            </section>
            ${DefinitionsPanel(responseData.definitions)}
            <details class="inline-raw-json">
                <summary>Raw JSON</summary>
                <pre>${escapeHtml(JSON.stringify(responseData || {}, null, 2))}</pre>
            </details>
        </div>
    `;
}

function renderIocStreamReport(responseData) {
    const html = IocStreamReportPage(responseData);
    iocStreamOutput.classList.remove("empty-state");
    iocStreamOutput.innerHTML = html;
    reportOutput.classList.remove("empty-state");
    reportOutput.innerHTML = `
        <h1>Recent IoC Stream Sample Report</h1>
        ${RecentExposureCollectionSummary(responseData)}
        ${SummaryCards(responseData.summary || {})}
        <p>${escapeHtml(String(responseData.message || "Recent IoC Stream Sample report generated."))}</p>
        <button type="button" class="link-button" data-switch-tab="ioc-stream">Open Recent IoC Stream Sample tab</button>
    `;
}

async function exportIocStreamDocx() {
    if (!lastIocStreamResponse) {
        showMessage("Generate a Recent IoC Stream Sample report before exporting a Word report.", "error");
        return;
    }

    setIocStreamDocxState(true, true);
    updateStatus("Exporting", "running");
    clearMessage();

    try {
        const payload = { ioc_stream_report: { ...lastIocStreamResponse } };
        const response = await fetch("/export/ioc-stream-docx", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            let detail = "Word export failed.";
            try {
                const errorPayload = await response.json();
                detail = errorPayload.detail || detail;
            } catch (_) {
                // Keep the generic message when the backend returned a non-JSON error.
            }
            throw new Error(detail);
        }

        const reportBlob = await response.blob();
        const contentDisposition = response.headers.get("content-disposition") || "";
        const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
        const filename = filenameMatch?.[1] || "gti-ioc-stream-report.docx";
        const downloadUrl = URL.createObjectURL(reportBlob);
        const downloadLink = document.createElement("a");
        downloadLink.href = downloadUrl;
        downloadLink.download = filename;
        document.body.append(downloadLink);
        downloadLink.click();
        downloadLink.remove();
        URL.revokeObjectURL(downloadUrl);

        updateStatus("Success", "success");
        showMessage("Word report exported.", "success");
    } catch (error) {
        updateStatus("Error", "error");
        showMessage(error.message || "Word export failed.", "error");
    } finally {
        setIocStreamDocxState(Boolean(lastIocStreamResponse), false);
    }
}

async function exportDtmDashboardDocx() {
    if (!lastDtmDashboardResponse) {
        showMessage("Run the DTM Dashboard before exporting a Word report.", "error");
        return;
    }

    setDtmDashboardDocxState(true, true);
    updateStatus("Exporting", "running");
    clearMessage();

    try {
        const maxItemsInput = document.getElementById("dtm_dashboard_chart_max_items");
        const maxChartItems = maxItemsInput ? Math.max(1, parseInt(maxItemsInput.value, 10) || 10) : 10;
        const payload = { dashboard_result: { ...lastDtmDashboardResponse }, max_chart_items: maxChartItems };
        const response = await fetch("/export/dtm-dashboard-docx", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            let detail = "Word export failed.";
            try {
                const errorPayload = await response.json();
                detail = errorPayload.detail || detail;
            } catch (_) {
                // Keep the generic message when the backend returned a non-JSON error.
            }
            throw new Error(detail);
        }

        const reportBlob = await response.blob();
        const contentDisposition = response.headers.get("content-disposition") || "";
        const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
        const filename = filenameMatch?.[1] || "gti-dtm-dashboard.docx";
        const downloadUrl = URL.createObjectURL(reportBlob);
        const downloadLink = document.createElement("a");
        downloadLink.href = downloadUrl;
        downloadLink.download = filename;
        document.body.append(downloadLink);
        downloadLink.click();
        downloadLink.remove();
        URL.revokeObjectURL(downloadUrl);

        updateStatus("Success", "success");
        showMessage("DTM Dashboard Word report exported.", "success");
    } catch (error) {
        updateStatus("Error", "error");
        showMessage(error.message || "Word export failed.", "error");
    } finally {
        setDtmDashboardDocxState(Boolean(lastDtmDashboardResponse), false);
    }
}

async function runIocStreamReport() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();
    setIocStreamLoadingState(true);
    setIocStreamDocxState(false);
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        const apiKey = apiKeyField.value.trim();
        const response = await fetch(`/api/ioc-stream/report?${buildIocStreamParams()}`, {
            headers: { "x-api-key": apiKey },
        });
        const responseData = await response.json().catch(() => ({}));
        if (!response.ok) {
            const detail = Array.isArray(responseData.detail)
                ? responseData.detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
                : responseData.detail;
            throw new Error(detail ? `API error: ${detail}` : "API error: The backend returned an error.");
        }

        lastIocStreamResponse = responseData;
        renderIocStreamReport(responseData);
        setIocStreamDocxState(true);
        switchToTab("ioc-stream");
        rawJsonOutput.textContent = JSON.stringify(responseData, null, 2);

        updateStatus("Success", "success");
        showMessage(
            responseData.message || `Recent IoC Stream Sample report generated with ${formatInteger(responseData.summary?.total_iocs)} indicator(s).`,
            "success",
        );
    } catch (error) {
        lastIocStreamResponse = null;
        iocStreamOutput.classList.add("empty-state");
        iocStreamOutput.innerHTML = `
            <h3>Recent IoC Stream Sample report failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = iocStreamOutput.innerHTML;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "Recent IoC Stream Sample report failed.", "error");
    } finally {
        setIocStreamLoadingState(false);

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

async function runDtmDashboard() {
    clearMessage();
    setDtmDashboardLoadingState(true);
    setDownloadState(false);
    lastGeneratedReport = "";

    const params = new URLSearchParams();
    const since = localDateTimeToRfc3339(dtmDashboardSinceField?.value || "");
    const until = localDateTimeToRfc3339(dtmDashboardUntilField?.value || "");
    const maxPages = Number(dtmDashboardMaxPagesField?.value || 20);
    const includeRaw = Boolean(dtmDashboardIncludeRawField?.checked);
    const apiKey = apiKeyField.value.trim();
    if (since) params.set("since", since);
    if (until) params.set("until", until);
    if (apiKey) params.set("api_key", apiKey);
    params.set("max_pages", String(maxPages));
    params.set("include_raw", includeRaw ? "true" : "false");

    try {
        const response = await fetch(`/dtm/dashboard?${params}`);
        const responseData = await response.json();
        if (!response.ok) {
            throw new Error(responseData.detail || "The backend returned an error.");
        }

        lastDtmDashboardResponse = responseData;
        renderDtmDashboard(responseData);
        setDtmDashboardDocxState(true);
        switchToTab("dtm-dashboard");
        rawJsonOutput.textContent = includeRaw
            ? JSON.stringify(responseData, null, 2)
            : "Raw JSON is hidden. Enable 'Show raw JSON in UI' in the DTM Dashboard filters to display it here.";

        updateStatus("Success", "success");
        showMessage(
            `DTM dashboard loaded: ${formatInteger(responseData.summary?.total_monitors)} monitor(s), ${formatInteger(responseData.summary?.total_alerts)} alert(s).`,
            "success",
        );
    } catch (error) {
        dtmDashboardOutput.classList.add("empty-state");
        dtmDashboardOutput.innerHTML = `
            <h3>DTM dashboard failed</h3>
            <p>${escapeHtml(error.message || "Unknown error.")}</p>
        `;
        reportOutput.classList.add("empty-state");
        reportOutput.innerHTML = dtmDashboardOutput.innerHTML;
        rawJsonOutput.textContent = "No valid JSON payload was returned.";
        updateStatus("Error", "error");
        showMessage(error.message || "DTM dashboard failed.", "error");
    } finally {
        setDtmDashboardLoadingState(false);

        if (!statusPill.classList.contains("success") && !statusPill.classList.contains("error")) {
            updateStatus("Idle", "idle");
        }
    }
}

async function runTopTargetsRanking() {
    if (!reportForm.reportValidity()) {
        return;
    }

    clearMessage();

    const startYear = Number(topTargetsStartYearField.value || 2024);
    const monthRaw = topTargetsMonthField?.value || "";
    const month = monthRaw ? Number(monthRaw) : null;
    const topN = Number(topTargetsTopNField.value || 10);
    const maxCollectionsRaw = topTargetsMaxCollectionsField.value.trim();
    const maxCollections = maxCollectionsRaw ? Number(maxCollectionsRaw) : TOP_TARGETS_DEFAULT_MAX_COLLECTIONS;
    const selectedRankings = getSelectedTopTargetRankings();
    if (selectedRankings.length === 0) {
        updateStatus("Error", "error");
        showMessage("Select at least one ranking to compute.", "error");
        return;
    }
    const deepOrganizationLookup = topTargetsDeepLookupField.checked;
    const maxDetailLookupsRaw = topTargetsMaxDetailLookupsField.value.trim();
    const maxDetailLookups = deepOrganizationLookup
        ? (maxDetailLookupsRaw ? Number(maxDetailLookupsRaw) : TOP_TARGETS_DEFAULT_DEEP_LOOKUPS)
        : 0;
    const ttpSource = topTargetsTtpSourceField?.value || "search_reports";
    const maxTtpCandidatesRaw = topTargetsMaxTtpCandidatesField?.value.trim() || "";
    const maxTtpCandidates = maxTtpCandidatesRaw
        ? Number(maxTtpCandidatesRaw)
        : TOP_TARGETS_DEFAULT_TTP_CANDIDATES;
    const ttpQueryFilter = topTargetsTtpQueryFilterField?.value.trim() || null;
    const includeTtpAnalysis = Boolean(topTargetsIncludeTtpField?.checked);
    const includeDebug = Boolean(topTargetsIncludeDebugField?.checked);
    const showRawJson = Boolean(topTargetsShowRawJsonField?.checked);
    const estimate = buildTopTargetsRequestEstimate(
        maxCollections,
        deepOrganizationLookup,
        maxDetailLookups,
        maxTtpCandidates,
        ttpSource,
        includeTtpAnalysis,
    );

    const shouldRun = window.confirm(
        `Estimated API requests before running:\n` +
        `${estimate.searchRequests} Intelligence Search request(s)\n` +
        `${estimate.detailLookups} collection detail lookup(s)\n` +
        `${estimate.ttpCandidates} TTP MITRE tree lookup(s)\n` +
        `${estimate.totalRequests} total request(s)\n\n` +
        `Period: ${getTopTargetsPeriodLabel()}\n` +
        `Max collections: ${estimate.maxCollections}\n` +
        `MITRE ATT&CK: ${includeTtpAnalysis ? "enabled" : "disabled"}\n` +
        `TTP mode: ${includeTtpAnalysis ? (ttpSource === "ranking_collections" ? "Use ranking result collections" : "Search reports for TTP analysis") : "disabled"}`,
    );
    if (!shouldRun) {
        updateStatus("Idle", "idle");
        return;
    }

    setTopTargetsLoadingState(true);
    lastTopTargetsResponse = null;
    setTopTargetsDocxState(false);
    setDownloadState(false);
    lastGeneratedReport = "";

    try {
        const response = await fetch("/explore/top-targets", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                api_key: apiKeyField.value.trim(),
                start_year: startYear,
                month,
                top_n: topN,
                max_collections: maxCollections,
                selected_rankings: selectedRankings,
                deep_organization_lookup: deepOrganizationLookup,
                max_detail_lookups: maxDetailLookups,
                ttp_source: ttpSource,
                max_ttp_candidates: maxTtpCandidates,
                ttp_query_filter: ttpQueryFilter,
                include_ttp_analysis: includeTtpAnalysis,
                include_debug: includeDebug,
            }),
        });

        const responseData = await response.json();
        if (!response.ok) {
            throw new Error(responseData.detail || "The backend returned an error.");
        }

        const normalizedResponseData = normalizeTopTargetsResponse(
            responseData,
            selectedRankings,
        );
        lastTopTargetsResponse = normalizedResponseData;

        renderTopTargetsResult(normalizedResponseData);
        renderCrossAnalysisTab(normalizedResponseData);
        renderDiagnosticsTab(normalizedResponseData, includeDebug);
        setTopTargetsDocxState(true);
        switchToTab("report");
        rawJsonOutput.textContent = showRawJson
            ? JSON.stringify(normalizedResponseData, null, 2)
            : "Raw JSON is hidden. Enable 'Show raw JSON in UI' in the sidebar to display it here.";

        const rankingCount = normalizedResponseData.selected_rankings.length;
        updateStatus("Success", "success");
        showMessage(
            `Ranking complete: ${rankingCount} ranking section(s) computed from ${normalizedResponseData.collections_analyzed} distinct GTI collections (${normalizedResponseData.period}).`,
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

    if (reportTypeField.value === DTM_DASHBOARD) {
        await runDtmDashboard();
        return;
    }

    if (reportTypeField.value === IOC_STREAM_REPORT) {
        await runIocStreamReport();
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
    const tabSwitch = event.target.closest("[data-switch-tab]");
    if (tabSwitch) {
        event.preventDefault();
        switchToTab(tabSwitch.dataset.switchTab || "report");
    }
}

async function copyRawJsonToClipboard() {
    const text = rawJsonOutput.textContent || "";
    if (!text || text === "No response yet.") {
        return;
    }
    try {
        await navigator.clipboard.writeText(text);
        showMessage("Raw JSON copied.", "success");
    } catch (_) {
        showMessage("Could not copy Raw JSON from this browser context.", "error");
    }
}

reportTypeField.addEventListener("change", syncTargetRequirement);
downloadButton.addEventListener("click", downloadCurrentReport);
dtmDashboardButton?.addEventListener("click", runDtmDashboard);
iocStreamButton?.addEventListener("click", runIocStreamReport);
iocStreamDocxButton?.addEventListener("click", exportIocStreamDocx);
dtmDashboardDocxButton?.addEventListener("click", exportDtmDashboardDocx);
iocStreamCollectionModeField?.addEventListener("change", syncIocStreamCollectionControls);
iocStreamPagesToFetchField?.addEventListener("change", syncIocStreamCollectionControls);
iocStreamTimeWindowField?.addEventListener("change", syncIocStreamCollectionControls);
topTargetsButton?.addEventListener("click", runTopTargetsRanking);
topTargetsDocxButton?.addEventListener("click", exportTopRankingDocx);
topTargetsDeepLookupField?.addEventListener("change", syncTopTargetsDeepLookupControls);
[
    topTargetsStartYearField,
    topTargetsMonthField,
    topTargetsTopNField,
    topTargetsMaxCollectionsField,
    topTargetsMaxDetailLookupsField,
    topTargetsIncludeTtpField,
    topTargetsTtpSourceField,
    topTargetsMaxTtpCandidatesField,
    topTargetsTtpQueryFilterField,
    topTargetsIncludeDebugField,
    topTargetsShowRawJsonField,
].filter(Boolean).forEach((field) => {
    field.addEventListener("input", updateTopTargetsEstimatePanel);
    field.addEventListener("change", updateTopTargetsEstimatePanel);
});
reportOutput.addEventListener("click", handleReportOutputClick);
dtmDashboardOutput?.addEventListener("click", (event) => {
    const sortButton = event.target.closest("[data-dtm-sort]");
    if (!sortButton || !lastDtmDashboardResponse) {
        handleReportOutputClick(event);
        return;
    }
    const nextSortKey = sortButton.dataset.dtmSort || "risk_score";
    if (dtmMonitorSortKey === nextSortKey) {
        dtmMonitorSortDirection = dtmMonitorSortDirection === "asc" ? "desc" : "asc";
    } else {
        dtmMonitorSortKey = nextSortKey;
        dtmMonitorSortDirection = "desc";
    }
    renderDtmDashboard(lastDtmDashboardResponse);
});
crossAnalysisOutput?.addEventListener("click", handleReportOutputClick);
diagnosticsOutput?.addEventListener("click", handleReportOutputClick);
iocStreamOutput?.addEventListener("click", handleReportOutputClick);
copyJsonButton?.addEventListener("click", copyRawJsonToClipboard);
reportForm.addEventListener("submit", generateReport);
setDownloadState(false);
syncTopTargetsDeepLookupControls();
updateTopTargetsEstimatePanel();
syncIocStreamCollectionControls();
syncTargetRequirement();
reportForm.dataset.initialized = "true"; // enable field animations after initial render

// ── Tab switching ──────────────────────────────────────────────────────────

const tabBtns = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");

function switchToTab(tabId) {
    tabBtns.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tabId));
    tabPanels.forEach((panel) => { panel.hidden = panel.id !== `tab-${tabId}`; });
}

tabBtns.forEach((btn) => btn.addEventListener("click", () => switchToTab(btn.dataset.tab)));

