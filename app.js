// Small frontend controller for the GTI report generator MVP.
// The goal is clarity over cleverness so the flow is easy to follow.

const reportForm = document.getElementById("report-form");
const apiKeyField = document.getElementById("api_key");
const apiKeyBlock = apiKeyField?.closest(".form-block");
const generateButton = document.getElementById("generate-button");
const reportOutput = document.getElementById("report-output");
const dtmDashboardOutput = document.getElementById("dtm-dashboard-output");
const rawJsonOutput = document.getElementById("raw-json-output");
const crossAnalysisOutput = document.getElementById("cross-analysis-output");
const diagnosticsOutput = document.getElementById("diagnostics-output");
const copyJsonButton = document.getElementById("copy-json-button");
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
const dtmDashboardFields = document.getElementById("dtm-dashboard-fields");
const dtmDashboardActions = document.getElementById("dtm-dashboard-actions");
const dtmDashboardButton = document.getElementById("dtm-dashboard-button");
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
const DTM_DASHBOARD = "DTM Monitor & Alert Dashboard";
const GTI_INTELLIGENCE_SEARCH = "GTI Intelligence Search";
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
    [DTM_DASHBOARD]: {
        label: "DTM Monitor & Alert Dashboard",
        description: "Builds a read-only dashboard from existing DTM monitors and alerts using the backend GTI environment key.",
        emptyTitle: "Ready to load the DTM dashboard",
        emptyText: "Choose a date range and page limit, then click Run Dashboard.",
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
let lastTopTargetsResponse = null;
let lastDtmDashboardResponse = null;
let activeCollectionAnalysisId = "";
let collectionAnalysisInProgressId = "";
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
    const isExplorerMode = (
        reportTypeField.value === INDUSTRY_SNAPSHOT_EXPLORER
    );
    const isCompanyExposureDtm = reportTypeField.value === COMPANY_EXPOSURE_DTM;
    const isIocEnrichment = reportTypeField.value === IOC_ENRICHMENT;
    const isIntelligenceSearch = reportTypeField.value === GTI_INTELLIGENCE_SEARCH;
    const isTopTargets = reportTypeField.value === TOP_TARGETS_RANKING;
    const isDtmDashboard = reportTypeField.value === DTM_DASHBOARD;
    const isSpecialMode = isExplorerMode || isCompanyExposureDtm || isIntelligenceSearch || isTopTargets || isDtmDashboard;

    if (apiKeyBlock) {
        apiKeyBlock.hidden = isDtmDashboard;
    }
    apiKeyField.required = !isDtmDashboard;
    apiKeyField.disabled = isDtmDashboard;
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
    dtmDashboardFields.hidden = !isDtmDashboard;
    dtmDashboardActions.hidden = !isDtmDashboard;

    targetField.required = (
        isIocEnrichment
        && !isExplorerMode
        && !isCompanyExposureDtm
        && !isIntelligenceSearch
        && !isTopTargets
        && !isDtmDashboard
    );
    intelligenceQueryField.required = isIntelligenceSearch;
    targetField.placeholder = isIocEnrichment ? "example.com" : "Company, region, or industry";
    targetLabel.textContent = isIocEnrichment ? "Target Domain" : "Target (Optional)";
    explorerButton.textContent = getExplorerButtonLabel();

    if (isSpecialMode) {
        lastGeneratedReport = "";
        setDownloadState(false);
    }
    setTopTargetsDocxState(isTopTargets && Boolean(lastTopTargetsResponse));

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

function renderRankingTable(
    items,
    countLabel,
    emptyMessage = "Field not present in GTI Intelligence Search preview for this sample",
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
        const countLabel = rankingKey === "timeline" ? "collections" : "collections";
        const emptyHtml = rankingKey === "targeted_organizations"
            ? "<p><em>Not enough organization data in preview fields.</em></p>"
            : renderRankingTable(items, countLabel);
        const tableHtml = rankingKey === "targeted_organizations" && responseData.top_companies_status === "not enough data"
            ? emptyHtml
            : renderRankingTable(items, countLabel);

        return renderSectionCard(label, tableHtml);
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
                renderRankingTable(responseData.top_subtechniques || [], "collections"),
            )
            : "";
    return `
        ${renderSectionCard("Top MITRE Tactics", renderRankingTable(responseData.top_tactics || [], "collections", "No MITRE tactics were extracted."))}
        ${renderSectionCard("Top MITRE Techniques", renderRankingTable(responseData.top_techniques || [], "collections", "No MITRE techniques were extracted."))}
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

function renderLiveRankingsFromTopTargets(responseData) {
    const rankings = responseData.rankings || {};
    const selectedRankings = Array.isArray(responseData.selected_rankings)
        ? responseData.selected_rankings
        : Object.keys(rankings);

    industriesChartEl.innerHTML = selectedRankings.includes("targeted_industries")
        ? renderRankingTable(rankings.targeted_industries || [], "collections")
        : "<p><em>No industries ranking is available for this run.</em></p>";

    companiesChartEl.innerHTML = !selectedRankings.includes("targeted_organizations")
        ? "<p><em>No organizations ranking is available for this run.</em></p>"
        : responseData.top_companies_status === "not enough data"
            ? "<p><em>Not enough organization data in preview fields.</em></p>"
            : renderRankingTable(rankings.targeted_organizations || [], "collections");
    companiesSourceBadgeEl.innerHTML = '<span class="badge source-badge">preview-only</span>';
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
            <div class="stats-charts-grid">
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Top Monitors by Alert Count</h2>
                    ${renderDtmBarTable(charts.top_monitors_by_alert_count, {
                        labelKey: "monitor_name",
                        valueKey: "alert_count",
                        valueTitle: "Alerts",
                        emptyMessage: "No alerts returned for this period.",
                    })}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Top Monitors by Risk Score</h2>
                    ${renderDtmBarTable(charts.top_monitors_by_risk_score, {
                        labelKey: "monitor_name",
                        valueKey: "risk_score",
                        valueTitle: "Risk",
                        emptyMessage: "No risk score was computed for this period.",
                    })}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Severity</h2>
                    ${renderDtmCountTable(charts.alerts_by_severity, "severity", "Severity")}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Type</h2>
                    ${renderDtmCountTable(charts.alerts_by_type, "type", "Type")}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts by Status</h2>
                    ${renderDtmCountTable(charts.alerts_by_status, "status", "Status")}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Alerts Timeline</h2>
                    ${renderDtmBarTable(charts.alerts_timeline, {
                        labelKey: "date",
                        valueKey: "count",
                        labelTitle: "Date",
                        valueTitle: "Alerts",
                        emptyMessage: "No dated alerts were returned.",
                    })}
                </section>
                <section class="stats-chart-panel">
                    <h2 class="stats-chart-title">Noisy Monitors</h2>
                    ${renderDtmBarTable(charts.noisy_monitors, {
                        labelKey: "monitor_name",
                        valueKey: "noise_score",
                        valueTitle: "Noise",
                        emptyMessage: "No noisy monitor pattern was detected.",
                    })}
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
    if (since) params.set("since", since);
    if (until) params.set("until", until);
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
        renderLiveRankingsFromTopTargets(normalizedResponseData);
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

    if (reportTypeField.value === DTM_DASHBOARD) {
        await runDtmDashboard();
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
    const tabSwitch = event.target.closest("[data-switch-tab]");
    if (tabSwitch) {
        event.preventDefault();
        switchToTab(tabSwitch.dataset.switchTab || "report");
        return;
    }

    const analyzeButton = event.target.closest("[data-analyze-collection-id]");
    if (!analyzeButton) {
        return;
    }

    event.preventDefault();
    analyzeSelectedCollection(analyzeButton.dataset.analyzeCollectionId || "");
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
explorerButton.addEventListener("click", runSelectedExplorer);
dtmMonitorsButton.addEventListener("click", testDtmMonitors);
dtmAlertsButton.addEventListener("click", testDtmAlerts);
dtmDashboardButton?.addEventListener("click", runDtmDashboard);
intelligenceSearchButton.addEventListener("click", searchGtiIntelligence);
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
intelligencePresetButtons.forEach((button) => {
    button.addEventListener("click", applyIntelligenceQueryPreset);
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
copyJsonButton?.addEventListener("click", copyRawJsonToClipboard);
reportForm.addEventListener("submit", generateReport);
setDownloadState(false);
syncTopTargetsDeepLookupControls();
updateTopTargetsEstimatePanel();
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
    const year = Number(statsYearField?.value || 2024);
    const target = statsTargetField?.value.trim() || "";
    fetchIndustries(year, target);
    fetchCompanies(year, target);
}

function onStatsInputChange() {
    clearTimeout(statsDebounceTimer);
    statsDebounceTimer = setTimeout(refreshStats, 400);
}

statsYearField?.addEventListener("change", onStatsInputChange);
statsTargetField?.addEventListener("input", onStatsInputChange);
apiKeyField?.addEventListener("change", refreshStats);
refreshStats();

// ── Tab switching ──────────────────────────────────────────────────────────

const tabBtns = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");

function switchToTab(tabId) {
    tabBtns.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tabId));
    tabPanels.forEach((panel) => { panel.hidden = panel.id !== `tab-${tabId}`; });
}

tabBtns.forEach((btn) => btn.addEventListener("click", () => switchToTab(btn.dataset.tab)));

