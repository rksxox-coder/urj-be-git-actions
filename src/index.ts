import { chromium, Browser, errors } from 'playwright-chromium';
import validator from 'validator';
import { URL } from 'url';
import dns from 'dns/promises';
import ipRangeCheck from 'ip-range-check';
import { writeFile } from 'fs/promises';

// --- Type Definitions (No changes) ---
interface Hop {
    url: string; status: number; server: string; timestamp: number;
}
interface AnalysisResult {
    originalURL: string; finalURL: string | null; sourceServer: string | null; targetServer: string | null;
    finalStatus: number | null; redirectChain: Hop[]; totalTime: number; error?: string;
}

// --- Server Identification & Icon Mapping (No changes) ---
const AKAMAI_IP_RANGES = ["23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"];
const ipCache = new Map<string, string>();
const ServerType = { AKAMAI: 'Akamai', AEM: 'Apache (AEM)', UNKNOWN: 'Unknown' };
const serverIconMap: Record<string, string> = {
    [ServerType.AKAMAI]: '<i data-feather="cloud" style="color: #007BFF;" title="Akamai"></i>',
    [ServerType.AEM]: '<i data-feather="feather" style="color: #c22121;" title="Apache (AEM)"></i>',
    [ServerType.UNKNOWN]: '<i data-feather="server" style="color: #6c757d;" title="Unknown Server"></i>'
};

// --- Helper Functions (No changes) ---
async function resolveIp(url: string): Promise<string | null> {
    try {
        const hostname = new URL(url).hostname;
        if (!hostname) return null;
        if (ipCache.has(hostname)) return ipCache.get(hostname)!;
        const { address } = await dns.lookup(hostname);
        ipCache.set(hostname, address);
        return address;
    } catch { return null; }
}
function isAkamaiIp(ip: string | null): boolean {
    if (!ip) return false;
    return AKAMAI_IP_RANGES.some(cidr => ipRangeCheck(ip, cidr));
}
async function getServerName(headers: Record<string, string>, url: string): Promise<string> {
    const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    const hostname = new URL(url).hostname;
    if (hostname && (hostname.toLowerCase().includes("bmw") || hostname.toLowerCase().includes("mini"))) {
        if ("cache-control" in lowerHeaders) return ServerType.AEM;
    }
    const serverValue = lowerHeaders["server"]?.toLowerCase() || "";
    if (serverValue) {
        if (serverValue.includes("akamai") || serverValue.includes("ghost")) return ServerType.AKAMAI;
        if (serverValue.includes("apache")) return ServerType.AEM;
    }
    const serverTiming = lowerHeaders["server-timing"] || "";
    const hasAkamaiCache = serverTiming.includes("cdn-cache; desc=HIT") || serverTiming.includes("cdn-cache; desc=MISS");
    const hasAkamaiRequestId = "x-akamai-request-id" in lowerHeaders;
    const ip = await resolveIp(url);
    const isAkamai = isAkamaiIp(ip);
    const hasDispatcher = "x-dispatcher" in lowerHeaders || "x-aem-instance" in lowerHeaders;
    const hasAemPaths = Object.entries(lowerHeaders).some(([key, value]) => 
        (key === "link" || key === "baqend-tags") && value.includes("/etc.clientlibs")
    );
    if (hasAkamaiCache || hasAkamaiRequestId || (serverTiming && isAkamai)) {
        if (hasAemPaths || hasDispatcher) return ServerType.AEM;
        return ServerType.AKAMAI;
    }
    if (hasDispatcher || hasAemPaths) return ServerType.AEM;
    if (isAkamai) return ServerType.AKAMAI;
    return ServerType.UNKNOWN;
}

// --- Core Analysis Logic (No changes) ---
async function fetchUrlWithPlaywright(browser: Browser, url: string): Promise<AnalysisResult> {
    let context;
    const startTime = Date.now();
    const redirectChain: Hop[] = [];
    try {
        context = await browser.newContext({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" });
        const page = await context.newPage();
        page.on("response", async (response) => {
            if (response.request().isNavigationRequest()) {
                const headers = await response.allHeaders();
                redirectChain.push({
                    url: response.url(), status: response.status(),
                    server: await getServerName(headers, response.url()), timestamp: (Date.now() - startTime) / 1000
                });
            }
        });
        await page.goto(url, { timeout: 30000, waitUntil: "domcontentloaded" });
        const finalHop = redirectChain[redirectChain.length - 1];
        return {
            originalURL: url, finalURL: page.url(), sourceServer: redirectChain[0]?.server || null,
            targetServer: finalHop?.server || null, finalStatus: finalHop?.status || null,
            redirectChain: redirectChain, totalTime: (Date.now() - startTime) / 1000,
        };
    } catch (e) {
        let errorMessage = "A critical server error occurred.";
        if (e instanceof errors.TimeoutError) errorMessage = "Navigation timed out after 30s.";
        else if (e instanceof Error && e.message.includes("net::ERR_TOO_MANY_REDIRECTS")) errorMessage = "Too many redirects.";
        else if (e instanceof Error) errorMessage = e.message;
        const finalHop = redirectChain.length > 0 ? redirectChain[redirectChain.length - 1] : null;
        return {
            originalURL: url, finalURL: finalHop?.url || "N/A", sourceServer: redirectChain[0]?.server || null,
            targetServer: finalHop?.server || null, finalStatus: finalHop?.status || null,
            redirectChain: redirectChain, totalTime: (Date.now() - startTime) / 1000, error: errorMessage,
        };
    } finally {
        if (context) await context.close();
    }
}

// --- HTML Report Generation (UI ENHANCEMENTS) ---
function generateHtmlReport(results: AnalysisResult[]): string {
    let tableRows = '';
    results.forEach((result, index) => {
        const sourceIcon = serverIconMap[result.sourceServer || ServerType.UNKNOWN];
        const targetIcon = result.error ? '<i data-feather="alert-triangle" style="color: #dc3545;" title="Error"></i>' : serverIconMap[result.targetServer || ServerType.UNKNOWN];
        const finalStatusBadge = result.error ? `<span class="status-badge error">${result.finalStatus || 'ERR'}</span>` : `<span class="status-badge success">${result.finalStatus || 'OK'}</span>`;
        const chainTooltip = result.redirectChain.map((h, i) => `Hop ${i + 1} (${h.server}): ${h.status}`).join('\n');
        const chainBadges = result.redirectChain.map(h => {
            const statusClass = h.status >= 400 ? 'error' : (h.status >= 300 ? 'redirect' : 'success');
            return `<span class="status-badge small ${statusClass}">${h.status}</span>`;
        }).join('');
        tableRows += `
            <tr>
                <td><div class="url-cell">${sourceIcon} <a href="${result.originalURL}" target="_blank">${result.originalURL}</a></div></td>
                <td><div class="url-cell">${targetIcon} <a href="${result.finalURL}" target="_blank">${result.finalURL}</a></div></td>
                <td>${finalStatusBadge}</td>
                <td class="chain-cell" title="${chainTooltip}">${chainBadges || 'N/A'}</td>
                <td><button class="details-btn" data-index="${index}"><i data-feather="eye"></i></button></td>
            </tr>`;
    });

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>URL Journey Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <link rel="stylesheet" href="https://cdn.datatables.net/2.0.8/css/dataTables.dataTables.css" />
    <script src="https://cdn.datatables.net/2.0.8/js/dataTables.js"></script>
    <style>
        :root { /* Theme Variables */
            --bg-color: #f4f6f9; --card-bg: #fff; --text-color: #333; --border-color: #dee2e6;
            --header-bg: #f8f9fa; --shadow-color: rgba(0,0,0,0.1); --link-color: #007bff;
        }
        body.dark-mode {
            --bg-color: #121212; --card-bg: #1e1e1e; --text-color: #e0e0e0; --border-color: #444;
            --header-bg: #333; --shadow-color: rgba(0,0,0,0.5); --link-color: #4dabf7;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.3s, color 0.3s; }
        .container { max-width: 1600px; margin: auto; background: var(--card-bg); padding: 25px; border-radius: 8px; box-shadow: 0 4px 12px var(--shadow-color); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header-controls { display: flex; align-items: center; gap: 20px; }
        .header-icons { display: flex; align-items: center; gap: 15px; }
        #export-btn { background-color: #28a745; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; display: flex; align-items: center; gap: 8px; }
        table { width: 100% !important; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        .url-cell { display: flex; align-items: center; } /* FIX: Proper icon alignment */
        .url-cell i.feather { margin-right: 10px; flex-shrink: 0; }
        td a { color: var(--link-color); text-decoration: none; font-size: 0.9em; word-break: break-all; }
        
        /* ENHANCEMENT: Theme toggle button styling and animation */
        #theme-toggle { position: relative; width: 24px; height: 24px; cursor: pointer; background: none; border: none; color: var(--text-color); }
        #theme-toggle .feather { position: absolute; top: 0; left: 0; transition: transform 0.5s ease-out, opacity 0.4s ease; }
        #theme-toggle .feather-sun { opacity: 0; transform: translateY(20px) rotate(90deg); }
        body.dark-mode #theme-toggle .feather-moon { opacity: 0; transform: translateY(-20px) rotate(-90deg); }
        body.dark-mode #theme-toggle .feather-sun { opacity: 1; transform: translateY(0) rotate(0); }

        /* FIX: Restored status badge styling */
        .status-badge { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; font-size: 13px; margin: 2px; }
        .status-badge.success { background-color: #28a745; }
        .status-badge.redirect { background-color: #ffc107; color: #333; }
        .status-badge.error { background-color: #dc3545; }
        .status-badge.small { padding: 3px 8px; font-size: 11px; margin-right: 4px; }
        
        .dataTables_wrapper .dataTables_length select, .dataTables_wrapper .dataTables_filter input { background-color: var(--card-bg); color: var(--text-color); border: 1px solid var(--border-color); }
        .swal2-popup { background-color: var(--card-bg) !important; color: var(--text-color) !important; }
        .swal2-title { color: var(--text-color) !important; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>URL Journey Analysis Report</h1>
            <div class="header-controls">
                <button id="export-btn"><i data-feather="file-text"></i> Export</button>
                <div class="header-icons">
                    <button id="theme-toggle" title="Toggle dark mode">
                        <i data-feather="moon"></i><i data-feather="sun"></i>
                    </button>
                    <a href="https://github.com/BindRakesh/" target="_blank" title="My GitHub"><i data-feather="github"></i></a>
                </div>
            </div>
        </div>
        <table id="analysisTable">
            <thead><tr><th>Source URL</th><th>Target URL</th><th>Status</th><th>Redirect Chain</th><th>Actions</th></tr></thead>
            <tbody>${tableRows}</tbody>
        </table>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const resultsData = ${JSON.stringify(results)};
            
            new DataTable('#analysisTable', {
                layout: { topStart: 'pageLength', topEnd: 'search', bottomStart: 'info', bottomEnd: 'paging' },
                "drawCallback": () => feather.replace()
            });

            const themeToggle = document.getElementById('theme-toggle');
            const body = document.body;
            if (localStorage.getItem('theme') === 'dark') body.classList.add('dark-mode');
            themeToggle.addEventListener('click', () => {
                body.classList.toggle('dark-mode');
                localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
            });

            document.querySelector('#analysisTable tbody').addEventListener('click', (event) => {
                const button = event.target.closest('.details-btn');
                if (button) {
                    const index = button.getAttribute('data-index');
                    const result = resultsData[index];
                    let modalContent = \`
                        <p style="text-align:left;word-break:break-all;"><strong>Original:</strong> \${result.originalURL}<br><strong>Final:</strong> \${result.finalURL}</p>
                        <table class="modal-table">
                           <thead><tr><th>#</th><th>URL</th><th>Status</th><th>Server</th></tr></thead>
                           <tbody>\${result.redirectChain.map((hop, i) => \`<tr><td>\${i+1}</td><td>\${hop.url}</td><td>\${hop.status}</td><td>\${hop.server}</td></tr>\`).join('')}</tbody>
                        </table>\`;
                    Swal.fire({ title: 'Redirect Details', html: modalContent, width: '800px' });
                }
            });
            
            // FIX: Restored the complete and correct Excel export logic
            document.getElementById('export-btn').addEventListener('click', () => {
                const summaryData = resultsData.map(r => ({
                    'Source URL': r.originalURL, 'Source Server': r.sourceServer, 'Target URL': r.finalURL,
                    'Target Server': r.targetServer, 'Final Status': r.finalStatus, 'Redirects': r.redirectChain.length - 1,
                    'Total Time (s)': r.totalTime.toFixed(2), 'Error': r.error || 'None'
                }));
                const summarySheet = XLSX.utils.json_to_sheet(summaryData);
                const wb = XLSX.utils.book_new();
                XLSX.utils.book_append_sheet(wb, summarySheet, 'Summary');

                resultsData.forEach((r, i) => {
                    if (r.redirectChain.length > 0) {
                        const detailData = r.redirectChain.map((hop, j) => ({
                            'Hop': j + 1, 'URL': hop.url, 'Status': hop.status,
                            'Server': hop.server, 'Timestamp (s)': hop.timestamp.toFixed(2)
                        }));
                        let sheetName = r.originalURL.replace(/https?:\\/\\//, '').substring(0, 25);
                        sheetName = \`Detail \${i+1} - \${sheetName}\`;
                        const detailSheet = XLSX.utils.json_to_sheet(detailData);
                        XLSX.utils.book_append_sheet(wb, detailSheet, sheetName);
                    }
                });
                XLSX.writeFile(wb, 'URL_Journey_Analysis_Report.xlsx');
            });

            feather.replace();
        });
    </script>
</body>
</html>`;
}

// --- Main Execution Logic (No changes) ---
async function main() {
    console.log("Starting URL analysis...");
    const allArgs = process.argv.slice(2);
    const urls = allArgs.join(' ').split(/\s+/).map(url => url.trim()).filter(url => url && validator.isURL(url));
    if (urls.length === 0) {
        console.error("Error: No valid URLs provided. Please paste a list of URLs (one per line).");
        process.exit(1);
    }
    console.log(`Found ${urls.length} valid URLs to analyze.`);
    const browser = await chromium.launch({ headless: true });
    const analysisPromises = urls.map(url => fetchUrlWithPlaywright(browser, url));
    const results = await Promise.all(analysisPromises);
    console.log("Analysis complete. Generating enhanced HTML report...");
    const htmlContent = generateHtmlReport(results);
    await writeFile('report.html', htmlContent);
    console.log("✅ Report successfully generated as report.html");
    await browser.close();
}

main().catch(err => {
    console.error("A critical error occurred:", err);
    process.exit(1);
});
