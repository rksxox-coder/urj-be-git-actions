// @ts-ignore
declare module 'ip-range-check';
import { chromium, Browser, errors } from 'playwright-chromium';
import validator from 'validator';
import { URL } from 'url';
import dns from 'dns/promises';
import ipRangeCheck from 'ip-range-check';
import { writeFile, readFile } from 'fs/promises';

// --- CONFIGURATION ---
const BATCH_SIZE = 5;       // Number of URLs to check simultaneously
const DELAY_MS = 2000;      // Wait time (ms) between batches to avoid rate limits
const REPORT_FILENAME = 'report.html';
const INPUT_FILENAME = 'urls.txt';

// --- TYPE DEFINITIONS ---
interface Hop {
    url: string;
    status: number;
    server: string;
    timestamp: number;
}

interface AnalysisResult {
    originalURL: string;
    finalURL: string | null;
    sourceServer: string | null;
    targetServer: string | null;
    finalStatus: number | null;
    redirectChain: Hop[];
    totalTime: number;
    error?: string;
}

// --- SERVER IDENTIFICATION ---
const AKAMAI_IP_RANGES = ["23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"];
const ipCache = new Map<string, string>();
const ServerType = { AKAMAI: 'Akamai', AEM: 'Apache (AEM)', UNKNOWN: 'Unknown' };
const serverIconMap: Record<string, string> = {
    [ServerType.AKAMAI]: '<i data-feather="cloud" style="color: #007BFF;" title="Akamai"></i>',
    [ServerType.AEM]: '<i data-feather="feather" style="color: #c22121;" title="Apache (AEM)"></i>',
    [ServerType.UNKNOWN]: '<i data-feather="server" style="color: #6c757d;" title="Unknown Server"></i>'
};

// --- HELPER FUNCTIONS ---
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

async function getServerName(headers: Record<string, string>, url: string, statusCode: number): Promise<string> {
    const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    const xCache = lowerHeaders["x-cache"] || "";
    
    // 1. Pro Check: X-Cache headers (Injected via Pragma)
    if (statusCode === 301 || statusCode === 302) {
        if (xCache.includes("TCP_HIT") || xCache.includes("TCP_MEM_HIT")) return ServerType.AKAMAI;
        if (xCache.includes("TCP_MISS")) return ServerType.AEM;
    }

    // 2. Standard Server Header
    const serverValue = lowerHeaders["server"]?.toLowerCase() || "";
    if (serverValue.includes("akamai") || serverValue.includes("ghost")) return ServerType.AKAMAI;
    
    // 3. AEM Specific Indicators
    const hostname = new URL(url).hostname;
    if (hostname && (hostname.toLowerCase().includes("bmw") || hostname.toLowerCase().includes("mini"))) {
        if ("x-dispatcher" in lowerHeaders || "x-aem-instance" in lowerHeaders) return ServerType.AEM;
        if ("cache-control" in lowerHeaders && !xCache) return ServerType.AEM;
    }

    if (serverValue.includes("apache")) return ServerType.AEM;

    // 4. Server Timing & IP Fallback
    const serverTiming = lowerHeaders["server-timing"] || "";
    if (serverTiming.includes("cdn-cache; desc=HIT") && (statusCode === 301 || statusCode === 302)) return ServerType.AKAMAI;

    const ip = await resolveIp(url);
    if (isAkamaiIp(ip) && !xCache.includes("TCP_MISS")) return ServerType.AKAMAI;

    return ServerType.UNKNOWN;
}

// --- CORE ANALYSIS LOGIC ---
async function fetchUrlWithPlaywright(browser: Browser, url: string): Promise<AnalysisResult> {
    let context;
    const startTime = Date.now();
    const redirectChain: Hop[] = [];
    try {
        context = await browser.newContext({ 
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            extraHTTPHeaders: {
                "Pragma": "akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-request-id, akamai-x-get-true-cache-key"
            }
        });
        
        const page = await context.newPage();
        page.on("response", async (response) => {
            if (response.request().isNavigationRequest()) {
                const headers = await response.allHeaders();
                const status = response.status();
                redirectChain.push({
                    url: response.url(), status: status,
                    server: await getServerName(headers, response.url(), status),
                    timestamp: (Date.now() - startTime) / 1000
                });
            }
        });

        await page.goto(url, { timeout: 45000, waitUntil: "domcontentloaded" });
        
        const finalHop = redirectChain[redirectChain.length - 1];
        return {
            originalURL: url, finalURL: page.url(), sourceServer: redirectChain[0]?.server || null,
            targetServer: finalHop?.server || null, finalStatus: finalHop?.status || null,
            redirectChain: redirectChain, totalTime: (Date.now() - startTime) / 1000,
        };
    } catch (e) {
        let errorMessage = "Error";
        if (e instanceof errors.TimeoutError) errorMessage = "Timeout";
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

// --- HTML REPORT GENERATION ---
function generateHtmlReport(results: AnalysisResult[]): string {
    let tableRows = '';
    results.forEach((result, index) => {
        const sourceIcon = serverIconMap[result.sourceServer || ServerType.UNKNOWN];
        const targetIcon = result.error ? '<i data-feather="alert-triangle" style="color: #dc3545;" title="Error"></i>' : serverIconMap[result.targetServer || ServerType.UNKNOWN];
        const finalStatusBadge = result.error ? `<span class="status-badge error">${result.finalStatus || 'ERR'}</span>` : `<span class="status-badge success">${result.finalStatus || 'OK'}</span>`;
        
        const chainBadges = result.redirectChain.map(h => {
            const statusClass = h.status >= 400 ? 'error' : (h.status >= 300 ? 'redirect' : 'success');
            return `<span class="status-badge small ${statusClass}">${h.status}</span>`;
        }).join('');
        
        const chainTooltip = result.redirectChain.map((h, i) => `Hop ${i + 1}: ${h.status} (${h.server})`).join(' &#013; ');

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
    <title>Redirect Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.sheetjs.com/xlsx-0.20.0/package/dist/xlsx.full.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <link rel="stylesheet" href="https://cdn.datatables.net/2.0.8/css/dataTables.dataTables.css" />
    <script src="https://cdn.datatables.net/2.0.8/js/dataTables.js"></script>
    <style>
        :root { --bg-color: #f4f6f9; --card-bg: #fff; --text-color: #333; --border-color: #dee2e6; --header-bg: #f8f9fa; --shadow-color: rgba(0,0,0,0.1); --link-color: #007bff; }
        body.dark-mode { --bg-color: #121212; --card-bg: #1e1e1e; --text-color: #e0e0e0; --border-color: #444; --header-bg: #333; --shadow-color: rgba(0,0,0,0.5); --link-color: #4dabf7; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.3s, color 0.3s; }
        .container { max-width: 1600px; margin: auto; background: var(--card-bg); padding: 25px; border-radius: 8px; box-shadow: 0 4px 12px var(--shadow-color); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header-controls { display: flex; align-items: center; gap: 20px; }
        #export-btn { background-color: #28a745; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; display: flex; align-items: center; gap: 8px; }
        table { width: 100% !important; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        .url-cell { display: flex; align-items: center; }
        .url-cell i.feather { margin-right: 10px; flex-shrink: 0; }
        td a { color: var(--link-color); text-decoration: none; font-size: 0.9em; word-break: break-all; }
        .status-badge { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; font-size: 13px; margin: 2px; }
        .status-badge.success { background-color: #28a745; }
        .status-badge.redirect { background-color: #ffc107; color: #333; }
        .status-badge.error { background-color: #dc3545; }
        .status-badge.small { padding: 3px 8px; font-size: 11px; margin-right: 4px; }
        .modal-table { width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 14px; color: #333; }
        .modal-table th { background: #f8f9fa; border-bottom: 2px solid #dee2e6; text-align: left; padding: 8px; }
        .modal-table td { border-bottom: 1px solid #eee; padding: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Redirect Analysis Report</h1>
            <div class="header-controls">
                <button id="export-btn"><i data-feather="file-text"></i> Export to Excel</button>
                <button onclick="document.body.classList.toggle('dark-mode')"><i data-feather="moon"></i></button>
            </div>
        </div>
        <table id="analysisTable">
            <thead><tr><th>Source URL</th><th>Target URL</th><th>Status</th><th>Chain</th><th>Details</th></tr></thead>
            <tbody>${tableRows}</tbody>
        </table>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const resultsData = ${JSON.stringify(results)};
            new DataTable('#analysisTable', { layout: { topStart: 'pageLength', topEnd: 'search', bottomStart: 'info', bottomEnd: 'paging' }, "drawCallback": () => feather.replace() });

            document.getElementById('export-btn').addEventListener('click', () => {
                try {
                    const wb = XLSX.utils.book_new();
                    const summaryData = resultsData.map(r => ({
                        'Source URL': r.originalURL,
                        'Source Server': r.sourceServer,
                        'Target URL': r.finalURL,
                        'Target Server': r.targetServer,
                        'Final Status': r.finalStatus,
                        'Hop Count': r.redirectChain.length - 1,
                        'Total Time (s)': r.totalTime,
                        'Error': r.error || ''
                    }));
                    const summarySheet = XLSX.utils.json_to_sheet(summaryData);
                    XLSX.utils.book_append_sheet(wb, summarySheet, 'Overview');

                    let sheetCounter = 1;
                    resultsData.forEach((r) => {
                        if (r.redirectChain.length > 0) {
                            const detailData = r.redirectChain.map((hop, i) => ({
                                'Step': i + 1, 'URL': hop.url, 'Status': hop.status, 'Server': hop.server, 'Time': hop.timestamp
                            }));
                            let safeName = "Row_" + sheetCounter;
                            sheetCounter++;
                            const detailSheet = XLSX.utils.json_to_sheet(detailData);
                            XLSX.utils.book_append_sheet(wb, detailSheet, safeName);
                        }
                    });
                    XLSX.writeFile(wb, 'Redirect_Analysis.xlsx');
                } catch (err) {
                    console.error(err);
                    Swal.fire('Export Error', 'Failed to generate Excel file. Check console.', 'error');
                }
            });

            document.querySelector('tbody').addEventListener('click', (e) => {
                const btn = e.target.closest('.details-btn');
                if (!btn) return;
                const idx = btn.dataset.index;
                const data = resultsData[idx];
                const chainHtml = data.redirectChain.map((h, i) => 
                    \`<tr><td>\${i+1}</td><td>\${h.url}</td><td>\${h.status}</td><td>\${h.server}</td></tr>\`
                ).join('');
                Swal.fire({
                    title: 'Redirect Chain', width: '800px',
                    html: \`<p><strong>Start:</strong> \${data.originalURL}</p><table class="modal-table"><thead><tr><th>#</th><th>URL</th><th>St</th><th>Srv</th></tr></thead><tbody>\${chainHtml}</tbody></table>\`
                });
            });
            feather.replace();
        });
    </script>
</body>
</html>`;
}

// --- MAIN EXECUTION ---
async function main() {
    console.log("Starting Analysis...");
    
    let urls: string[] = [];
    
    // 1. Try to read from urls.txt (GitHub Actions mode)
    try {
        const fileContent = await readFile(INPUT_FILENAME, 'utf-8');
        urls = fileContent.split('\n').map(u => u.trim()).filter(u => u && validator.isURL(u));
        console.log(`Loaded ${urls.length} URLs from ${INPUT_FILENAME}`);
    } catch (e) {
        // 2. Fallback to CLI args (Local testing mode)
        console.log(`${INPUT_FILENAME} not found, checking command line args...`);
        const allArgs = process.argv.slice(2);
        urls = allArgs.join(' ').split(/\s+/).map(u => u.trim()).filter(u => u && validator.isURL(u));
    }

    if (urls.length === 0) {
        console.error("Error: No valid URLs found. Please provide 'urls.txt' or CLI arguments.");
        process.exit(1);
    }

    console.log(`Total URLs to process: ${urls.length}`);
    console.log(`Configuration: Batch Size = ${BATCH_SIZE}, Delay = ${DELAY_MS}ms`);

    const browser = await chromium.launch({ headless: true });
    const allResults: AnalysisResult[] = [];

    // --- BATCH PROCESSING LOOP ---
    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
        const batch = urls.slice(i, i + BATCH_SIZE);
        const batchNumber = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(urls.length / BATCH_SIZE);

        console.log(`Processing Batch ${batchNumber}/${totalBatches} (${batch.length} URLs)...`);

        const batchPromises = batch.map(url => fetchUrlWithPlaywright(browser, url));
        const batchResults = await Promise.all(batchPromises);
        allResults.push(...batchResults);

        if (i + BATCH_SIZE < urls.length) {
            console.log(`Waiting ${DELAY_MS}ms...`);
            await new Promise(resolve => setTimeout(resolve, DELAY_MS));
        }
    }

    console.log("All batches complete. Generating report...");
    const htmlContent = generateHtmlReport(allResults);
    await writeFile(REPORT_FILENAME, htmlContent);
    console.log(`✅ Report generated successfully: ${REPORT_FILENAME}`);
    
    await browser.close();
}

main().catch(err => {
    console.error("Critical Error:", err);
    process.exit(1);
});
