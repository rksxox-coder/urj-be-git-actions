// @ts-ignore
import ipRangeCheck from 'ip-range-check';
import { chromium, Browser, errors } from 'playwright-chromium';
import validator from 'validator';
import { URL } from 'url';
import dns from 'dns/promises';
import { writeFile, readFile, mkdir } from 'fs/promises';
import * as path from 'path';

// --- CONFIGURATION ---
const BATCH_SIZE = 5;
const DELAY_MS = 2000;
const HISTORY_FILE = 'history.json';

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

interface HistoryEntry {
    id: string;
    date: string;
    timestamp: number;
    path: string;
    urlCount: number;
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

// --- ENHANCED AKAMAI DETECTION LOGIC ---ed it from origin
    if (xCache.includes("TCP_HIT") || xCache.includes("TCP_MEM_HIT") || xCache.includes("TCP_REFRESH_HIT")) {
        return ServerType.AKAMAI;
    }

    // B. Check Akamai-Specific Debug Headers
    // If these exist, Akamai processed the request, even if it passed it to Origin.
    if (lowerHeaders["x-akamai-request-id"] || lowerHeaders["x-akamai-staging"] || lowerHeaders["akamai-mon-ibit"]) {
        // If status is a redirect (3xx), and Akamai touched it, we usually credit Akamai
        // UNLESS X-Cache explicitly says MISS, which means Akamai fetched the redirect from Origin.
        if (!xCache.includes("TCP_MISS")) {
            return ServerType.AKAMAI;
        }
    }

    // C. Check Server Header (Standard)
    const serverValue = lowerHeaders["server"]?.toLowerCase() || "";
    if (serverValue.includes("akamai") || serverValue.includes("ghost")) return ServerType.AKAMAI;
    
    // --- 2. ORIGIN (AEM) DETECTION ---
    
    const hostname = new URL(url).hostname;
    if (hostname && (hostname.toLowerCase().includes("bmw") || hostname.toLowerCase().includes("mini"))) {
        if ("x-dispatcher" in lowerHeaders || "x-aem-instance" in lowerHeaders) return ServerType.AEM;
        // Fallback: If it's BMW/Mini and NO Akamai cache hit, assume AEM
        if ("cache-control" in lowerHeaders && !xCache) return ServerType.AEM;
    }

    if (serverValue.includes("apache")) return ServerType.AEM;

    // --- 3. FALLBACKS ---
    
    const serverTiming = lowerHeaders["server-timing"] || "";
    if (serverTiming.includes("cdn-cache; desc=HIT")) return ServerType.AKAMAI;

    const ip = await resolveIp(url);
    if (isAkamaiIp(ip) && !xCache.includes("TCP_MISS")) return ServerType.AKAMAI;

    return ServerType.UNKNOWN;
}
async function getServerName(headers: Record<string, string>, url: string, statusCode: number): Promise<string> {
    const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    
    // --- 1. AGGRESSIVE AKAMAI DETECTION ---
    
    // A. Check X-Cache Headers (The most reliable method)
    const xCache = lowerHeaders["x-cache"] || "";
    // TCP_HIT: Content was in Akamai cache
    // TCP_MEM_HIT: Content was in Akamai memory
    

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
function generateHtmlReport(results: AnalysisResult[], timestampStr: string): string {
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
                <td><button class="details-btn" data-index="${index}"><i data-feather="eye" style="width:14px; height:14px;"></i></button></td>
            </tr>`;
    });

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Report ${timestampStr}</title>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.sheetjs.com/xlsx-0.20.0/package/dist/xlsx.full.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <link rel="stylesheet" href="https://cdn.datatables.net/2.0.8/css/dataTables.dataTables.css" />
    <script src="https://cdn.datatables.net/2.0.8/js/dataTables.js"></script>
    <style>
        :root { --bg-color: #f4f6f9; --card-bg: #fff; --text-color: #333; --border-color: #dee2e6; --header-bg: #f8f9fa; --shadow-color: rgba(0,0,0,0.1); --link-color: #007bff; }
        
        body.dark-mode { 
            --bg-color: #1a202c; --card-bg: #2d3748; --text-color: #e2e8f0; 
            --border-color: #4a5568; --header-bg: #2d3748; --shadow-color: rgba(0,0,0,0.5); --link-color: #63b3ed; 
        }
        
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 10px; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.3s; font-size: 14px; }
        /* Added margin-top to container to prevent overlap with parent button */
        .container { max-width: 100%; margin: auto; background: var(--card-bg); padding: 15px; border-radius: 8px; box-shadow: 0 2px 8px var(--shadow-color); margin-top: 50px; }
        
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border-color); }
        h1 { font-size: 1.2rem; margin: 0; font-weight: 600; } 
        .header-controls { display: flex; align-items: center; gap: 10px; }
        
        #export-btn { 
            background-color: #28a745; color: white; padding: 5px 10px; 
            border: none; border-radius: 4px; cursor: pointer; font-size: 12px; 
            display: flex; align-items: center; gap: 5px; 
        }
        button#theme-toggle { 
            background: none; border: none; cursor: pointer; color: var(--text-color); 
            padding: 2px; display: flex; align-items: center; 
        }
        
        table { width: 100% !important; border-collapse: collapse; }
        th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
        .url-cell { display: flex; align-items: center; }
        .url-cell i.feather { margin-right: 8px; flex-shrink: 0; width: 14px; height: 14px; }
        td a { color: var(--link-color); text-decoration: none; font-size: 0.9em; word-break: break-all; }
        
        .status-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; color: white; font-weight: bold; font-size: 11px; }
        .status-badge.success { background-color: #28a745; }
        .status-badge.redirect { background-color: #ffc107; color: #333; }
        .status-badge.error { background-color: #dc3545; }
        .status-badge.small { padding: 1px 5px; font-size: 10px; margin-right: 3px; }
        
        .dataTables_wrapper .dataTables_length select, .dataTables_wrapper .dataTables_filter input { 
            background-color: var(--card-bg); color: var(--text-color); border: 1px solid var(--border-color); padding: 2px; font-size: 12px;
        }
        .details-btn { background: none; border: none; cursor: pointer; color: var(--text-color); padding: 2px; }
        
        body.dark-mode .swal2-popup { background-color: #2d3748; color: #e2e8f0; }
        body.dark-mode .swal2-title, body.dark-mode .swal2-content { color: #e2e8f0; }
        
        .modal-table { width: 100%; margin-top: 5px; border-collapse: collapse; font-size: 12px; color: inherit; }
        .modal-table th { background: var(--header-bg); border-bottom: 1px solid var(--border-color); text-align: left; padding: 6px; }
        .modal-table td { border-bottom: 1px solid var(--border-color); padding: 6px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Analysis Report</h1>
            <div class="header-controls">
                <button id="export-btn"><i data-feather="file-text" style="width:12px; height:12px;"></i> Export</button>
                <button id="theme-toggle" title="Toggle dark mode"><i data-feather="moon" style="width:14px; height:14px;"></i></button>
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
            const body = document.body;
            const toggleBtn = document.getElementById('theme-toggle');
            
            // --- THEME INHERITANCE ON LOAD ---
            let parentIsDark = false;
            try {
                if (window.self !== window.top) {
                    parentIsDark = window.parent.document.documentElement.classList.contains('dark');
                }
            } catch(e) { }

            const storedTheme = localStorage.getItem('theme');
            if (storedTheme === 'dark' || (!storedTheme && parentIsDark)) {
                body.classList.add('dark-mode');
                toggleBtn.innerHTML = '<i data-feather="sun" style="width:14px; height:14px;"></i>';
            }

            // Listen for theme changes from parent
            window.addEventListener('message', (event) => {
                if (event.data && event.data.type === 'theme-change') {
                    const isDark = event.data.theme === 'dark';
                    if (isDark) {
                        body.classList.add('dark-mode');
                        toggleBtn.innerHTML = '<i data-feather="sun" style="width:14px; height:14px;"></i>';
                    } else {
                        body.classList.remove('dark-mode');
                        toggleBtn.innerHTML = '<i data-feather="moon" style="width:14px; height:14px;"></i>';
                    }
                    localStorage.setItem('theme', event.data.theme);
                    feather.replace();
                }
            });

            toggleBtn.addEventListener('click', () => {
                body.classList.toggle('dark-mode');
                const isDark = body.classList.contains('dark-mode');
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
                toggleBtn.innerHTML = isDark ? '<i data-feather="sun" style="width:14px; height:14px;"></i>' : '<i data-feather="moon" style="width:14px; height:14px;"></i>';
                feather.replace();
            });

            new DataTable('#analysisTable', { layout: { topStart: 'pageLength', topEnd: 'search', bottomStart: 'info', bottomEnd: 'paging' }, "drawCallback": () => feather.replace() });

            // --- UPDATED EXPORT LOGIC (SINGLE SHEET FLATTENED) ---
            document.getElementById('export-btn').addEventListener('click', () => {
                try {
                    const flatData = resultsData.map(r => {
                        const row = {
                            'Original URL': r.originalURL,
                            'Final URL': r.finalURL,
                            'Hop Count': r.redirectChain.length,
                            'Final Target Status': r.finalStatus,
                            'Total Time (s)': r.totalTime.toFixed(2),
                            'Error': r.error || ''
                        };

                        r.redirectChain.forEach((hop, i) => {
                            const prefix = \`Hop \${i + 1}\`;
                            row[\`\${prefix} URL\`] = hop.url;
                            row[\`\${prefix} Status\`] = hop.status;
                            row[\`\${prefix} Server\`] = hop.server;
                        });

                        return row;
                    });

                    const wb = XLSX.utils.book_new();
                    const ws = XLSX.utils.json_to_sheet(flatData);
                    XLSX.utils.book_append_sheet(wb, ws, 'Redirect Report');
                    XLSX.writeFile(wb, 'Redirect_Analysis.xlsx');
                } catch (err) {
                    console.error(err);
                    Swal.fire('Export Error', 'Failed to generate Excel file.', 'error');
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
                    title: 'Redirect Chain', width: '600px',
                    html: \`<p style="word-break:break-all;font-size:12px"><strong>Start:</strong> \${data.originalURL}</p><table class="modal-table"><thead><tr><th>#</th><th>URL</th><th>St</th><th>Srv</th></tr></thead><tbody>\${chainHtml}</tbody></table>\`
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
    
    try {
        const fileContent = await readFile('urls.txt', 'utf-8');
        urls = fileContent.split('\n').map(u => u.trim()).filter(u => u && validator.isURL(u));
    } catch (e) {
        console.log("urls.txt not found, checking CLI args...");
        const allArgs = process.argv.slice(2);
        urls = allArgs.join(' ').split(/\s+/).map(u => u.trim()).filter(u => u && validator.isURL(u));
    }

    if (urls.length === 0) {
        console.error("No valid URLs found.");
        process.exit(1);
    }

    const browser = await chromium.launch({ headless: true });
    const allResults: AnalysisResult[] = [];

    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
        const batch = urls.slice(i, i + BATCH_SIZE);
        const batchPromises = batch.map(url => fetchUrlWithPlaywright(browser, url));
        const batchResults = await Promise.all(batchPromises);
        allResults.push(...batchResults);

        if (i + BATCH_SIZE < urls.length) {
            await new Promise(resolve => setTimeout(resolve, DELAY_MS));
        }
    }
    await browser.close();

    // 3. Generate Dynamic Path
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const timestamp = now.getTime(); 

    const folderPath = `reports/${year}/${month}/${day}`;
    const fileName = `report-${timestamp}.html`;
    const fullPath = path.join(folderPath, fileName);

    await mkdir(folderPath, { recursive: true });

    const htmlContent = generateHtmlReport(allResults, new Date().toLocaleString());
    await writeFile(fullPath, htmlContent);
    console.log(`✅ Report generated: ${fullPath}`);

    // 4. Update History
    const historyEntry: HistoryEntry = {
        id: timestamp.toString(),
        date: new Date().toLocaleString(),
        timestamp: timestamp,
        path: fullPath, 
        urlCount: urls.length
    };

    let history: HistoryEntry[] = [];
    try {
        const historyData = await readFile(HISTORY_FILE, 'utf-8');
        history = JSON.parse(historyData);
    } catch (e) {
        console.log("No existing history.json, creating new one.");
    }

    history.unshift(historyEntry);
    if (history.length > 50) history = history.slice(0, 50);

    await writeFile(HISTORY_FILE, JSON.stringify(history, null, 2));
    console.log("✅ History Updated");
}

main().catch(err => {
    console.error("Critical Error:", err);
    process.exit(1);
});
