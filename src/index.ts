import { chromium, Browser, errors } from 'playwright-chromium';
import validator from 'validator';
import { URL } from 'url';
import dns from 'dns/promises';
import ipRangeCheck from 'ip-range-check';
import { writeFile } from 'fs/promises';

// --- Type Definitions (No changes needed here) ---
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

// --- Server Identification & Icon Mapping (No changes needed here) ---
const AKAMAI_IP_RANGES = ["23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"];
const ipCache = new Map<string, string>();

const ServerType = {
    AKAMAI: 'Akamai',
    APACHE_AEM: 'Apache (AEM)',
    UNKNOWN: 'Unknown'
};

const serverIconMap: Record<string, string> = {
    [ServerType.AKAMAI]: '<i class="fa-solid fa-cloud" style="color: #007BFF;" title="Akamai"></i>',
    [ServerType.APACHE_AEM]: '<i class="fa-solid fa-feather-pointed" style="color: #DC3545;" title="Apache (AEM)"></i>',
    [ServerType.UNKNOWN]: '<i class="fa-solid fa-server" style="color: #6c757d;" title="Unknown Server"></i>'
};


// --- Helper Functions (No changes needed here) ---
async function resolveIp(url: string): Promise<string | null> {
    try {
        const hostname = new URL(url).hostname;
        if (!hostname) return null;
        if (ipCache.has(hostname)) return ipCache.get(hostname)!;
        const { address } = await dns.lookup(hostname);
        ipCache.set(hostname, address);
        return address;
    } catch {
        return null;
    }
}

function isAkamaiIp(ip: string | null): boolean {
    if (!ip) return false;
    return AKAMAI_IP_RANGES.some(cidr => ipRangeCheck(ip, cidr));
}

async function getServerName(headers: Record<string, string>, url: string): Promise<string> {
    const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    const serverValue = lowerHeaders["server"]?.toLowerCase() || "";
    if (serverValue.includes("akamai") || serverValue.includes("ghost")) return ServerType.AKAMAI;
    if (serverValue.includes("apache")) return ServerType.APACHE_AEM;
    const ip = await resolveIp(url);
    if (isAkamaiIp(ip)) return ServerType.AKAMAI;
    if ("x-dispatcher" in lowerHeaders || "x-aem-instance" in lowerHeaders) return ServerType.APACHE_AEM;
    return ServerType.UNKNOWN;
}


// --- Core Analysis Logic (No changes needed here) ---
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
                    url: response.url(),
                    status: response.status(),
                    server: await getServerName(headers, response.url()),
                    timestamp: (Date.now() - startTime) / 1000
                });
            }
        });
        await page.goto(url, { timeout: 30000, waitUntil: "domcontentloaded" });
        const finalHop = redirectChain[redirectChain.length - 1];
        return {
            originalURL: url,
            finalURL: page.url(),
            sourceServer: redirectChain[0]?.server || null,
            targetServer: finalHop?.server || null,
            finalStatus: finalHop?.status || null,
            redirectChain: redirectChain,
            totalTime: (Date.now() - startTime) / 1000,
        };
    } catch (e) {
        let errorMessage = "A critical server error occurred.";
        if (e instanceof errors.TimeoutError) errorMessage = "Navigation timed out after 30s.";
        else if (e instanceof Error && e.message.includes("net::ERR_TOO_MANY_REDIRECTS")) errorMessage = "Too many redirects.";
        else if (e instanceof Error) errorMessage = e.message;
        const finalHop = redirectChain.length > 0 ? redirectChain[redirectChain.length - 1] : null;
        return {
            originalURL: url,
            finalURL: finalHop?.url || "N/A",
            sourceServer: redirectChain[0]?.server || null,
            targetServer: finalHop?.server || null,
            finalStatus: finalHop?.status || null,
            redirectChain: redirectChain,
            totalTime: (Date.now() - startTime) / 1000,
            error: errorMessage,
        };
    } finally {
        if (context) await context.close();
    }
}


// --- HTML Report Generation (COMPLETE OVERHAUL) ---
function generateHtmlReport(results: AnalysisResult[]): string {
    let tableRows = '';
    results.forEach((result, index) => {
        const sourceIcon = serverIconMap[result.sourceServer || ServerType.UNKNOWN];
        const targetIcon = result.error ? '<i class="fa-solid fa-triangle-exclamation" style="color: #dc3545;" title="Error"></i>' : serverIconMap[result.targetServer || ServerType.UNKNOWN];
        
        const finalStatusBadge = result.error 
            ? `<span class="status-badge error">${result.finalStatus || 'ERR'}</span>`
            : `<span class="status-badge success">${result.finalStatus || 'OK'}</span>`;
        
        // UPDATED: Create styled labels for the redirect chain
        const chainTooltip = result.redirectChain.map((h, i) => `Hop ${i + 1} (${h.server}): ${h.status}`).join('\n');
        const chainBadges = result.redirectChain.map(h => {
            const statusClass = h.status >= 400 ? 'error' : (h.status >= 300 ? 'redirect' : 'success');
            return `<span class="status-badge small ${statusClass}">${h.status}</span>`;
        }).join('');

        tableRows += `
            <tr>
                <td>${sourceIcon} <a href="${result.originalURL}" target="_blank">${result.originalURL}</a></td>
                <td>${targetIcon} <a href="${result.finalURL}" target="_blank">${result.finalURL}</a></td>
                <td>${finalStatusBadge}</td>
                <td class="chain-cell" title="${chainTooltip}">${chainBadges || 'N/A'}</td>
                <td><button class="details-btn" data-index="${index}">Details</button></td>
            </tr>
        `;
    });

    // UPDATED: This entire HTML block is revised for better styling and reliable JS loading.
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>URL Journey Analysis Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
        <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>

        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f4f6f9; color: #333; }
            .container { max-width: 1400px; margin: auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 4px_8px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            #export-btn { background-color: #28a745; color: white; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; transition: background-color 0.2s; }
            #export-btn:hover { background-color: #218838; }
            
            /* FIX: Improved table layout */
            table { width: 100%; border-collapse: collapse; table-layout: fixed; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; vertical-align: middle; }
            th { background-color: #f8f9fa; font-weight: 600; }
            tr:hover { background-color: #f1f1f1; }
            td:first-child, td:nth-child(2) { word-break: break-all; } /* Allow long URLs to wrap */
            
            /* FIX: Column width control */
            th:nth-child(1), th:nth-child(2) { width: 35%; }
            th:nth-child(3) { width: 10%; }
            th:nth-child(4) { width: 15%; }
            th:nth-child(5) { width: 5%; text-align: center; }
            td:nth-child(5) { text-align: center; }

            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }

            /* FIX: Updated status badge styling */
            .status-badge { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; font-size: 13px; }
            .status-badge.success { background-color: #28a745; }
            .status-badge.redirect { background-color: #ffc107; color: #333; }
            .status-badge.error { background-color: #dc3545; }
            .status-badge.small { padding: 3px 8px; font-size: 11px; margin-right: 4px; }
            
            .chain-cell { cursor: help; }
            .details-btn { background-color: #007bff; color: white; padding: 5px 10px; border: none; border-radius: 5px; cursor: pointer; }
            .details-btn:hover { background-color: #0056b3; }
            .modal-table { width: 100%; text-align: left; margin-top: 15px; } 
            .modal-table th, .modal-table td { padding: 8px; border-bottom: 1px solid #eee; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>URL Journey Analysis Report</h1>
                <button id="export-btn"><i class="fa-solid fa-file-excel"></i> Export to Excel</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Source URL</th>
                        <th>Target URL</th>
                        <th>Final Status</th>
                        <th>Redirect Chain</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRows}
                </tbody>
            </table>
        </div>

        <script>
            // FIX: Robust event handling for modal and export buttons
            document.addEventListener('DOMContentLoaded', () => {
                const resultsData = ${JSON.stringify(results)};

                // Details Modal Event Listener
                document.querySelectorAll('.details-btn').forEach(button => {
                    button.addEventListener('click', (event) => {
                        const index = event.currentTarget.getAttribute('data-index');
                        const result = resultsData[index];
                        if (!result) return;

                        let modalContent = \`
                            <p style="text-align:left;">
                                <strong>Original URL:</strong> \${result.originalURL}<br>
                                <strong>Final URL:</strong> \${result.finalURL}<br>
                                <strong>Total Time:</strong> \${result.totalTime.toFixed(2)}s<br>
                                \${result.error ? \`<strong>Error:</strong> <span style="color:red;">\${result.error}</span><br>\` : ''}
                            </p>
                            <table class="modal-table">
                                <thead><tr><th>#</th><th>URL</th><th>Status</th><th>Server</th><th>Time (s)</th></tr></thead>
                                <tbody>\${result.redirectChain.map((hop, i) => \`
                                    <tr>
                                        <td>\${i+1}</td>
                                        <td>\${hop.url}</td>
                                        <td>\${hop.status}</td>
                                        <td>\${hop.server}</td>
                                        <td>\${hop.timestamp.toFixed(2)}</td>
                                    </tr>\`).join('')}
                                </tbody>
                            </table>
                        \`;

                        Swal.fire({
                            title: 'Redirect Details',
                            html: modalContent,
                            width: '800px',
                            confirmButtonText: 'Close'
                        });
                    });
                });

                // Excel Export Event Listener
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
            });
        </script>
    </body>
    </html>
    `;
}

// --- Main Execution Logic (No changes needed here) ---
async function main() {
    console.log("Starting URL analysis...");
    const allArgs = process.argv.slice(2);

    // FIX: Correctly split by any whitespace (spaces, newlines, etc.)
    const urls = allArgs
        .join(' ')
        .split(/\s+/) // This was the line with the typo
        .map(url => url.trim())
        .filter(url => url && validator.isURL(url));

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
