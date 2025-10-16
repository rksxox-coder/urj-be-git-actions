import { chromium, Browser, errors } from 'playwright-chromium';
import validator from 'validator';
import { URL } from 'url';
import dns from 'dns/promises';
import ipRangeCheck from 'ip-range-check';
import { writeFile } from 'fs/promises';

// --- Type Definitions (Slightly modified for reporting) ---
interface Hop {
    url: string;
    status: number;
    server: string;
    timestamp: number;
}

interface AnalysisResult {
    originalURL: string;
    finalURL: string | null;
    redirectChain: Hop[];
    totalTime: number;
    error?: string;
}

// --- Configuration & Caches ---
const AKAMAI_IP_RANGES = ["23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"];
const ipCache = new Map<string, string>();

// --- Helper Functions (Unchanged Logic) ---
async function resolveIp(url: string): Promise<string | null> {
    try {
        const hostname = new URL(url).hostname;
        if (!hostname) return null;
        if (ipCache.has(hostname)) return ipCache.get(hostname)!;
        
        const { address } = await dns.lookup(hostname);
        ipCache.set(hostname, address);
        return address;
    } catch (error) {
        return null;
    }
}

function isAkamaiIp(ip: string | null): boolean {
    if (!ip) return false;
    return AKAMAI_IP_RANGES.some(cidr => ipRangeCheck(ip, cidr));
}

async function getServerName(headers: Record<string, string>, url: string): Promise<string> {
    const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    const hostname = new URL(url).hostname;

    if (hostname && (hostname.toLowerCase().includes("bmw") || hostname.toLowerCase().includes("mini"))) {
        if ("cache-control" in lowerHeaders) return "Apache (AEM)";
    }
    const serverValue = lowerHeaders["server"]?.toLowerCase() || "";
    if (serverValue) {
        if (serverValue.includes("akamai") || serverValue.includes("ghost")) return "Akamai";
        if (serverValue.includes("apache")) return "Apache (AEM)";
        return serverValue.charAt(0).toUpperCase() + serverValue.slice(1);
    }
    const serverTiming = lowerHeaders["server-timing"] || "";
    const hasAkamaiCache = serverTiming.includes("cdn-cache; desc=HIT") || serverTiming.includes("cdn-cache; desc=MISS");
    if (hasAkamaiCache) return "Akamai";
    const ip = await resolveIp(url);
    if (isAkamaiIp(ip)) return "Akamai";
    if ("x-dispatcher" in lowerHeaders || "x-aem-instance" in lowerHeaders) return "Apache (AEM)";

    return "Unknown";
}

// --- Core Analysis Logic (Refactored to return data) ---
async function fetchUrlWithPlaywright(browser: Browser, url: string): Promise<AnalysisResult> {
    let context;
    const startTime = Date.now();
    const redirectChain: Hop[] = [];

    try {
        context = await browser.newContext({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" });
        const page = await context.newPage();
        
        await page.route("**/*", (route) => {
            const resourceType = route.request().resourceType();
            if (["image", "stylesheet", "font", "media"].includes(resourceType)) route.abort();
            else route.continue();
        });

        page.on("response", async (response) => {
            if (response.request().isNavigationRequest()) {
                const headers = await response.allHeaders();
                const hop: Hop = {
                    url: response.url(),
                    status: response.status(),
                    server: await getServerName(headers, response.url()),
                    timestamp: (Date.now() - startTime) / 1000
                };
                if (!redirectChain.length || redirectChain[redirectChain.length - 1].url !== hop.url) {
                    redirectChain.push(hop);
                }
            }
        });

        await page.goto(url, { timeout: 60000, waitUntil: "domcontentloaded" });
        const finalUrl = page.url();
        
        return {
            originalURL: url,
            finalURL: finalUrl,
            redirectChain: redirectChain,
            totalTime: (Date.now() - startTime) / 1000,
        };
    } catch (e) {
        let errorMessage = "A critical server error occurred.";
        if (e instanceof errors.TimeoutError) {
            errorMessage = "Navigation timed out after 60s.";
        } else if (e instanceof Error && e.message.includes("net::ERR_TOO_MANY_REDIRECTS")) {
            errorMessage = "Browser detected too many redirects.";
        } else if (e instanceof Error) {
            errorMessage = e.message;
        }
        return {
            originalURL: url,
            finalURL: null,
            redirectChain: redirectChain,
            totalTime: (Date.now() - startTime) / 1000,
            error: errorMessage,
        };
    } finally {
        if (context) await context.close();
    }
}

// --- HTML Report Generation ---
function generateHtmlReport(results: AnalysisResult[]): string {
    let resultsHtml = '';
    for (const result of results) {
        const isError = !!result.error;
        const statusClass = isError ? 'error' : 'success';
        const statusIcon = isError ? '❌' : '✅';

        let chainHtml = '<table><tr><th>#</th><th>URL</th><th>Status</th><th>Server</th><th>Time (s)</th></tr>';
        if (result.redirectChain.length > 0) {
            result.redirectChain.forEach((hop, index) => {
                chainHtml += `<tr><td>${index + 1}</td><td>${hop.url}</td><td>${hop.status}</td><td>${hop.server}</td><td>${hop.timestamp.toFixed(2)}</td></tr>`;
            });
        } else {
            chainHtml += '<tr><td colspan="5">No redirect chain captured.</td></tr>';
        }
        chainHtml += '</table>';

        resultsHtml += `
            <div class="card ${statusClass}">
                <div class="card-header">
                    <h3>${statusIcon} ${result.originalURL}</h3>
                    <span class="total-time">${result.totalTime.toFixed(2)}s</span>
                </div>
                <div class="card-body">
                    <p><strong>Final URL:</strong> ${result.finalURL || 'N/A'}</p>
                    ${isError ? `<p class="error-message"><strong>Error:</strong> ${result.error}</p>` : ''}
                    <h4>Redirect Chain (${result.redirectChain.length} hops)</h4>
                    ${chainHtml}
                </div>
            </div>
        `;
    }

    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>URL Journey Analysis Report</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f0f2f5; }
                .container { max-width: 900px; margin: 20px auto; padding: 20px; }
                h1 { color: #1c1e21; }
                .card { background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .card-header { display: flex; justify-content: space-between; align-items: center; padding: 16px; border-bottom: 1px solid #dddfe2; }
                .card-header h3 { margin: 0; font-size: 1.1em; word-break: break-all; }
                .card-body { padding: 16px; }
                .total-time { font-weight: bold; color: #606770; font-size: 0.9em; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { text-align: left; padding: 8px; border-bottom: 1px solid #dddfe2; word-break: break-all; }
                th { background-color: #f5f6f7; }
                .card.error { border-left: 5px solid #e74c3c; }
                .card.success { border-left: 5px solid #2ecc71; }
                .error-message { color: #e74c3c; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>URL Journey Analysis Report</h1>
                <p>Generated on: ${new Date().toUTCString()}</p>
                ${resultsHtml}
            </div>
        </body>
        </html>
    `;
}

// --- Main Execution Logic ---
async function main() {
    console.log("Starting URL analysis...");
    const args = process.argv.slice(2);
    const urls: string[] = [];

    // Simple argument parsing for a list of URLs
    for (const arg of args) {
        if (validator.isURL(arg)) {
            urls.push(arg);
        }
    }

    if (urls.length === 0) {
        console.error("Error: No valid URLs provided. Please provide URLs as command-line arguments.");
        process.exit(1);
    }
    
    console.log(`Found ${urls.length} URLs to analyze.`);

    const browser = await chromium.launch({ headless: true });
    const results: AnalysisResult[] = [];
    
    // Process URLs in chunks for concurrency
    const concurrencyLimit = 5;
    for (let i = 0; i < urls.length; i += concurrencyLimit) {
        const chunk = urls.slice(i, i + concurrencyLimit);
        console.log(`Processing chunk ${i / concurrencyLimit + 1}...`);
        const promises = chunk.map(url => fetchUrlWithPlaywright(browser, url));
        results.push(...await Promise.all(promises));
    }
    
    console.log("Analysis complete. Generating HTML report...");
    const htmlContent = generateHtmlReport(results);
    await writeFile('report.html', htmlContent);
    console.log("✅ Report successfully generated as report.html");
    
    await browser.close();
}

main().catch(err => {
    console.error("A critical error occurred:", err);
    process.exit(1);
});
