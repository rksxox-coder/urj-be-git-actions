const fetch = require('node-fetch');

// --- SECURE CONFIGURATION ---
const GH_TOKEN = process.env.GH_TOKEN;
const OWNER = process.env.GH_USER;
const REPO = process.env.GH_REPO;

let USERS = {};
try {
    USERS = JSON.parse(process.env.APP_USERS || '{}');
} catch (e) {
    console.error("Critical Error: APP_USERS environment variable is missing or invalid JSON.");
}

exports.handler = async (event, context) => {
    const { action, username, password, payload } = JSON.parse(event.body || '{}');

    // 1. AUTHENTICATION
    const user = USERS[username];
    if (!user || user.pass !== password) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid Credentials" }) };
    }

    // 2. ROUTING
    try {
        if (action === 'upload') {
            // Enforce Limits
            const urls = payload.split('\n').filter(u => u.trim());
            if (urls.length > user.limit) {
                return { 
                    statusCode: 403, 
                    body: JSON.stringify({ error: `Limit Exceeded. Your plan allows ${user.limit} links, but you sent ${urls.length}.` }) 
                };
            }
            return await uploadToGitHub(payload);
        } 
        else if (action === 'check_run') {
            return await checkRunStatus(payload.runId);
        }
        else if (action === 'get_history') {
            return await getFileContent('history.json', true);
        }
        else if (action === 'get_report') {
            return await getFileContent(payload.path, false);
        }
        
        return { statusCode: 400, body: "Invalid Action" };

    } catch (e) {
        console.error("API Error:", e); // Log error to Netlify console
        return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
    }
};

// --- HELPER FUNCTIONS ---

async function uploadToGitHub(content) {
    const path = "urls.txt";
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`;
    
    // 1. Get SHA (Existing file check)
    let sha = null;
    try {
        const getResp = await fetch(url, { headers: { 'Authorization': `token ${GH_TOKEN}` } });
        if (getResp.ok) {
            const data = await getResp.json();
            sha = data.sha;
        }
    } catch (e) {}

    // 2. Upload File
    const body = {
        message: "Trigger Scan via Netlify",
        content: Buffer.from(content).toString('base64'),
        branch: "main"
    };
    if (sha) body.sha = sha;

    const putResp = await fetch(url, {
        method: 'PUT',
        headers: { 
            'Authorization': `token ${GH_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    });

    if (!putResp.ok) throw new Error("GitHub Upload Failed. Check Token Permissions.");

    // 3. ROBUST RETRY LOOP (The Fix)
    // We try to find the run 5 times, waiting 3 seconds between tries.
    let latestRun = null;
    
    for (let i = 0; i < 5; i++) {
        console.log(`Attempt ${i+1}: Looking for active workflow run...`);
        
        // Wait 3 seconds
        await new Promise(r => setTimeout(r, 3000));

        // Fetch runs triggered by 'push' event
        const runsResp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/actions/runs?event=push&per_page=1`, { 
            headers: { 'Authorization': `token ${GH_TOKEN}` } 
        });
        
        if (runsResp.ok) {
            const runsData = await runsResp.json();
            
            // Check if a run exists
            if (runsData.workflow_runs && runsData.workflow_runs.length > 0) {
                const run = runsData.workflow_runs[0];
                const runTime = new Date(run.created_at).getTime();
                const now = Date.now();
                
                // Verify this is a NEW run (created in the last 60 seconds), not an old one
                if ((now - runTime) < 60000) { 
                    latestRun = run;
                    break; // Found it! Exit loop.
                }
            }
        }
    }

    if (!latestRun) {
        throw new Error("Upload succeeded, but the Workflow failed to start within 15 seconds. Please refresh history manually.");
    }

    return { statusCode: 200, body: JSON.stringify({ runId: latestRun.id }) };
}

async function checkRunStatus(runId) {
    const resp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/actions/runs/${runId}`, { 
        headers: { 'Authorization': `token ${GH_TOKEN}` } 
    });
    
    if (!resp.ok) return { statusCode: 404, body: JSON.stringify({ status: 'unknown' }) };
    
    const data = await resp.json();
    return { statusCode: 200, body: JSON.stringify(data) };
}

async function getFileContent(path, isJson) {
    // Add timestamp to bypass cache
    const resp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?t=${Date.now()}`, { 
        headers: { 'Authorization': `token ${GH_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } 
    });
    
    if (!resp.ok) return { statusCode: 404, body: JSON.stringify({ error: "Not found" }) };
    
    const data = await resp.json();
    const content = Buffer.from(data.content, 'base64').toString('utf-8');
    
    return { statusCode: 200, body: isJson ? content : JSON.stringify({ content: content }) };
}
