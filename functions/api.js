const fetch = require('node-fetch');

// --- SECURE CONFIGURATION ---
const GH_TOKEN = process.env.GH_TOKEN;
const OWNER = process.env.GH_USER;
const REPO = process.env.GH_REPO;

let USERS = {};
try {
    USERS = JSON.parse(process.env.APP_USERS || '{}');
} catch (e) {
    console.error("Critical Error: APP_USERS missing.");
}

exports.handler = async (event, context) => {
    const { action, username, password, payload } = JSON.parse(event.body || '{}');

    const user = USERS[username];
    if (!user || user.pass !== password) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid Credentials" }) };
    }

    try {
        if (action === 'upload') {
            const urls = payload.split('\n').filter(u => u.trim());
            if (urls.length > user.limit) {
                return { statusCode: 403, body: JSON.stringify({ error: `Limit Exceeded: ${urls.length}/${user.limit}` }) };
            }
            return await uploadToGitHub(payload);
        } 
        else if (action === 'get_latest_run') {
            return await getLatestRun();
        }
        else if (action === 'check_run') {
            return await checkRunStatus(payload.runId);
        }
        else if (action === 'get_history') {
            return await getFileContent('history.json');
        }
        else if (action === 'get_report') {
            return await getFileContent(payload.path);
        }
        return { statusCode: 400, body: "Invalid Action" };
    } catch (e) {
        return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
    }
};

// --- HELPER FUNCTIONS ---

async function uploadToGitHub(content) {
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/contents/urls.txt`;
    
    // 1. Get SHA
    let sha = null;
    try {
        const getResp = await fetch(url, { headers: { 'Authorization': `token ${GH_TOKEN}` } });
        if (getResp.ok) {
            const data = await getResp.json();
            sha = data.sha;
        }
    } catch (e) {}

    // 2. FORCE UNIQUE CONTENT (The Fix)
    // We append a timestamp comment so GitHub ALWAYS sees a change and triggers the workflow.
    const uniqueContent = content + `\n# Trigger ID: ${Date.now()}`;

    const body = {
        message: "Trigger Scan via Netlify",
        content: Buffer.from(uniqueContent).toString('base64'),
        branch: "master", // <--- UPDATED TO MASTER
        sha: sha 
    };

    const putResp = await fetch(url, {
        method: 'PUT',
        headers: { 'Authorization': `token ${GH_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    if (!putResp.ok) throw new Error("GitHub Upload Failed");

    return { statusCode: 200, body: JSON.stringify({ status: "uploaded", timestamp: Date.now() }) };
}

async function getLatestRun() {
    // Look for runs created in the last 2 minutes
    const runsResp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/actions/runs?event=push&per_page=1`, { 
        headers: { 'Authorization': `token ${GH_TOKEN}` } 
    });
    
    if (!runsResp.ok) return { statusCode: 200, body: JSON.stringify({ runId: null }) };
    
    const runsData = await runsResp.json();
    if (runsData.workflow_runs && runsData.workflow_runs.length > 0) {
        const run = runsData.workflow_runs[0];
        const runTime = new Date(run.created_at).getTime();
        
        // Only return if it's fresh (created in last 90 seconds)
        if ((Date.now() - runTime) < 90000) {
            return { statusCode: 200, body: JSON.stringify({ runId: run.id }) };
        }
    }
    return { statusCode: 200, body: JSON.stringify({ runId: null }) };
}

async function checkRunStatus(runId) {
    const resp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/actions/runs/${runId}`, { 
        headers: { 'Authorization': `token ${GH_TOKEN}` } 
    });
    const data = await resp.json();
    return { statusCode: 200, body: JSON.stringify(data) };
}

async function getFileContent(path) {
    const resp = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?t=${Date.now()}`, { 
        headers: { 'Authorization': `token ${GH_TOKEN}`, 'Accept': 'application/vnd.github.v3+json' } 
    });
    
    if (!resp.ok) return { statusCode: 404, body: JSON.stringify({ error: "File not found" }) };
    
    const data = await resp.json();
    const content = Buffer.from(data.content, 'base64').toString('utf-8');
    
    return { statusCode: 200, body: JSON.stringify({ content: content }) };
}
