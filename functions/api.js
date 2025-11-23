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
            // Enforce Limits
            const urls = payload.split('\n').filter(u => u.trim());
            if (urls.length > user.limit) {
                return { statusCode: 403, body: JSON.stringify({ error: `Limit Exceeded: ${urls.length}/${user.limit}` }) };
            }
            return await uploadToGitHub(payload);
        } 
        // NEW: Endpoint to check for the latest run without uploading
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
    const path = "urls.txt";
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`;
    
    // 1. Get SHA
    let sha = null;
    try {
        const getResp = await fetch(url, { headers: { 'Authorization': `token ${GH_TOKEN}` } });
        if (getResp.ok) {
            const data = await getResp.json();
            sha = data.sha;
        }
    } catch (e) {}

    // 2. Force Uniqueness (THE FIX)
    // We add a comment at the bottom so Git ALWAYS sees a change
    const uniqueContent = content + `\n# Run ID: ${Date.now()}`;

    const body = {
        message: "Trigger Scan via Netlify",
        content: Buffer.from(uniqueContent).toString('base64'),
        branch: "main",
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
    
    // Send back as a JSON object wrapper so frontend always parses the same way
    return { statusCode: 200, body: JSON.stringify({ content: content }) };
}
```

---

### Step 2: Update `index.html` (Frontend Polling)
This update moves the "Wait Logic" to the browser and fixes the History parser.

```html
<!-- ... (Header/Styles remain the same) ... -->

    <script>
        // ... (Auth Logic remains the same) ...

        // --- API WRAPPER ---
        async function callApi(action, payload = {}, user = CREDENTIALS?.username, pass = CREDENTIALS?.password) {
            const res = await fetch('/api', {
                method: 'POST',
                body: JSON.stringify({ action, username: user, password: pass, payload })
            });
            return await res.json();
        }

        // --- HISTORY FIX ---
        async function fetchHistory() {
            try {
                const data = await callApi('get_history');
                if(data.error) throw new Error("No history found");
                
                // FIX: Parse the inner content string
                const historyArray = JSON.parse(data.content); 
                
                historySelect.innerHTML = '<option value="">-- Select Past Report --</option>';
                historyArray.forEach(h => {
                    const opt = document.createElement('option');
                    opt.value = h.path;
                    opt.innerText = `${h.date} (${h.urlCount} URLs)`;
                    historySelect.appendChild(opt);
                });
            } catch(e) { 
                console.log(e);
                historySelect.innerHTML = '<option value="">No history available</option>'; 
            }
        }

        // --- START BUTTON LOGIC (UPDATED) ---
        runBtn.addEventListener('click', async () => {
            const urls = document.getElementById('urlInput').value;
            if(!urls.trim()) return log("No URLs", 'error');
            
            runBtn.disabled = true;
            btnLoader.classList.remove('hidden');
            log("Authenticating & Uploading...");
            
            // 1. Upload File
            const resp = await callApi('upload', urls);
            
            if(resp.error) {
                log(resp.error, 'error');
                alert(resp.error); 
                runBtn.disabled = false;
                btnLoader.classList.add('hidden');
                return;
            }

            log("Upload Success. Waiting for GitHub to start...");
            badge.innerText = "QUEUED";
            badge.classList.remove('hidden');
            
            // 2. Poll for the NEW Run ID (Frontend Wait Loop)
            waitForRunId();
        });

        function waitForRunId() {
            let attempts = 0;
            const maxAttempts = 20; // Wait up to 60 seconds (20 * 3s)

            const interval = setInterval(async () => {
                attempts++;
                const resp = await callApi('get_latest_run');
                
                if (resp.runId) {
                    clearInterval(interval);
                    log(`Run ID Found: ${resp.runId}`);
                    trackProgress(resp.runId);
                } else {
                    if (attempts >= maxAttempts) {
                        clearInterval(interval);
                        log("Timeout: GitHub didn't start the workflow in time.", 'error');
                        runBtn.disabled = false;
                        btnLoader.classList.add('hidden');
                    } else {
                        // Still waiting...
                        console.log("Waiting for run...");
                    }
                }
            }, 3000); // Check every 3 seconds
        }

        function trackProgress(runId) {
            badge.innerText = "RUNNING";
            
            const interval = setInterval(async () => {
                const status = await callApi('check_run', { runId });
                
                if(status.status === 'completed') {
                    clearInterval(interval);
                    runBtn.disabled = false;
                    btnLoader.classList.add('hidden');
                    
                    if(status.conclusion === 'success') {
                        log("Success! Loading report...", 'success');
                        badge.innerText = "SUCCESS";
                        // Wait a moment for the file commit to be readable
                        setTimeout(() => {
                            fetchHistory();
                            // Auto-load logic could go here
                        }, 4000);
                    } else {
                        log("Workflow Failed.", 'error');
                        badge.innerText = "FAILED";
                    }
                } else {
                    log(`Status: ${status.status}`);
                }
            }, 4000);
        }
        
        // ... (Rest of the display/render logic remains the same) ...
    </script>
