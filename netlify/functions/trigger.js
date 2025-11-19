// netlify/functions/trigger.js

exports.handler = async (event) => {
    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    try {
        // 1. Get the environment variables (We will set these in Netlify later)
        const { GITHUB_TOKEN, GITHUB_USER, GITHUB_REPO, WORKFLOW_ID } = process.env;
        
        // 2. Parse the incoming data from the frontend
        const { urls } = JSON.parse(event.body);

        if (!urls) {
            return { statusCode: 400, body: JSON.stringify({ error: 'No URLs provided' }) };
        }

        // 3. Prepare the call to GitHub API
        const endpoint = `https://api.github.com/repos/${GITHUB_USER}/${GITHUB_REPO}/actions/workflows/${WORKFLOW_ID}/dispatches`;
        
        // 4. Send the request to GitHub
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': `token ${GITHUB_TOKEN}`, // Using the hidden secret!
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ref: 'main', // The branch to run on
                inputs: { urls: urls } // Passing the URLs to the workflow
            }),
        });

        if (!response.ok) {
            return { statusCode: response.status, body: `GitHub Error: ${response.statusText}` };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({ message: 'Workflow triggered successfully!' }),
        };

    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
    }
};
