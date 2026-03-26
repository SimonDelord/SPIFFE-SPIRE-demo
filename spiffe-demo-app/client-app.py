#!/usr/bin/env python3
"""
Client application that uses SPIFFE identity to authenticate to the API server.
Gets JWT-SVID from SPIRE and uses it to call protected endpoints.
"""
import os
import json
import time
from flask import Flask, render_template_string, jsonify, request
import requests

# SPIFFE Workload API
try:
    from spiffe import JwtSource, X509Source
    SPIFFE_AVAILABLE = True
except ImportError:
    SPIFFE_AVAILABLE = False

app = Flask(__name__)

# Configuration
API_SERVER_URL = os.environ.get('API_SERVER_URL', 'http://unified-api.spiffe-demo.svc:8080')
SPIFFE_ENDPOINT_SOCKET = os.environ.get('SPIFFE_ENDPOINT_SOCKET', 'unix:///run/spire/sockets/spire-agent.sock')

def get_jwt_svid(audience):
    """Fetch a JWT-SVID from the SPIRE agent."""
    if not SPIFFE_AVAILABLE:
        return None, "SPIFFE library not available"
    
    try:
        with JwtSource() as source:
            jwt_svid = source.fetch_svid(audience={audience})
            return jwt_svid.token, None
    except Exception as e:
        return None, str(e)

def get_x509_svid():
    """Fetch X.509 SVID information from the SPIRE agent."""
    if not SPIFFE_AVAILABLE:
        return None, "SPIFFE library not available"
    
    try:
        with X509Source() as source:
            svid = source.svid
            return {
                'spiffe_id': str(svid.spiffe_id),
                'cert_chain_length': len(svid.cert_chain),
            }, None
    except Exception as e:
        return None, str(e)

def call_api(endpoint, jwt_token=None):
    """Call the API server with optional JWT authentication."""
    url = f"{API_SERVER_URL}{endpoint}"
    headers = {}
    
    if jwt_token:
        headers['Authorization'] = f'Bearer {jwt_token}'
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return {
            'status_code': response.status_code,
            'response': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
        }, None
    except requests.exceptions.RequestException as e:
        return None, str(e)

# HTML template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPIFFE Client App</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #2d1b4e 0%, #1a0a2e 100%);
            min-height: 100vh;
            color: #e4e4e4;
            padding: 40px 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            color: #a855f7;
        }
        h2 { color: #a855f7; margin-bottom: 15px; font-size: 1.3rem; }
        h3 { color: #c084fc; margin-bottom: 10px; font-size: 1.1rem; }
        p { line-height: 1.6; margin-bottom: 10px; color: #b4b4b4; }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            margin: 5px;
            cursor: pointer;
            border: none;
            font-size: 1rem;
        }
        .btn-primary {
            background: linear-gradient(90deg, #a855f7, #6366f1);
            color: white;
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .result-box {
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            font-family: monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 400px;
            overflow-y: auto;
        }
        .success { border-left: 4px solid #22c55e; }
        .error { border-left: 4px solid #ef4444; }
        .info { border-left: 4px solid #3b82f6; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            margin: 2px;
        }
        .badge-purple { background: rgba(168, 85, 247, 0.2); color: #a855f7; }
        .badge-green { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .badge-red { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .status { font-size: 0.9rem; }
        .flow-diagram {
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 20px;
            font-family: monospace;
            font-size: 12px;
            color: #c084fc;
            overflow-x: auto;
        }
        .loading { color: #f59e0b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🔑 SPIFFE Client App</h1>
            <p>This application uses SPIFFE identity (JWT-SVID) to authenticate to the API server</p>
            <span class="badge badge-purple">Workload Identity</span>
            <span class="badge badge-{{ 'green' if spiffe_available else 'red' }}">
                SPIFFE: {{ 'Connected' if spiffe_available else 'Not Available' }}
            </span>
        </div>

        <div class="card">
            <h2>Authentication Flow</h2>
            <div class="flow-diagram">
┌─────────────────┐     1. Get JWT-SVID      ┌─────────────────┐
│  This Client    │ ◄────────────────────────│   SPIRE Agent   │
│                 │                          └─────────────────┘
└────────┬────────┘
         │ 2. Call API with JWT-SVID
         ▼
┌─────────────────┐     3. Validate JWT      ┌─────────────────────────┐
│  API Server     │ ────────────────────────►│ SPIRE OIDC Discovery    │
│                 │                          │ {{ oidc_issuer }}
└─────────────────┘                          └─────────────────────────┘
            </div>
        </div>

        <div class="card">
            <h2>My SPIFFE Identity</h2>
            <div id="identity-result">
                <a href="/api/identity" class="btn btn-secondary" onclick="fetchAndDisplay('/api/identity', 'identity-result'); return false;">
                    Fetch My Identity
                </a>
            </div>
        </div>

        <div class="card">
            <h2>Get JWT-SVID</h2>
            <p>Fetch a JWT token from SPIRE that proves this workload's identity</p>
            <div id="jwt-result">
                <a href="/api/get-jwt" class="btn btn-primary" onclick="fetchAndDisplay('/api/get-jwt', 'jwt-result'); return false;">
                    Get JWT-SVID
                </a>
            </div>
        </div>

        <div class="card">
            <h2>Call Protected API</h2>
            <p>Use the JWT-SVID to authenticate to the API server's protected endpoint</p>
            <div id="protected-result">
                <a href="/api/call-protected" class="btn btn-primary" onclick="fetchAndDisplay('/api/call-protected', 'protected-result'); return false;">
                    Call Protected Endpoint
                </a>
            </div>
        </div>

        <div class="card">
            <h2>Call Public API (No Auth)</h2>
            <p>Call the API server without authentication for comparison</p>
            <div id="public-result">
                <a href="/api/call-public" class="btn btn-secondary" onclick="fetchAndDisplay('/api/call-public', 'public-result'); return false;">
                    Call Public Endpoint
                </a>
            </div>
        </div>

        <div class="card">
            <h2>Configuration</h2>
            <p><strong>API Server:</strong> <code>{{ api_server_url }}</code></p>
            <p><strong>SPIFFE Socket:</strong> <code>{{ spiffe_socket }}</code></p>
            <p><strong>OIDC Issuer:</strong> <code>{{ oidc_issuer }}</code></p>
        </div>
    </div>

    <script>
        async function fetchAndDisplay(url, elementId) {
            const container = document.getElementById(elementId);
            container.innerHTML = '<div class="result-box info loading">Loading...</div>';
            
            try {
                const response = await fetch(url);
                const data = await response.json();
                const isSuccess = response.ok && !data.error;
                
                container.innerHTML = `
                    <div class="result-box ${isSuccess ? 'success' : 'error'}">
${JSON.stringify(data, null, 2)}
                    </div>
                `;
            } catch (e) {
                container.innerHTML = `
                    <div class="result-box error">Error: ${e.message}</div>
                `;
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    """Home page with interactive UI."""
    return render_template_string(
        HTML_TEMPLATE,
        spiffe_available=SPIFFE_AVAILABLE,
        api_server_url=API_SERVER_URL,
        spiffe_socket=SPIFFE_ENDPOINT_SOCKET,
        oidc_issuer=os.environ.get('OIDC_ISSUER', 'https://oidc-discovery.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com')
    )

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'spiffe-client-app'})

@app.route('/api/identity')
def get_identity():
    """Get this workload's SPIFFE identity (X.509 SVID)."""
    svid_info, error = get_x509_svid()
    
    if error:
        return jsonify({
            'error': 'Failed to get SPIFFE identity',
            'message': error,
            'spiffe_available': SPIFFE_AVAILABLE
        }), 500
    
    return jsonify({
        'identity': svid_info,
        'message': 'Successfully retrieved SPIFFE identity'
    })

@app.route('/api/get-jwt')
def get_jwt():
    """Get a JWT-SVID for this workload."""
    audience = request.args.get('audience', 'spiffe-api-server')
    jwt_token, error = get_jwt_svid(audience)
    
    if error:
        return jsonify({
            'error': 'Failed to get JWT-SVID',
            'message': error,
            'spiffe_available': SPIFFE_AVAILABLE
        }), 500
    
    # Decode the JWT to show its contents (without verification)
    import base64
    parts = jwt_token.split('.')
    if len(parts) >= 2:
        # Decode payload
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        try:
            decoded_payload = json.loads(base64.urlsafe_b64decode(payload))
        except:
            decoded_payload = "Could not decode"
    else:
        decoded_payload = "Invalid JWT format"
    
    return jsonify({
        'jwt_svid': jwt_token,
        'decoded_payload': decoded_payload,
        'audience': audience,
        'message': 'Successfully retrieved JWT-SVID from SPIRE'
    })

@app.route('/api/call-protected')
def call_protected():
    """Call the protected API endpoint using JWT-SVID authentication."""
    # Get JWT-SVID
    jwt_token, error = get_jwt_svid('spiffe-api-server')
    
    if error:
        return jsonify({
            'error': 'Failed to get JWT-SVID',
            'message': error,
            'step': 'Getting JWT-SVID from SPIRE'
        }), 500
    
    # Call the protected endpoint
    result, error = call_api('/api/protected', jwt_token)
    
    if error:
        return jsonify({
            'error': 'Failed to call API',
            'message': error,
            'step': 'Calling protected endpoint',
            'api_server': API_SERVER_URL
        }), 500
    
    return jsonify({
        'step1': 'Got JWT-SVID from SPIRE',
        'step2': 'Called API with JWT-SVID in Authorization header',
        'step3': 'API validated JWT against OIDC Discovery Provider',
        'api_response': result,
        'jwt_svid_used': jwt_token[:50] + '...' if jwt_token else None
    })

@app.route('/api/call-public')
def call_public():
    """Call the public API endpoint without authentication."""
    result, error = call_api('/api/public')
    
    if error:
        return jsonify({
            'error': 'Failed to call API',
            'message': error,
            'api_server': API_SERVER_URL
        }), 500
    
    return jsonify({
        'message': 'Called public endpoint (no auth required)',
        'api_response': result
    })

@app.route('/api/call-whoami')
def call_whoami():
    """Call the whoami endpoint to see full identity details."""
    jwt_token, error = get_jwt_svid('spiffe-api-server')
    
    if error:
        return jsonify({
            'error': 'Failed to get JWT-SVID',
            'message': error
        }), 500
    
    result, error = call_api('/api/whoami', jwt_token)
    
    if error:
        return jsonify({
            'error': 'Failed to call API',
            'message': error
        }), 500
    
    return jsonify({
        'message': 'Identity verified by API server',
        'api_response': result
    })

if __name__ == '__main__':
    print(f"Starting SPIFFE Client App")
    print(f"API Server URL: {API_SERVER_URL}")
    print(f"SPIFFE Available: {SPIFFE_AVAILABLE}")
    app.run(host='0.0.0.0', port=8080, debug=False)
