#!/usr/bin/env python3
"""
Unified API Server that accepts tokens from MULTIPLE OIDC issuers:
1. Keycloak - for human users and M2M (client credentials)
2. SPIRE OIDC Discovery Provider - for SPIFFE workload identities

This demonstrates federation between traditional OIDC and SPIFFE/SPIRE.
"""
import os
import json
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
import jwt
from jwt import PyJWKClient
import requests

app = Flask(__name__)

# Configuration for multiple OIDC issuers
ISSUERS = {
    "keycloak": {
        "issuer": os.environ.get('KEYCLOAK_ISSUER', 'https://keycloak-keycloak.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com/realms/demo'),
        "jwks_uri": os.environ.get('KEYCLOAK_JWKS_URI', 'https://keycloak-keycloak.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com/realms/demo/protocol/openid-connect/certs'),
        "type": "oidc",
        "description": "Keycloak OIDC (Human users + M2M)"
    },
    "spire": {
        "issuer": os.environ.get('SPIRE_ISSUER', 'https://oidc-discovery.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com'),
        "jwks_uri": os.environ.get('SPIRE_JWKS_URI', 'https://oidc-discovery.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com/keys'),
        "type": "spiffe",
        "description": "SPIRE OIDC Discovery (Workload Identity)"
    }
}

# Cache JWKS clients
jwks_clients = {}

def get_jwks_client(issuer_key):
    """Get or create JWKS client for an issuer."""
    if issuer_key not in jwks_clients:
        jwks_uri = ISSUERS[issuer_key]["jwks_uri"]
        jwks_clients[issuer_key] = PyJWKClient(jwks_uri)
    return jwks_clients[issuer_key]

def identify_issuer(token):
    """Identify which issuer a token came from."""
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_issuer = unverified.get("iss", "")
        
        for key, config in ISSUERS.items():
            if token_issuer == config["issuer"]:
                return key, config
        
        return None, None
    except Exception:
        return None, None

def validate_token(token):
    """Validate a token against its issuer's JWKS."""
    issuer_key, issuer_config = identify_issuer(token)
    
    if not issuer_key:
        return None, None, "Unknown or untrusted issuer"
    
    try:
        client = get_jwks_client(issuer_key)
        signing_key = client.get_signing_key_from_jwt(token)
        
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256", "ES384"],
            options={"verify_aud": False},
            issuer=issuer_config["issuer"]
        )
        return decoded, issuer_key, None
    except jwt.ExpiredSignatureError:
        return None, issuer_key, "Token has expired"
    except jwt.InvalidIssuerError:
        return None, issuer_key, f"Invalid issuer"
    except jwt.InvalidTokenError as e:
        return None, issuer_key, f"Invalid token: {str(e)}"
    except Exception as e:
        return None, issuer_key, f"Validation error: {str(e)}"

def require_auth(f):
    """Decorator to require valid authentication from any trusted issuer."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Missing or invalid Authorization header',
                'message': 'Provide a Bearer token from any trusted issuer',
                'trusted_issuers': {k: v['description'] for k, v in ISSUERS.items()}
            }), 401
        
        token = auth_header.split(' ', 1)[1]
        claims, issuer_key, error = validate_token(token)
        
        if error:
            return jsonify({
                'error': 'Authentication failed',
                'message': error,
                'issuer_identified': issuer_key,
                'trusted_issuers': {k: v['description'] for k, v in ISSUERS.items()}
            }), 401
        
        request.auth_claims = claims
        request.auth_issuer = issuer_key
        request.auth_type = ISSUERS[issuer_key]["type"]
        return f(*args, **kwargs)
    
    return decorated_function

# HTML template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified API Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
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
        h1 { font-size: 2rem; margin-bottom: 10px; color: #00d9ff; }
        h2 { color: #00d9ff; margin-bottom: 15px; font-size: 1.3rem; }
        p { line-height: 1.6; margin-bottom: 10px; color: #b4b4b4; }
        .issuer-card {
            background: rgba(0, 217, 255, 0.1);
            border: 1px solid rgba(0, 217, 255, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin: 10px 0;
        }
        .issuer-card.keycloak { border-color: rgba(255, 165, 0, 0.5); background: rgba(255, 165, 0, 0.1); }
        .issuer-card.spire { border-color: rgba(138, 43, 226, 0.5); background: rgba(138, 43, 226, 0.1); }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            margin: 2px;
        }
        .badge-orange { background: rgba(255, 165, 0, 0.2); color: #ffa500; }
        .badge-purple { background: rgba(138, 43, 226, 0.2); color: #9370db; }
        .badge-cyan { background: rgba(0, 217, 255, 0.2); color: #00d9ff; }
        .endpoint {
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
        }
        .method { color: #7ee787; font-weight: bold; }
        .path { color: #79c0ff; }
        code {
            background: #0d1117;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .flow-diagram {
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 20px;
            font-family: monospace;
            font-size: 11px;
            color: #00d9ff;
            overflow-x: auto;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🔐 Unified API Server</h1>
            <p>This API accepts tokens from <strong>multiple OIDC issuers</strong>, demonstrating federation between traditional OIDC and SPIFFE/SPIRE.</p>
            <span class="badge badge-cyan">Multi-Issuer OIDC</span>
            <span class="badge badge-orange">Keycloak</span>
            <span class="badge badge-purple">SPIFFE/SPIRE</span>
        </div>

        <div class="card">
            <h2>Trusted Identity Providers</h2>
            
            <div class="issuer-card keycloak">
                <h3 style="color: #ffa500;">🔑 Keycloak (OIDC)</h3>
                <p><strong>Issuer:</strong> <code>{{ issuers.keycloak.issuer }}</code></p>
                <p><strong>Accepts:</strong> Human users (browser login) + M2M (client credentials)</p>
                <span class="badge badge-orange">Human Identity</span>
                <span class="badge badge-orange">Machine Identity (secrets)</span>
            </div>
            
            <div class="issuer-card spire">
                <h3 style="color: #9370db;">🛡️ SPIRE OIDC Discovery</h3>
                <p><strong>Issuer:</strong> <code>{{ issuers.spire.issuer }}</code></p>
                <p><strong>Accepts:</strong> Workload identities (JWT-SVIDs from SPIRE)</p>
                <span class="badge badge-purple">Workload Identity</span>
                <span class="badge badge-purple">No Secrets Needed</span>
            </div>
        </div>

        <div class="card">
            <h2>Authentication Flows</h2>
            <div class="flow-diagram">
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│  FLOW 1: Human User (Keycloak)          FLOW 2: M2M Client (Keycloak)          │
│  ──────────────────────────────          ─────────────────────────────          │
│  User ──► Browser ──► Keycloak           Service ──► client_id/secret           │
│                  │                                        │                     │
│                  ▼                                        ▼                     │
│           ID Token (JWT)                           Access Token (JWT)           │
│                  │                                        │                     │
│                  └──────────────┬─────────────────────────┘                     │
│                                 │                                               │
│                                 ▼                                               │
│                        ┌────────────────┐                                       │
│                        │  Unified API   │                                       │
│                        │  (this server) │                                       │
│                        └───────▲────────┘                                       │
│                                │                                               │
│                  ┌─────────────┴─────────────┐                                  │
│                  │                           │                                  │
│           JWT-SVID (JWT)              validates via JWKS                        │
│                  │                           │                                  │
│                  │                           ▼                                  │
│  FLOW 3: SPIFFE Workload            ┌──────────────────┐                       │
│  ────────────────────────           │ Keycloak JWKS    │                       │
│  Pod ──► SPIRE Agent                │ SPIRE OIDC JWKS  │                       │
│                                     └──────────────────┘                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
            </div>
        </div>

        <div class="card">
            <h2>API Endpoints</h2>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/health</span>
                <p style="margin-top: 10px; color: #8b949e;">Health check (no auth)</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/public</span>
                <p style="margin-top: 10px; color: #8b949e;">Public endpoint (no auth)</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/protected</span>
                <p style="margin-top: 10px; color: #8b949e;">Protected - requires token from ANY trusted issuer</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/whoami</span>
                <p style="margin-top: 10px; color: #8b949e;">Returns identity info and which issuer authenticated you</p>
            </div>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, issuers=ISSUERS)

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'unified-api-server'})

@app.route('/api/public')
def public_endpoint():
    return jsonify({
        'message': 'This is a public endpoint - no authentication required',
        'trusted_issuers': {k: v['description'] for k, v in ISSUERS.items()},
        'note': 'Try /api/protected with a token from any trusted issuer'
    })

@app.route('/api/protected')
@require_auth
def protected_endpoint():
    issuer_key = request.auth_issuer
    auth_type = request.auth_type
    claims = request.auth_claims
    
    # Determine identity based on issuer type
    if auth_type == "spiffe":
        identity = claims.get('sub', 'Unknown SPIFFE ID')
        identity_type = "SPIFFE Workload"
    else:
        # Keycloak - could be human or M2M
        if 'preferred_username' in claims:
            if claims.get('preferred_username', '').startswith('service-account-'):
                identity = claims.get('client_id', claims.get('azp', 'Unknown M2M Client'))
                identity_type = "Keycloak M2M Client"
            else:
                identity = claims.get('preferred_username', 'Unknown User')
                identity_type = "Keycloak Human User"
        else:
            identity = claims.get('sub', 'Unknown')
            identity_type = "Keycloak"
    
    return jsonify({
        'message': 'Access granted!',
        'authenticated_via': ISSUERS[issuer_key]['description'],
        'identity_type': identity_type,
        'identity': identity,
        'issuer': ISSUERS[issuer_key]['issuer'],
        'secret_data': {
            'api_key': 'sk-unified-api-secret-key',
            'database_url': 'postgresql://secret:password@db:5432/app',
            'encryption_key': 'aes-256-unified-demo-key'
        },
        'note': 'This endpoint accepts tokens from multiple identity providers!'
    })

@app.route('/api/whoami')
@require_auth
def whoami():
    issuer_key = request.auth_issuer
    claims = request.auth_claims
    
    return jsonify({
        'authenticated': True,
        'issuer_key': issuer_key,
        'issuer_type': ISSUERS[issuer_key]['type'],
        'issuer_description': ISSUERS[issuer_key]['description'],
        'issuer_url': ISSUERS[issuer_key]['issuer'],
        'subject': claims.get('sub'),
        'all_claims': claims
    })

@app.route('/api/validate', methods=['POST'])
def validate():
    """Validate a token and return info about it."""
    data = request.get_json() or {}
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'No token provided'}), 400
    
    claims, issuer_key, error = validate_token(token)
    
    if error:
        return jsonify({
            'valid': False,
            'error': error,
            'issuer_identified': issuer_key
        })
    
    return jsonify({
        'valid': True,
        'issuer_key': issuer_key,
        'issuer_description': ISSUERS[issuer_key]['description'],
        'subject': claims.get('sub'),
        'claims': claims
    })

if __name__ == '__main__':
    print("Starting Unified API Server")
    print("Trusted Issuers:")
    for key, config in ISSUERS.items():
        print(f"  - {key}: {config['issuer']}")
    app.run(host='0.0.0.0', port=8080, debug=False)
