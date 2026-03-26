#!/usr/bin/env python3
"""
API Server that validates JWT-SVIDs using SPIRE's OIDC Discovery Provider.
This server only accepts requests with valid JWT tokens issued by SPIRE.
"""
import os
import json
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
import jwt
from jwt import PyJWKClient
import requests

app = Flask(__name__)

# SPIRE OIDC Discovery Provider configuration
OIDC_ISSUER = os.environ.get('OIDC_ISSUER', 'https://oidc-discovery.apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com')
JWKS_URL = f"{OIDC_ISSUER}/keys"

# Cache the JWKS client
jwks_client = None

def get_jwks_client():
    """Get or create JWKS client for token validation."""
    global jwks_client
    if jwks_client is None:
        jwks_client = PyJWKClient(JWKS_URL)
    return jwks_client

def validate_jwt_svid(token):
    """Validate a JWT-SVID against SPIRE's OIDC Discovery Provider."""
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256", "ES384"],
            options={
                "verify_aud": False,  # SPIRE JWT-SVIDs may not have audience
                "verify_iss": True
            },
            issuer=OIDC_ISSUER
        )
        return decoded, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidIssuerError:
        return None, f"Invalid issuer. Expected: {OIDC_ISSUER}"
    except jwt.InvalidTokenError as e:
        return None, f"Invalid token: {str(e)}"
    except Exception as e:
        return None, f"Validation error: {str(e)}"

def require_spiffe_auth(f):
    """Decorator to require valid SPIFFE JWT-SVID authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'error': 'Missing or invalid Authorization header',
                'message': 'Provide a Bearer token in the Authorization header'
            }), 401
        
        token = auth_header.split(' ', 1)[1]
        claims, error = validate_jwt_svid(token)
        
        if error:
            return jsonify({
                'error': 'Authentication failed',
                'message': error,
                'oidc_issuer': OIDC_ISSUER
            }), 401
        
        # Add claims to request context
        request.spiffe_claims = claims
        return f(*args, **kwargs)
    
    return decorated_function

# HTML template for the UI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPIFFE API Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            min-height: 100vh;
            color: #e4e4e4;
            padding: 40px 20px;
        }
        .container { max-width: 900px; margin: 0 auto; }
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
            color: #4ecdc4;
        }
        h2 { color: #4ecdc4; margin-bottom: 15px; font-size: 1.3rem; }
        p { line-height: 1.6; margin-bottom: 10px; color: #b4b4b4; }
        .endpoint {
            background: #0d1117;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
        }
        .method { color: #7ee787; font-weight: bold; }
        .path { color: #79c0ff; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            background: rgba(78, 205, 196, 0.2);
            color: #4ecdc4;
        }
        code {
            background: #0d1117;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🔐 SPIFFE API Server</h1>
            <p>This API validates JWT-SVIDs using SPIRE's OIDC Discovery Provider</p>
            <span class="badge">OIDC Validation Enabled</span>
        </div>
        
        <div class="card">
            <h2>OIDC Configuration</h2>
            <p><strong>Issuer:</strong> <code>{{ issuer }}</code></p>
            <p><strong>JWKS URL:</strong> <code>{{ jwks_url }}</code></p>
        </div>
        
        <div class="card">
            <h2>API Endpoints</h2>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/health</span>
                <p style="margin-top: 10px; color: #8b949e;">Health check (no auth required)</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/public</span>
                <p style="margin-top: 10px; color: #8b949e;">Public endpoint (no auth required)</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/protected</span>
                <p style="margin-top: 10px; color: #8b949e;">Protected endpoint - requires valid JWT-SVID</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/api/whoami</span>
                <p style="margin-top: 10px; color: #8b949e;">Returns the SPIFFE identity from the JWT-SVID</p>
            </div>
        </div>
        
        <div class="card">
            <h2>How to Call Protected Endpoints</h2>
            <div class="endpoint">
                <p style="color: #8b949e;">Include the JWT-SVID in the Authorization header:</p>
                <p style="margin-top: 10px;">curl -H "Authorization: Bearer &lt;JWT-SVID&gt;" {{ request_url }}/api/protected</p>
            </div>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    """Home page with API documentation."""
    return render_template_string(
        HTML_TEMPLATE,
        issuer=OIDC_ISSUER,
        jwks_url=JWKS_URL,
        request_url=request.url_root.rstrip('/')
    )

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'spiffe-api-server'})

@app.route('/api/public')
def public_endpoint():
    """Public endpoint - no authentication required."""
    return jsonify({
        'message': 'This is a public endpoint - no authentication required',
        'oidc_issuer': OIDC_ISSUER,
        'note': 'Try /api/protected with a valid JWT-SVID'
    })

@app.route('/api/protected')
@require_spiffe_auth
def protected_endpoint():
    """Protected endpoint - requires valid JWT-SVID."""
    claims = request.spiffe_claims
    return jsonify({
        'message': 'Access granted! Your workload identity was validated.',
        'spiffe_id': claims.get('sub'),
        'validated_by': OIDC_ISSUER,
        'secret_data': {
            'database_password': 'super-secret-db-password-123',
            'api_key': 'sk-live-abc123xyz789',
            'encryption_key': 'aes-256-key-for-demo'
        },
        'note': 'In production, this would be real secrets or sensitive data'
    })

@app.route('/api/whoami')
@require_spiffe_auth
def whoami():
    """Returns detailed information about the authenticated workload."""
    claims = request.spiffe_claims
    return jsonify({
        'authenticated': True,
        'spiffe_id': claims.get('sub'),
        'issuer': claims.get('iss'),
        'issued_at': claims.get('iat'),
        'expires_at': claims.get('exp'),
        'audience': claims.get('aud'),
        'all_claims': claims
    })

@app.route('/api/validate', methods=['POST'])
def validate_token():
    """Endpoint to validate a JWT-SVID without requiring it in the header."""
    data = request.get_json() or {}
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'No token provided'}), 400
    
    claims, error = validate_jwt_svid(token)
    
    if error:
        return jsonify({
            'valid': False,
            'error': error,
            'oidc_issuer': OIDC_ISSUER
        })
    
    return jsonify({
        'valid': True,
        'spiffe_id': claims.get('sub'),
        'claims': claims
    })

if __name__ == '__main__':
    print(f"Starting SPIFFE API Server")
    print(f"OIDC Issuer: {OIDC_ISSUER}")
    print(f"JWKS URL: {JWKS_URL}")
    app.run(host='0.0.0.0', port=8080, debug=False)
